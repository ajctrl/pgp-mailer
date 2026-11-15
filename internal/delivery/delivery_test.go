package delivery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/textproto"
	"testing"
	"time"

	"pgp-mailer/internal/metrics"
	"pgp-mailer/internal/store"
)

var t0 = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

type fakeTransport struct {
	openErr error
	onOpen  func()
	sendErr func(to string) error
	opens   int
	sent    []string
	resets  int
}

type fakeSession struct{ t *fakeTransport }

func (f *fakeTransport) Open(context.Context) (Session, error) {
	f.opens++
	if f.onOpen != nil {
		f.onOpen()
	}
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &fakeSession{f}, nil
}

func (s *fakeSession) Send(from, to string, msg []byte) error {
	if s.t.sendErr != nil {
		if err := s.t.sendErr(string(msg)); err != nil {
			return err
		}
	}
	s.t.sent = append(s.t.sent, string(msg))
	return nil
}
func (s *fakeSession) Reset() error { s.t.resets++; return nil }
func (s *fakeSession) Close()       {}
func (s *fakeSession) Abort()       {}

// flakyQueue is the real store with injectable failures.
type flakyQueue struct {
	*store.Store
	markErr error
	mailErr error
	marks   int
	mails   int
}

func (q *flakyQueue) MarkDelivered(id string, now time.Time) error {
	q.marks++
	if q.markErr != nil {
		return q.markErr
	}
	return q.Store.MarkDelivered(id, now)
}

func (q *flakyQueue) Mail(id string) ([]byte, error) {
	q.mails++
	if q.mailErr != nil {
		return nil, q.mailErr
	}
	return q.Store.Mail(id)
}

type env struct {
	q     *flakyQueue
	st    *store.Store
	tr    *fakeTransport
	w     *Worker
	clock time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(t.TempDir(), store.DefaultLimit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{q: &flakyQueue{Store: st}, st: st, tr: &fakeTransport{}, clock: t0}
	m := metrics.New(nil, []string{store.ReasonExpired, store.ReasonPermanent})
	e.w = New(e.q, e.tr, m, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return e.clock })
	return e
}

func (e *env) enqueue(t *testing.T, n int) string {
	t.Helper()
	id := fmt.Sprintf("%032x", n)
	it := &store.Item{
		ID: id, Source: "app", Receiver: "ops", Level: "info", AcceptedAt: e.clock,
		EnvelopeFrom: "a@example.com", EnvelopeTo: "b@example.com",
		Deadline: e.clock.Add(store.RetryWindow), NextAttempt: e.clock,
		DedupKind: store.DedupIdem, DedupKey: store.IdemKey("app", id),
	}
	if err := e.st.Enqueue(it, []byte("mail-"+id), [32]byte{}, e.clock); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) tick(t *testing.T) {
	t.Helper()
	if _, err := e.w.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func smtpErr(code int) error { return &textproto.Error{Code: code, Msg: "test"} }

func TestBackoffSchedule(t *testing.T) {
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, base := range want {
		lo, hi := Backoff(i+1, 0), Backoff(i+1, 0.999999)
		if lo != time.Duration(float64(base)*0.8) {
			t.Errorf("attempt %d: lower bound %v, want %v", i+1, lo, time.Duration(float64(base)*0.8))
		}
		if hi <= base || hi > time.Duration(float64(base)*1.2) {
			t.Errorf("attempt %d: upper bound %v not within +20%% of %v", i+1, hi, base)
		}
	}
}

func TestDeliversBatchOverOneSession(t *testing.T) {
	e := setup(t)
	for i := 1; i <= 3; i++ {
		e.enqueue(t, i)
	}
	e.tick(t)
	if len(e.tr.sent) != 3 || e.tr.opens != 1 {
		t.Fatalf("sent=%d opens=%d", len(e.tr.sent), e.tr.opens)
	}
	if st, _ := e.st.Stats(); st.Pending != 0 || st.Failed != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestTransientErrorIsRetriedUntilDeadline(t *testing.T) {
	e := setup(t)
	id := e.enqueue(t, 1)
	e.tr.sendErr = func(string) error { return smtpErr(451) }

	e.tick(t)
	due, _ := e.st.Due(t0.Add(time.Hour), 10)
	if len(due) != 1 || due[0].Attempts != 1 || due[0].LastSMTPCode != 451 {
		t.Fatalf("after first failure: %+v", due)
	}
	delay := due[0].NextAttempt.Sub(t0)
	if delay < 24*time.Second || delay > 36*time.Second {
		t.Fatalf("first retry delay = %v, want 30s ±20%%", delay)
	}
	if e.tr.resets != 1 {
		t.Fatalf("session not reset after an SMTP error reply")
	}

	// Keep failing; the item must never be scheduled past its deadline and
	// must end up in the failed queue once the hour is over.
	deadline := t0.Add(store.RetryWindow)
	for i := 0; i < 100; i++ {
		at, ok, _ := e.st.NextDue()
		if !ok {
			break
		}
		if at.After(deadline) {
			t.Fatalf("scheduled at %v, after the deadline %v", at, deadline)
		}
		e.clock = at
		e.tick(t)
	}
	failed, _ := e.st.ListFailed()
	if len(failed) != 1 || failed[0].ID != id || failed[0].FailReason != store.ReasonExpired {
		t.Fatalf("failed queue = %+v", failed)
	}
	if !failed[0].FailedAt.Equal(deadline) {
		t.Fatalf("expired at %v, want exactly the deadline %v", failed[0].FailedAt, deadline)
	}
	if len(e.tr.sent) != 0 {
		t.Fatal("message reported as sent")
	}
}

func TestPermanentErrorFailsImmediately(t *testing.T) {
	e := setup(t)
	bad := e.enqueue(t, 1)
	good := e.enqueue(t, 2)
	e.tr.sendErr = func(msg string) error {
		if msg == "mail-"+bad {
			return smtpErr(550)
		}
		return nil
	}
	e.tick(t)
	failed, _ := e.st.ListFailed()
	if len(failed) != 1 || failed[0].ID != bad || failed[0].FailReason != store.ReasonPermanent || failed[0].LastSMTPCode != 550 {
		t.Fatalf("failed queue = %+v", failed)
	}
	if len(e.tr.sent) != 1 || e.tr.sent[0] != "mail-"+good {
		t.Fatalf("the other message was not delivered: %v", e.tr.sent)
	}
}

func TestSessionFailureAppliesToWholeBatch(t *testing.T) {
	t.Run("connection failure is transient", func(t *testing.T) {
		e := setup(t)
		e.enqueue(t, 1)
		e.enqueue(t, 2)
		e.tr.openErr = errors.New("dial tcp: connection refused")
		e.tick(t)
		if e.tr.opens != 1 {
			t.Fatalf("opens = %d, want a single dial for the batch", e.tr.opens)
		}
		due, _ := e.st.Due(t0.Add(time.Hour), 10)
		if len(due) != 2 || due[0].Attempts != 1 || due[1].Attempts != 1 {
			t.Fatalf("pending = %+v", due)
		}
		if now, _ := e.st.Due(t0, 10); len(now) != 0 {
			t.Fatal("items still due immediately after a failed dial")
		}
	})
	t.Run("authentication failure 535 keeps the retry window", func(t *testing.T) {
		e := setup(t)
		e.enqueue(t, 1)
		e.enqueue(t, 2)
		e.tr.openErr = smtpErr(535)
		e.tick(t)
		if failed, _ := e.st.ListFailed(); len(failed) != 0 {
			t.Fatalf("failed queue = %+v, want nothing failed by a session error", failed)
		}
		due, _ := e.st.Due(t0.Add(time.Hour), 10)
		if len(due) != 2 || due[0].Attempts != 1 || due[0].LastSMTPCode != 535 {
			t.Fatalf("pending = %+v", due)
		}
		// Once the credentials are fixed the mails go out by themselves.
		e.tr.openErr = nil
		e.clock = t0.Add(time.Minute)
		e.tick(t)
		if len(e.tr.sent) != 2 {
			t.Fatalf("sent = %d after the session error was fixed", len(e.tr.sent))
		}
	})
	t.Run("no new session is opened during the pause", func(t *testing.T) {
		e := setup(t)
		e.enqueue(t, 1)
		e.tr.openErr = smtpErr(535)
		e.tick(t)
		// New mail arriving must not trigger another login attempt.
		e.enqueue(t, 2)
		for i := 0; i < 3; i++ {
			if n, err := e.w.Tick(context.Background()); err != nil || n != 0 {
				t.Fatalf("Tick during the pause = %d, %v; want nothing handled", n, err)
			}
		}
		if e.tr.opens != 1 {
			t.Fatalf("opens = %d during the pause, want 1", e.tr.opens)
		}
		if d := e.w.idleFor(); d < 24*time.Second-time.Millisecond || d > 36*time.Second {
			t.Fatalf("idle for %v, want the rest of the 30s ±20%% pause", d)
		}
		// The pause grows with consecutive failures: 30s, then 1m.
		e.clock = t0.Add(37 * time.Second)
		e.tick(t)
		if e.tr.opens != 2 {
			t.Fatalf("opens = %d after the first pause", e.tr.opens)
		}
		e.clock = e.clock.Add(37 * time.Second)
		e.enqueue(t, 3)
		e.tick(t)
		if e.tr.opens != 2 {
			t.Fatalf("opens = %d, want the second pause to last at least 48s", e.tr.opens)
		}
		// A successful session ends the pause and resets its length.
		e.tr.openErr = nil
		e.clock = e.clock.Add(time.Hour / 2)
		e.tick(t)
		if len(e.tr.sent) != 3 || !e.w.pauseUntil.IsZero() || e.w.sessionFailures != 0 {
			t.Fatalf("sent=%d pauseUntil=%v failures=%d", len(e.tr.sent), e.w.pauseUntil, e.w.sessionFailures)
		}
	})
	t.Run("pause and retry times count from the end of a slow failure", func(t *testing.T) {
		e := setup(t)
		e.enqueue(t, 1)
		e.tr.openErr = errors.New("i/o timeout")
		e.tr.onOpen = func() { e.clock = e.clock.Add(45 * time.Second) } // dial + greeting timeouts
		e.tick(t)
		gaveUp := t0.Add(45 * time.Second)
		if e.w.pauseUntil.Before(gaveUp.Add(24 * time.Second)) {
			t.Fatalf("pause ends %v after the failure, want at least 24s", e.w.pauseUntil.Sub(gaveUp))
		}
		due, _ := e.st.Due(t0.Add(time.Hour), 10)
		if len(due) != 1 || due[0].NextAttempt.Before(gaveUp.Add(24*time.Second)) {
			t.Fatalf("next attempt %v after the failure, want at least 24s", due[0].NextAttempt.Sub(gaveUp))
		}
		e.tick(t)
		if e.tr.opens != 1 {
			t.Fatal("reconnected immediately after a slow failure")
		}
	})
	t.Run("covers every due item, not only the batch", func(t *testing.T) {
		e := setup(t)
		const n = batchSize + 20
		for i := 1; i <= n; i++ {
			e.enqueue(t, i)
		}
		e.clock = t0.Add(time.Second)
		e.tr.openErr = errors.New("dial tcp: connection refused")
		if handled, err := e.w.Tick(context.Background()); err != nil || handled != n {
			t.Fatalf("Tick = %d, %v; want all %d items handled", handled, err, n)
		}
		if now, _ := e.st.Due(e.clock, 2*n); len(now) != 0 {
			t.Fatalf("%d items still due right after the failed dial", len(now))
		}
		due, _ := e.st.Due(t0.Add(time.Hour), 2*n)
		if len(due) != n {
			t.Fatalf("pending = %d", len(due))
		}
		for _, it := range due {
			if it.Attempts != 1 || it.LastErrorKind == "" {
				t.Fatalf("item beyond the batch not charged: %+v", it)
			}
		}
	})
	t.Run("stored mails are not read during the pause", func(t *testing.T) {
		e := setup(t)
		e.enqueue(t, 1)
		e.tr.openErr = smtpErr(535)
		e.tick(t)
		e.enqueue(t, 2)
		before := e.q.mails
		e.tick(t)
		if e.q.mails != before {
			t.Fatalf("%d mail(s) read while no session can be opened", e.q.mails-before)
		}
	})
	t.Run("items still expire during the pause", func(t *testing.T) {
		e := setup(t)
		e.enqueue(t, 1)
		e.tr.openErr = smtpErr(554)
		e.tick(t)
		e.w.pauseUntil = t0.Add(3 * time.Hour)
		e.clock = t0.Add(store.RetryWindow)
		e.tick(t)
		failed, _ := e.st.ListFailed()
		if len(failed) != 1 || failed[0].FailReason != store.ReasonExpired {
			t.Fatalf("failed queue = %+v", failed)
		}
	})
}

func TestItemsExpiredWhileStoppedGoToFailedQueue(t *testing.T) {
	e := setup(t)
	e.enqueue(t, 1)
	e.clock = t0.Add(2 * time.Hour) // service was down past the retry window
	e.tick(t)
	failed, _ := e.st.ListFailed()
	if len(failed) != 1 || failed[0].FailReason != store.ReasonExpired {
		t.Fatalf("failed queue = %+v", failed)
	}
	if e.tr.opens != 0 {
		t.Fatal("an expired item must not be attempted")
	}
	// Manual retry sends the very same mail.
	if err := e.st.RetryFailed(failed[0].ID, e.clock); err != nil {
		t.Fatal(err)
	}
	e.tick(t)
	if len(e.tr.sent) != 1 || e.tr.sent[0] != "mail-"+failed[0].ID {
		t.Fatalf("sent = %v", e.tr.sent)
	}
}

func TestShutdownDuringSendLeavesItemQueued(t *testing.T) {
	e := setup(t)
	e.enqueue(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	e.tr.sendErr = func(string) error {
		cancel() // shutdown arrives mid-transmission and the send is aborted
		return errors.New("use of closed network connection")
	}
	if _, err := e.w.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	due, _ := e.st.Due(t0, 10)
	if len(due) != 1 || due[0].Attempts != 0 {
		t.Fatalf("item must stay due and untouched for the next start: %+v", due)
	}
}

func TestDeliveredItemIsNotResentWhenItsRemovalFails(t *testing.T) {
	e := setup(t)
	e.enqueue(t, 1)
	e.q.markErr = errors.New("no space left on device")
	for i := 0; i < 3; i++ {
		if _, err := e.w.Tick(context.Background()); err == nil {
			t.Fatal("the failed removal was not reported")
		}
	}
	if len(e.tr.sent) != 1 || e.tr.opens != 1 {
		t.Fatalf("sent=%d opens=%d, want exactly one transmission", len(e.tr.sent), e.tr.opens)
	}
	if e.q.marks != 3 {
		t.Fatalf("removal attempts = %d, want one per tick", e.q.marks)
	}

	// Still not delivered twice, nor failed, once the retry window is over.
	e.clock = t0.Add(2 * store.RetryWindow)
	if _, err := e.w.Tick(context.Background()); err == nil {
		t.Fatal("the failed removal was not reported")
	}
	if failed, _ := e.st.ListFailed(); len(failed) != 0 {
		t.Fatalf("a delivered item was moved to the failed queue: %+v", failed)
	}

	e.q.markErr = nil
	e.tick(t)
	if st, _ := e.st.Stats(); st.Pending != 0 || st.Failed != 0 || len(e.tr.sent) != 1 {
		t.Fatalf("stats = %+v, sent = %d", st, len(e.tr.sent))
	}
	// A later item with the queue healthy again is delivered normally.
	e.enqueue(t, 2)
	e.tick(t)
	if len(e.tr.sent) != 2 {
		t.Fatalf("sent = %d", len(e.tr.sent))
	}
}

func TestUnreadableMail(t *testing.T) {
	t.Run("read error is retried with backoff and without SMTP", func(t *testing.T) {
		e := setup(t)
		e.enqueue(t, 1)
		e.q.mailErr = errors.New("input/output error")
		e.tick(t)
		if e.tr.opens != 0 {
			t.Fatal("an SMTP session was opened for an unreadable mail")
		}
		if now, _ := e.st.Due(t0, 10); len(now) != 0 {
			t.Fatal("item still due immediately")
		}
		due, _ := e.st.Due(t0.Add(time.Hour), 10)
		if len(due) != 1 || due[0].Attempts != 1 || due[0].LastErrorKind != kindMailUnreadable {
			t.Fatalf("pending = %+v", due)
		}
		e.q.mailErr = nil
		e.clock = due[0].NextAttempt
		e.tick(t)
		if len(e.tr.sent) != 1 {
			t.Fatalf("sent = %d after the mail became readable", len(e.tr.sent))
		}
	})
	t.Run("missing mail fails at once and does not hold up others", func(t *testing.T) {
		e := setup(t)
		bad := e.enqueue(t, 1)
		good := e.enqueue(t, 2)
		missing := &missingMail{flakyQueue: e.q, id: bad}
		e.w = New(missing, e.tr, metrics.New(nil, []string{store.ReasonExpired, store.ReasonPermanent}),
			slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return e.clock })
		e.tick(t)
		failed, _ := e.st.ListFailed()
		if len(failed) != 1 || failed[0].ID != bad || failed[0].FailReason != store.ReasonPermanent ||
			failed[0].LastErrorKind != kindMailUnreadable {
			t.Fatalf("failed queue = %+v", failed)
		}
		if len(e.tr.sent) != 1 || e.tr.sent[0] != "mail-"+good {
			t.Fatalf("sent = %v", e.tr.sent)
		}
	})
}

type missingMail struct {
	*flakyQueue
	id string
}

func (q *missingMail) Mail(id string) ([]byte, error) {
	if id == q.id {
		return nil, store.ErrNotFound
	}
	return q.flakyQueue.Mail(id)
}
