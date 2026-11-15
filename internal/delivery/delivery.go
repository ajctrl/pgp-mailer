// Package delivery drains the pending queue to SMTP, applying the retry
// schedule and moving items to the failed queue on permanent errors or
// when their retry window closes.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"pgp-mailer/internal/metrics"
	"pgp-mailer/internal/smtpsend"
	"pgp-mailer/internal/store"
)

const (
	batchSize   = 50
	maxIdle     = 30 * time.Second
	minIdle     = 200 * time.Millisecond
	errorPause  = 5 * time.Second
	backoffBase = 30 * time.Second
	backoffMax  = 5 * time.Minute
	jitter      = 0.2

	// kindMailUnreadable is the error kind of an attempt that failed because
	// the stored mail could not be read back from the queue.
	kindMailUnreadable = "stored_mail_unreadable"
)

// Queue is the part of the persistent queue the worker uses; *store.Store
// implements it.
type Queue interface {
	Due(now time.Time, limit int) ([]*store.Item, error)
	NextDue() (at time.Time, ok bool, err error)
	Mail(id string) ([]byte, error)
	MarkDelivered(id string, now time.Time) error
	Reschedule(id string, next time.Time, errKind string, smtpCode int) error
	SessionFailed(now time.Time, skip map[string]bool, next func(*store.Item) time.Time, errKind string, smtpCode int) (retried, expired []*store.Item, err error)
	Fail(id, reason string, attempted bool, errKind string, smtpCode int, now time.Time) error
}

// Session is one open SMTP connection.
type Session interface {
	Send(from, to string, msg []byte) error
	Reset() error
	Close()
	Abort()
}

// Transport opens SMTP sessions.
type Transport interface {
	Open(ctx context.Context) (Session, error)
}

// SMTP adapts an smtpsend.Sender to Transport.
func SMTP(s *smtpsend.Sender) Transport { return smtpTransport{s} }

type smtpTransport struct{ s *smtpsend.Sender }

func (t smtpTransport) Open(ctx context.Context) (Session, error) {
	sess, err := t.s.Open(ctx)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// Backoff returns the delay before the next attempt after the given number
// of failed attempts (1-based): 30s, 1m, 2m, 4m, then 5m, each scaled by a
// factor in [0.8, 1.2]. r must be in [0, 1).
func Backoff(failedAttempts int, r float64) time.Duration {
	d := backoffMax
	if failedAttempts >= 1 && failedAttempts <= 4 {
		d = backoffBase << (failedAttempts - 1)
	}
	return time.Duration(float64(d) * (1 - jitter + 2*jitter*r))
}

type Worker struct {
	store     Queue
	transport Transport
	metrics   *metrics.Metrics
	log       *slog.Logger
	now       func() time.Time
	wake      chan struct{}

	// unrecorded holds the IDs of items the SMTP server has accepted but
	// whose removal from the queue failed. They are never transmitted again
	// by this process; only the removal is retried. Used by Tick only.
	unrecorded map[string]bool

	// After a failed connection or authentication no new session is opened
	// before pauseUntil; sessionFailures counts the failures in a row and
	// sets the length of the pause. Used by the Run goroutine only.
	pauseUntil      time.Time
	sessionFailures int

	mu  sync.Mutex
	cur Session
}

func New(q Queue, tr Transport, m *metrics.Metrics, log *slog.Logger, now func() time.Time) *Worker {
	return &Worker{store: q, transport: tr, metrics: m, log: log, now: now,
		wake: make(chan struct{}, 1), unrecorded: map[string]bool{}}
}

// Wake makes the worker look at the queue now instead of at its next timer.
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Abort force-closes the SMTP connection in use, if any. The message being
// sent stays in the queue.
func (w *Worker) Abort() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil {
		w.cur.Abort()
	}
}

func (w *Worker) setCur(s Session) {
	w.mu.Lock()
	w.cur = s
	w.mu.Unlock()
}

// Run delivers until ctx is cancelled. Cancellation does not interrupt a
// message that is already being transmitted; Run returns once it is done.
func (w *Worker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := w.Tick(ctx)
		switch {
		case err != nil:
			w.log.Error("delivery: queue error", "error", err.Error())
			w.sleep(ctx, errorPause)
		case n == 0:
			w.sleep(ctx, w.idleFor())
		}
	}
}

func (w *Worker) idleFor() time.Duration {
	d := maxIdle
	if at, ok, err := w.store.NextDue(); err == nil && ok {
		if until := at.Sub(w.now()); until < d {
			d = until
		}
	}
	// Due items cannot be sent while session opening is paused.
	if rest := w.pauseUntil.Sub(w.now()); rest > d {
		d = rest
	}
	if d < minIdle {
		d = minIdle
	}
	return d
}

func (w *Worker) sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-w.wake:
	case <-t.C:
	}
}

// Tick processes one batch of due items and returns how many it handled.
// Items that only wait for the session pause to end are not counted.
func (w *Worker) Tick(ctx context.Context) (int, error) {
	items, err := w.store.Due(w.now(), batchSize)
	if err != nil || len(items) == 0 {
		return 0, err
	}
	var sess Session
	closeSession := func() {
		if sess != nil {
			w.setCur(nil)
			sess.Close()
			sess = nil
		}
	}
	defer closeSession()

	handled := 0
	var firstErr error
	note := func(err error) {
		if err != nil && !errors.Is(err, store.ErrNotFound) && firstErr == nil {
			firstErr = err
		}
	}

	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		if w.unrecorded[it.ID] {
			// Already handed to the SMTP server: only the bookkeeping is
			// outstanding, whatever the deadline says.
			note(w.recordDelivered(it))
			handled++
			continue
		}
		now := w.now()
		if !now.Before(it.Deadline) {
			note(w.expire(it, now))
			handled++
			continue
		}
		if sess == nil && now.Before(w.pauseUntil) {
			continue
		}
		// Read the mail before any SMTP work, so that an unreadable item
		// costs no connection and takes the normal retry schedule.
		mail, err := w.store.Mail(it.ID)
		if err != nil {
			// Not expected: item and mail are written in one transaction.
			// A missing mail can never be sent; any other read error may pass.
			res := smtpsend.Result{Kind: kindMailUnreadable, Permanent: errors.Is(err, store.ErrNotFound)}
			note(w.attemptFailed(it, res, now))
			handled++
			continue
		}
		if sess == nil {
			s, err := w.transport.Open(ctx)
			if err != nil {
				if ctx.Err() != nil {
					break
				}
				// Open can block for most of a minute; the pause and the
				// retry times count from the moment it gave up.
				now = w.now()
				res := smtpsend.Classify(err)
				w.sessionFailures++
				pause := Backoff(w.sessionFailures, rand.Float64())
				w.pauseUntil = now.Add(pause)
				w.logSessionError(res, pause)
				// A 5xx at this stage (greeting, AUTH) is about the server
				// or our credentials, not about any one message: the mails
				// can still be delivered once it is fixed, so they keep
				// their retry window instead of failing at once.
				res.Permanent = false
				// Nothing can be sent right now, so the failure counts as an
				// attempt for every item that is due, in this batch or not.
				retried, expired, err := w.store.SessionFailed(now, w.unrecorded, func(it *store.Item) time.Time {
					return nextAttempt(it, it.Attempts, now)
				}, res.Kind, res.Code)
				note(err)
				for _, it := range expired {
					w.noteExpired(it)
				}
				for _, it := range retried {
					w.logRetry(it, it.Attempts, res)
				}
				handled += len(retried) + len(expired)
				break
			}
			sess = s
			w.setCur(s)
			w.sessionFailures, w.pauseUntil = 0, time.Time{}
		}
		handled++
		err = sess.Send(it.EnvelopeFrom, it.EnvelopeTo, mail)
		if err == nil {
			w.metrics.Delivered()
			w.log.Info("delivered", itemAttrs(it, "delivered", it.Attempts+1)...)
			note(w.recordDelivered(it))
			continue
		}
		if ctx.Err() != nil {
			// Shutdown interrupted the transmission: leave the item as it
			// is so that it is retried on the next start.
			break
		}
		res := smtpsend.Classify(err)
		note(w.attemptFailed(it, res, w.now()))
		if !res.SMTP || sess.Reset() != nil {
			closeSession()
		}
	}
	return handled, firstErr
}

func itemAttrs(it *store.Item, result string, attempts int) []any {
	return []any{"id", it.ID, "source", it.Source, "receiver", it.Receiver, "level", it.Level,
		"result", result, "attempts", attempts}
}

func (w *Worker) logSessionError(res smtpsend.Result, pause time.Duration) {
	attrs := []any{"result", "smtp_session_failed", "kind", res.Kind, "retry_in_seconds", int(pause.Seconds())}
	if res.Code != 0 {
		attrs = append(attrs, "smtp_code", res.Code)
	}
	// Certificate failures and 5xx replies (535: wrong credentials) are
	// retried like other session errors but are always worth an operator's
	// attention.
	if res.Kind == smtpsend.KindTLSCert || res.Permanent {
		w.log.Error("smtp session failed", attrs...)
	} else {
		w.log.Warn("smtp session failed", attrs...)
	}
}

// recordDelivered removes a delivered item from the queue. If that fails the
// item is remembered, so that later ticks retry the removal instead of
// sending the mail again. The memory does not survive a restart; the mail is
// then sent once more, as after any interrupted shutdown.
func (w *Worker) recordDelivered(it *store.Item) error {
	err := w.store.MarkDelivered(it.ID, w.now())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		w.unrecorded[it.ID] = true
		return fmt.Errorf("item %s was delivered but could not be removed from the queue: %w", it.ID, err)
	}
	delete(w.unrecorded, it.ID)
	return nil
}

func (w *Worker) expire(it *store.Item, now time.Time) error {
	if err := w.store.Fail(it.ID, store.ReasonExpired, false, "", 0, now); err != nil {
		return err
	}
	w.noteExpired(it)
	return nil
}

func (w *Worker) noteExpired(it *store.Item) {
	w.metrics.Failed(store.ReasonExpired)
	w.log.Error("moved to failed queue", itemAttrs(it, "failed_expired", it.Attempts)...)
}

// nextAttempt is when an item is tried again after its attempts-th failure:
// the backoff, but never past the deadline.
func nextAttempt(it *store.Item, attempts int, now time.Time) time.Time {
	next := now.Add(Backoff(attempts, rand.Float64()))
	if next.After(it.Deadline) {
		next = it.Deadline
	}
	return next
}

func attemptAttrs(it *store.Item, result string, attempts int, res smtpsend.Result) []any {
	a := append(itemAttrs(it, result, attempts), "kind", res.Kind)
	if res.Code != 0 {
		a = append(a, "smtp_code", res.Code)
	}
	return a
}

func (w *Worker) logRetry(it *store.Item, attempts int, res smtpsend.Result) {
	// Certificate failures and unreadable mails are retried like other
	// transient errors but are always worth an operator's attention.
	if res.Kind == smtpsend.KindTLSCert || res.Kind == kindMailUnreadable {
		w.log.Error("delivery attempt failed", attemptAttrs(it, "retry_scheduled", attempts, res)...)
	} else {
		w.log.Warn("delivery attempt failed", attemptAttrs(it, "retry_scheduled", attempts, res)...)
	}
}

func (w *Worker) attemptFailed(it *store.Item, res smtpsend.Result, now time.Time) error {
	attempts := it.Attempts + 1
	if res.Permanent {
		if err := w.store.Fail(it.ID, store.ReasonPermanent, true, res.Kind, res.Code, now); err != nil {
			return err
		}
		w.metrics.Failed(store.ReasonPermanent)
		w.log.Error("moved to failed queue", attemptAttrs(it, "failed_permanent", attempts, res)...)
		return nil
	}
	if err := w.store.Reschedule(it.ID, nextAttempt(it, attempts, now), res.Kind, res.Code); err != nil {
		return err
	}
	w.logRetry(it, attempts, res)
	return nil
}
