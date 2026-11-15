package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

var t0 = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

func open(t *testing.T, limit int64) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func id(n int) string { return fmt.Sprintf("%032x", n) }

func idemItem(n int, caller, key string, at time.Time) *Item {
	return &Item{
		ID: id(n), Source: caller, Receiver: "ops", Level: "info", AcceptedAt: at,
		KeyFingerprint: "FP-A", EnvelopeFrom: "a@example.com", EnvelopeTo: "b@example.com",
		Deadline: at.Add(RetryWindow), NextAttempt: at,
		DedupKind: DedupIdem, DedupKey: IdemKey(caller, key),
	}
}

func grafanaItem(n int, body string, at time.Time) *Item {
	it := idemItem(n, "grafana", "", at)
	it.DedupKind, it.DedupKey = DedupGrafana, GrafanaKey("grafana", sha256.Sum256([]byte(body)))
	return it
}

// recount compares the stored counters with a full scan.
func recount(t *testing.T, s *Store) {
	t.Helper()
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	counts := map[string]int{}
	s.db.View(func(tx *bolt.Tx) error {
		for _, name := range dataBuckets {
			tx.Bucket(name).ForEach(func(k, v []byte) error {
				total += int64(len(k) + len(v))
				counts[string(name)]++
				return nil
			})
		}
		return nil
	})
	if st.Bytes != total || st.Pending != counts["pending"] || st.Failed != counts["failed"] || st.Quarantined != counts["quarantine"] {
		t.Fatalf("counters drifted: stats=%+v scan bytes=%d counts=%v", st, total, counts)
	}
	if counts["due"] != counts["pending"] {
		t.Fatalf("due index has %d entries for %d pending items", counts["due"], counts["pending"])
	}
	if counts["blob"] != counts["pending"]+counts["failed"]+counts["quarantine"] {
		t.Fatalf("blob count %d does not match items %v", counts["blob"], counts)
	}
}

func TestEnqueueDeliverAndIdempotencyRetention(t *testing.T) {
	s, _ := open(t, DefaultLimit)
	hash := sha256.Sum256([]byte("content"))
	mail := []byte("encrypted mail")

	if err := s.Enqueue(idemItem(1, "app", "k1", t0), mail, hash, t0); err != nil {
		t.Fatal(err)
	}
	// The same key belongs to each caller separately.
	if _, _, found, _ := s.LookupIdem("other", "k1", t0); found {
		t.Fatal("key leaked across callers")
	}
	gotID, gotHash, found, err := s.LookupIdem("app", "k1", t0)
	if err != nil || !found || gotID != id(1) || gotHash != hash {
		t.Fatalf("LookupIdem = %q %x %v %v", gotID, gotHash, found, err)
	}
	if err := s.Enqueue(idemItem(2, "app", "k1", t0), mail, hash, t0); !errors.Is(err, ErrExists) {
		t.Fatalf("second Enqueue with the same key = %v, want ErrExists", err)
	}
	recount(t, s)

	due, _ := s.Due(t0, 10)
	if len(due) != 1 || due[0].ID != id(1) {
		t.Fatalf("Due = %v", due)
	}
	if got, err := s.Mail(id(1)); err != nil || !bytes.Equal(got, mail) {
		t.Fatalf("Mail = %q %v", got, err)
	}
	delivered := t0.Add(time.Minute)
	if err := s.MarkDelivered(id(1), delivered); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mail(id(1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mail still present after delivery: %v", err)
	}
	recount(t, s)

	// The record outlives delivery by 24 hours, across sweeps.
	almost := delivered.Add(Retention - time.Second)
	if _, err := s.Sweep(almost); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := s.LookupIdem("app", "k1", almost); !found {
		t.Fatal("idempotency record gone before 24h")
	}
	after := delivered.Add(Retention)
	if _, _, found, _ := s.LookupIdem("app", "k1", after); found {
		t.Fatal("idempotency record still honoured after 24h")
	}
	if res, err := s.Sweep(after); err != nil || res.Dedup != 1 {
		t.Fatalf("Sweep = %+v %v", res, err)
	}
	if st, _ := s.Stats(); st.Bytes != 0 {
		t.Fatalf("storage not empty after everything expired: %+v", st)
	}
	recount(t, s)
}

func TestStorageLimit(t *testing.T) {
	s, _ := open(t, 5000)
	mail := bytes.Repeat([]byte("x"), 1500)
	var hash [32]byte
	if err := s.Enqueue(idemItem(1, "app", "k1", t0), mail, hash, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(idemItem(2, "app", "k2", t0), mail, hash, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(idemItem(3, "app", "k3", t0), mail, hash, t0); !errors.Is(err, ErrFull) {
		t.Fatalf("Enqueue over the limit = %v, want ErrFull", err)
	}
	// A refused request leaves no trace, so the key can be retried.
	if _, _, found, _ := s.LookupIdem("app", "k3", t0); found {
		t.Fatal("refused request left an idempotency record")
	}
	recount(t, s)
	// The failed queue counts too: moving an item there frees nothing.
	if err := s.Fail(id(1), ReasonPermanent, true, "smtp", 550, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(idemItem(3, "app", "k3", t0), mail, hash, t0); !errors.Is(err, ErrFull) {
		t.Fatalf("Enqueue with a full failed queue = %v, want ErrFull", err)
	}
	if err := s.DeleteFailed(id(1), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(idemItem(3, "app", "k3", t0), mail, hash, t0); err != nil {
		t.Fatalf("Enqueue after freeing space: %v", err)
	}
	recount(t, s)
}

func TestRescheduleFailRetryDelete(t *testing.T) {
	s, _ := open(t, DefaultLimit)
	var hash [32]byte
	if err := s.Enqueue(idemItem(1, "app", "k1", t0), []byte("m"), hash, t0); err != nil {
		t.Fatal(err)
	}
	next := t0.Add(30 * time.Second)
	if err := s.Reschedule(id(1), next, "smtp", 451); err != nil {
		t.Fatal(err)
	}
	if due, _ := s.Due(t0.Add(29*time.Second), 10); len(due) != 0 {
		t.Fatal("item due before its next attempt")
	}
	if at, ok, _ := s.NextDue(); !ok || !at.Equal(next) {
		t.Fatalf("NextDue = %v %v", at, ok)
	}
	due, _ := s.Due(next, 10)
	if len(due) != 1 || due[0].Attempts != 1 || due[0].LastSMTPCode != 451 {
		t.Fatalf("Due = %+v", due)
	}
	recount(t, s)

	failedAt := t0.Add(time.Hour)
	if err := s.Fail(id(1), ReasonExpired, false, "", 0, failedAt); err != nil {
		t.Fatal(err)
	}
	failed, _ := s.ListFailed()
	if len(failed) != 1 || failed[0].FailReason != ReasonExpired || !failed[0].FailedAt.Equal(failedAt) {
		t.Fatalf("ListFailed = %+v", failed)
	}
	if due, _ := s.Due(failedAt, 10); len(due) != 0 {
		t.Fatal("failed item still due")
	}
	// The key stays reserved while the item sits in the failed queue.
	if _, _, found, _ := s.LookupIdem("app", "k1", failedAt.Add(23*time.Hour)); !found {
		t.Fatal("idempotency record lost while item is in the failed queue")
	}
	recount(t, s)

	retryAt := failedAt.Add(2 * time.Hour)
	if err := s.RetryFailed(id(1), retryAt); err != nil {
		t.Fatal(err)
	}
	due, _ = s.Due(retryAt, 10)
	if len(due) != 1 || due[0].Attempts != 0 || !due[0].Deadline.Equal(retryAt.Add(RetryWindow)) || due[0].ID != id(1) {
		t.Fatalf("after retry: %+v", due)
	}
	if got, _ := s.Mail(id(1)); string(got) != "m" {
		t.Fatal("ciphertext changed by retry")
	}
	if err := s.RetryFailed(id(1), retryAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RetryFailed on a pending item = %v", err)
	}

	// Failing again restarts the 24h retention.
	failedAgain := retryAt.Add(time.Hour)
	if err := s.Fail(id(1), ReasonPermanent, true, "smtp", 550, failedAgain); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.Sweep(failedAgain.Add(Retention - time.Second)); res.Failed != 0 {
		t.Fatal("failed item swept before 24h")
	}
	swept := failedAgain.Add(Retention)
	if res, _ := s.Sweep(swept); res.Failed != 1 {
		t.Fatal("failed item not swept after 24h")
	}
	// Auto-deletion is a final state: the record lives 24h more.
	if _, _, found, _ := s.LookupIdem("app", "k1", swept.Add(Retention-time.Second)); !found {
		t.Fatal("idempotency record gone right after auto-deletion")
	}
	if _, _, found, _ := s.LookupIdem("app", "k1", swept.Add(Retention)); found {
		t.Fatal("idempotency record kept beyond 24h after auto-deletion")
	}
	recount(t, s)
}

func TestGrafanaSuppressionWindowIsFixed(t *testing.T) {
	s, _ := open(t, DefaultLimit)
	hash := sha256.Sum256([]byte("body"))
	if err := s.Enqueue(grafanaItem(1, "body", t0), []byte("m"), [32]byte{}, t0); err != nil {
		t.Fatal(err)
	}
	if got, found, _ := s.LookupGrafana("grafana", hash, t0.Add(GrafanaSuppression-time.Second)); !found || got != id(1) {
		t.Fatalf("LookupGrafana inside the window = %q %v", got, found)
	}
	// Delivery does not extend or shorten the window.
	if err := s.MarkDelivered(id(1), t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.LookupGrafana("grafana", hash, t0.Add(4*time.Minute)); !found {
		t.Fatal("suppression ended early after delivery")
	}
	after := t0.Add(GrafanaSuppression)
	if _, found, _ := s.LookupGrafana("grafana", hash, after); found {
		t.Fatal("suppression still active after 5 minutes")
	}
	if err := s.Enqueue(grafanaItem(2, "body", after), []byte("m"), [32]byte{}, after); err != nil {
		t.Fatalf("same body after the window: %v", err)
	}
	recount(t, s)
}

func TestReplayMark(t *testing.T) {
	s, _ := open(t, DefaultLimit)
	key := ReplayKey("grafana", []byte("signature"))
	exp := t0.Add(9 * time.Minute)
	if err := s.EnqueueSigned(grafanaItem(1, "body", t0), []byte("m"), [32]byte{}, &Replay{Key: key, Expires: exp}, t0); err != nil {
		t.Fatal(err)
	}
	// It outlives the body suppression and ends with the signature.
	if got, found, _ := s.LookupReplay(key, exp.Add(-time.Second)); !found || got != id(1) {
		t.Fatalf("LookupReplay before expiry = %q %v", got, found)
	}
	if _, found, _ := s.LookupReplay(key, exp); found {
		t.Fatal("replay mark still active at its expiry")
	}
	if _, found, _ := s.LookupReplay(ReplayKey("grafana", []byte("other")), t0); found {
		t.Fatal("unrelated signature reported as used")
	}
	// A second item for the same signed request is refused as a whole.
	late := t0.Add(GrafanaSuppression)
	err := s.EnqueueSigned(grafanaItem(2, "body", late), []byte("m"), [32]byte{}, &Replay{Key: key, Expires: exp}, late)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("replayed enqueue: err = %v, want ErrExists", err)
	}
	if st, _ := s.Stats(); st.Pending != 1 {
		t.Fatalf("pending = %d", st.Pending)
	}
	recount(t, s)
	if res, err := s.Sweep(exp); err != nil || res.Dedup != 2 {
		t.Fatalf("Sweep = %+v, %v; want the body record and the replay mark removed", res, err)
	}
	recount(t, s)
}

func TestQuarantineDropsReplayMark(t *testing.T) {
	s, _ := open(t, DefaultLimit)
	key := ReplayKey("grafana", []byte("signature"))
	g := grafanaItem(1, "body", t0)
	g.KeyFingerprint = "OLD"
	if err := s.EnqueueSigned(g, []byte("m"), [32]byte{}, &Replay{Key: key, Expires: t0.Add(9 * time.Minute)}, t0); err != nil {
		t.Fatal(err)
	}
	if moved, err := s.Quarantine([]string{"OLD"}, t0.Add(time.Minute)); err != nil || moved != 1 {
		t.Fatalf("Quarantine = %d, %v", moved, err)
	}
	// The same signed request must be accepted again for the new key.
	if _, found, _ := s.LookupReplay(key, t0.Add(2*time.Minute)); found {
		t.Fatal("replay mark still points at the quarantined item")
	}
	if _, found, _ := s.LookupGrafana("grafana", sha256.Sum256([]byte("body")), t0.Add(2*time.Minute)); found {
		t.Fatal("body record still points at the quarantined item")
	}
	recount(t, s)
}

func TestSessionFailed(t *testing.T) {
	s, _ := open(t, DefaultLimit)
	hash := [32]byte{}
	old := idemItem(1, "app", "k1", t0.Add(-RetryWindow)) // deadline is t0
	if err := s.Enqueue(old, []byte("m"), hash, t0.Add(-RetryWindow)); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 4; i++ {
		if err := s.Enqueue(idemItem(i, "app", fmt.Sprint("k", i), t0), []byte("m"), hash, t0); err != nil {
			t.Fatal(err)
		}
	}
	later := idemItem(5, "app", "k5", t0.Add(time.Minute)) // not due yet
	if err := s.Enqueue(later, []byte("m"), hash, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	next := t0.Add(30 * time.Second)
	retried, expired, err := s.SessionFailed(t0, map[string]bool{id(4): true},
		func(it *Item) time.Time { return next }, "connect", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].ID != id(1) || len(retried) != 2 {
		t.Fatalf("retried = %d, expired = %+v", len(retried), expired)
	}
	for _, it := range retried {
		if it.Attempts != 1 || it.LastErrorKind != "connect" || !it.NextAttempt.Equal(next) {
			t.Fatalf("retried item = %+v", it)
		}
	}
	// Only the skipped item is still due; the later one is untouched.
	due, _ := s.Due(t0, 10)
	if len(due) != 1 || due[0].ID != id(4) || due[0].Attempts != 0 {
		t.Fatalf("due at t0 = %+v", due)
	}
	if all, _ := s.Due(t0.Add(time.Hour), 10); len(all) != 4 {
		t.Fatalf("pending = %d, want 4", len(all))
	}
	if failed, _ := s.ListFailed(); len(failed) != 1 || failed[0].FailReason != ReasonExpired || failed[0].Attempts != 0 {
		t.Fatalf("failed = %+v", failed)
	}
	recount(t, s)
}

func TestQuarantine(t *testing.T) {
	s, _ := open(t, DefaultLimit)
	var hash [32]byte
	mk := func(n int, key, fp string) *Item {
		it := idemItem(n, "app", key, t0)
		it.KeyFingerprint = fp
		return it
	}
	for _, it := range []*Item{mk(1, "k1", "OLD"), mk(2, "k2", "OLD"), mk(3, "k3", "NEW")} {
		if err := s.Enqueue(it, []byte("mail-"+it.ID), hash, t0); err != nil {
			t.Fatal(err)
		}
	}
	g := grafanaItem(4, "body", t0)
	g.KeyFingerprint = "OLD"
	if err := s.Enqueue(g, []byte("mail-g"), hash, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(id(2), ReasonPermanent, true, "smtp", 550, t0); err != nil {
		t.Fatal(err)
	}

	moved, err := s.Quarantine([]string{"OLD"}, t0.Add(time.Minute))
	if err != nil || moved != 3 {
		t.Fatalf("Quarantine = %d %v", moved, err)
	}
	q, _ := s.ListQuarantined()
	if len(q) != 3 {
		t.Fatalf("quarantined = %d", len(q))
	}
	due, _ := s.Due(t0.Add(time.Hour), 10)
	if len(due) != 1 || due[0].ID != id(3) {
		t.Fatalf("only the item for the current key may remain deliverable: %+v", due)
	}
	if failed, _ := s.ListFailed(); len(failed) != 0 {
		t.Fatal("failed item for the quarantined key was not moved")
	}
	// Callers can resend with the same key; Grafana's body is not suppressed.
	for _, k := range []string{"k1", "k2"} {
		if _, _, found, _ := s.LookupIdem("app", k, t0.Add(time.Minute)); found {
			t.Fatalf("idempotency record %s survived quarantine", k)
		}
	}
	if _, _, found, _ := s.LookupIdem("app", "k3", t0.Add(time.Minute)); !found {
		t.Fatal("unrelated idempotency record was deleted")
	}
	if _, found, _ := s.LookupGrafana("grafana", sha256.Sum256([]byte("body")), t0.Add(time.Minute)); found {
		t.Fatal("grafana suppression record survived quarantine")
	}
	// Quarantined items still count against storage and cannot be retried.
	if err := s.RetryFailed(id(2), t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RetryFailed on quarantined item = %v", err)
	}
	recount(t, s)

	if err := s.DeleteQuarantined(id(1)); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.Sweep(t0.Add(time.Minute + Retention)); res.Quarantined != 2 {
		t.Fatalf("Sweep quarantined = %d", res.Quarantined)
	}
	recount(t, s)
}

func TestReopenKeepsQueueAndRebuildsCounters(t *testing.T) {
	s, dir := open(t, DefaultLimit)
	var hash [32]byte
	for i := 1; i <= 3; i++ {
		if err := s.Enqueue(idemItem(i, "app", fmt.Sprint("k", i), t0), []byte("mail"), hash, t0); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := s.Stats()
	// Corrupt the counter to prove Open reconciles it.
	s.db.Update(func(tx *bolt.Tx) error { return putInt(tx, kBytes, 1) })
	s.Close()

	s2, err := Open(dir, DefaultLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	after, _ := s2.Stats()
	if after != before || after.Pending != 3 {
		t.Fatalf("stats after reopen = %+v, before = %+v", after, before)
	}
	if due, _ := s2.Due(t0, 10); len(due) != 3 {
		t.Fatalf("queue lost across restart: %d", len(due))
	}
	if err := s2.ProbeWrite(t0); err != nil {
		t.Fatal(err)
	}
}
