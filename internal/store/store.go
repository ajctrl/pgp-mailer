// Package store is the persistent queue. Pending, failed and quarantined
// items, the encrypted mails, both kinds of de-duplication record and the
// storage counters all live in one bbolt file, so every state change is a
// single fsynced transaction.
package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	// DefaultLimit is the application-level cap on stored logical bytes.
	DefaultLimit = 256 << 20
	// RetryWindow is how long delivery is retried after acceptance (or
	// after a manual retry).
	RetryWindow = time.Hour
	// Retention is how long failed and quarantined items, and finished
	// idempotency records, are kept.
	Retention = 24 * time.Hour
	// GrafanaSuppression is the fixed body-based suppression window.
	GrafanaSuppression = 5 * time.Minute

	fileName = "queue.db"
)

var (
	ErrFull     = errors.New("queue storage limit reached")
	ErrNotFound = errors.New("item not found")
	ErrExists   = errors.New("de-duplication record already exists")
)

var (
	bMeta       = []byte("meta")
	bPending    = []byte("pending")
	bFailed     = []byte("failed")
	bQuarantine = []byte("quarantine")
	bBlob       = []byte("blob")
	bDue        = []byte("due")
	bIdem       = []byte("idem")
	bGrafana    = []byte("grafana")
	bReplay     = []byte("replay")

	// Buckets whose contents count against the storage limit.
	dataBuckets = [][]byte{bPending, bFailed, bQuarantine, bBlob, bDue, bIdem, bGrafana, bReplay}

	kBytes  = []byte("bytes")
	kHealth = []byte("health")

	// Index entries carry a non-empty value so that presence checks never
	// depend on how bbolt represents empty values.
	dueVal = []byte{1}
)

// Dedup kinds.
const (
	DedupIdem    = "idem"
	DedupGrafana = "grafana"
)

// Failure reasons.
const (
	ReasonExpired   = "expired"
	ReasonPermanent = "permanent"
)

// Item is the metadata of one accepted notification. It never contains the
// title, the message or any plaintext; the encrypted mail is stored apart.
type Item struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	Receiver   string    `json:"receiver"`
	Level      string    `json:"level"`
	AcceptedAt time.Time `json:"accepted_at"`

	KeyFingerprint string `json:"key_fingerprint"`
	EncSubkeyID    string `json:"enc_subkey_id"`

	EnvelopeFrom string `json:"envelope_from"`
	EnvelopeTo   string `json:"envelope_to"`
	MessageID    string `json:"message_id"`

	Deadline    time.Time `json:"deadline"`
	NextAttempt time.Time `json:"next_attempt"`
	Attempts    int       `json:"attempts"`

	// Outcome of the most recent delivery attempt: an error class and the
	// SMTP reply code (0 if none). Server reply text is not kept.
	LastErrorKind string `json:"last_error_kind,omitempty"`
	LastSMTPCode  int    `json:"last_smtp_code,omitempty"`

	FailReason    string    `json:"fail_reason,omitempty"`
	FailedAt      time.Time `json:"failed_at,omitzero"`
	QuarantinedAt time.Time `json:"quarantined_at,omitzero"`

	DedupKind string `json:"dedup_kind"`
	DedupKey  []byte `json:"dedup_key"`
	// ReplayKey is the key of the replay mark written with the item, if any.
	ReplayKey []byte `json:"replay_key,omitempty"`
}

// Stats is a snapshot of the counters kept in the database.
type Stats struct {
	Bytes       int64
	Pending     int
	Failed      int
	Quarantined int
}

type Store struct {
	db    *bolt.DB
	limit int64
}

// Open opens (creating if needed) the queue database in dir and reconciles
// the stored counters with the actual contents.
func Open(dir string, limit int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("queue dir: %w", err)
	}
	db, err := bolt.Open(filepath.Join(dir, fileName), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open queue db: %w", err)
	}
	s := &Store{db: db, limit: limit}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bMeta); err != nil {
			return err
		}
		var total int64
		for _, name := range dataBuckets {
			b, err := tx.CreateBucketIfNotExists(name)
			if err != nil {
				return err
			}
			var n int64
			if err := b.ForEach(func(k, v []byte) error {
				total += int64(len(k) + len(v))
				n++
				return nil
			}); err != nil {
				return err
			}
			if err := putInt(tx, countKey(name), n); err != nil {
				return err
			}
		}
		return putInt(tx, kBytes, total)
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init queue db: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Limit returns the configured storage limit in bytes.
func (s *Store) Limit() int64 { return s.limit }

func countKey(bucket []byte) []byte { return append([]byte("n:"), bucket...) }

func getInt(tx *bolt.Tx, key []byte) int64 {
	v := tx.Bucket(bMeta).Get(key)
	if len(v) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(v))
}

func putInt(tx *bolt.Tx, key []byte, n int64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return tx.Bucket(bMeta).Put(key, b[:])
}

// txn wraps a write transaction and keeps the byte and item counters in
// step with every put and delete.
type txn struct {
	tx     *bolt.Tx
	dBytes int64
	dCount map[string]int64
}

func (t *txn) get(bucket, key []byte) []byte { return t.tx.Bucket(bucket).Get(key) }

func (t *txn) put(bucket, key, val []byte) error {
	b := t.tx.Bucket(bucket)
	if old := b.Get(key); old != nil {
		t.dBytes -= int64(len(key) + len(old))
	} else {
		t.dCount[string(bucket)]++
	}
	t.dBytes += int64(len(key) + len(val))
	return b.Put(key, val)
}

func (t *txn) del(bucket, key []byte) error {
	b := t.tx.Bucket(bucket)
	old := b.Get(key)
	if old == nil {
		return nil
	}
	t.dBytes -= int64(len(key) + len(old))
	t.dCount[string(bucket)]--
	return b.Delete(key)
}

func (t *txn) putItem(bucket []byte, it *Item) error {
	v, err := json.Marshal(it)
	if err != nil {
		return err
	}
	return t.put(bucket, []byte(it.ID), v)
}

func (t *txn) getItem(bucket []byte, id string) (*Item, error) {
	return decodeItem(t.get(bucket, []byte(id)))
}

func decodeItem(v []byte) (*Item, error) {
	if v == nil {
		return nil, ErrNotFound
	}
	it := &Item{}
	if err := json.Unmarshal(v, it); err != nil {
		return nil, fmt.Errorf("corrupt item: %w", err)
	}
	return it, nil
}

func (s *Store) update(fn func(t *txn) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		t := &txn{tx: tx, dCount: map[string]int64{}}
		if err := fn(t); err != nil {
			return err
		}
		for name, d := range t.dCount {
			if d != 0 {
				k := countKey([]byte(name))
				if err := putInt(tx, k, getInt(tx, k)+d); err != nil {
					return err
				}
			}
		}
		if t.dBytes != 0 {
			return putInt(tx, kBytes, getInt(tx, kBytes)+t.dBytes)
		}
		return nil
	})
}

func dueKey(at time.Time, id string) []byte {
	k := make([]byte, 8, 8+len(id))
	binary.BigEndian.PutUint64(k, uint64(at.UnixNano()))
	return append(k, id...)
}

// --- de-duplication records -------------------------------------------------
//
// idem value:    expiresAt(8) | id(32) | contentHash(32)
// grafana value: expiresAt(8) | id(32)
// replay value:  expiresAt(8) | id(32)
//
// expiresAt is Unix nanoseconds; 0 means "kept while the item is alive".
// Neither record contains any message content.

const idLen = 32

func IdemKey(caller, key string) []byte {
	return append(append([]byte(caller), 0), key...)
}

func GrafanaKey(source string, bodyHash [32]byte) []byte {
	return append(append([]byte(source), 0), bodyHash[:]...)
}

func encodeDedup(expires time.Time, id string, hash []byte) []byte {
	v := make([]byte, 8, 8+idLen+len(hash))
	if !expires.IsZero() {
		binary.BigEndian.PutUint64(v, uint64(expires.UnixNano()))
	}
	v = append(v, id...)
	return append(v, hash...)
}

// decodeDedup returns ok=false for malformed or expired records.
func decodeDedup(v []byte, now time.Time) (id string, hash []byte, ok bool) {
	if len(v) < 8+idLen {
		return "", nil, false
	}
	if exp := int64(binary.BigEndian.Uint64(v)); exp != 0 && exp <= now.UnixNano() {
		return "", nil, false
	}
	return string(v[8 : 8+idLen]), bytes.Clone(v[8+idLen:]), true
}

// LookupIdem returns the acceptance ID and content hash recorded for an
// Idempotency-Key of one caller.
func (s *Store) LookupIdem(caller, key string, now time.Time) (id string, hash [32]byte, found bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		rid, h, ok := decodeDedup(tx.Bucket(bIdem).Get(IdemKey(caller, key)), now)
		if ok && len(h) == 32 {
			id, found = rid, true
			copy(hash[:], h)
		}
		return nil
	})
	return
}

// LookupGrafana returns the acceptance ID of an identical body received
// from source within the suppression window.
func (s *Store) LookupGrafana(source string, bodyHash [32]byte, now time.Time) (id string, found bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		id, _, found = decodeDedup(tx.Bucket(bGrafana).Get(GrafanaKey(source, bodyHash)), now)
		return nil
	})
	return
}

// Replay marks one signed request as used: Key identifies the request (see
// ReplayKey) and the mark is kept until Expires, the moment its signature
// stops being accepted anyway.
type Replay struct {
	Key     []byte
	Expires time.Time
}

func ReplayKey(source string, signature []byte) []byte {
	return append(append([]byte(source), 0), signature...)
}

// LookupReplay returns the acceptance ID recorded for a signed request that
// was already accepted and whose mark has not expired.
func (s *Store) LookupReplay(key []byte, now time.Time) (id string, found bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		id, _, found = decodeDedup(tx.Bucket(bReplay).Get(key), now)
		return nil
	})
	return
}

// --- intake -----------------------------------------------------------------

// Enqueue stores the item, its encrypted mail and its de-duplication record
// in one transaction. For DedupIdem, contentHash is recorded with the key;
// for DedupGrafana the record expires GrafanaSuppression after now. It
// returns ErrFull when the storage limit would be exceeded and ErrExists if
// a live de-duplication record is already present.
func (s *Store) Enqueue(it *Item, mail []byte, contentHash [32]byte, now time.Time) error {
	return s.EnqueueSigned(it, mail, contentHash, nil, now)
}

// EnqueueSigned is Enqueue for a request that carried a signature: if replay
// is not nil, the mark is written in the same transaction, and ErrExists is
// returned when a live mark for the same request is already present.
func (s *Store) EnqueueSigned(it *Item, mail []byte, contentHash [32]byte, replay *Replay, now time.Time) error {
	return s.update(func(t *txn) error {
		if replay != nil {
			if _, _, ok := decodeDedup(t.get(bReplay, replay.Key), now); ok {
				return ErrExists
			}
			if err := t.put(bReplay, replay.Key, encodeDedup(replay.Expires, it.ID, nil)); err != nil {
				return err
			}
			it.ReplayKey = replay.Key
		}
		switch it.DedupKind {
		case DedupIdem:
			if _, _, ok := decodeDedup(t.get(bIdem, it.DedupKey), now); ok {
				return ErrExists
			}
			if err := t.put(bIdem, it.DedupKey, encodeDedup(time.Time{}, it.ID, contentHash[:])); err != nil {
				return err
			}
		case DedupGrafana:
			if _, _, ok := decodeDedup(t.get(bGrafana, it.DedupKey), now); ok {
				return ErrExists
			}
			if err := t.put(bGrafana, it.DedupKey, encodeDedup(now.Add(GrafanaSuppression), it.ID, nil)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown dedup kind %q", it.DedupKind)
		}
		if err := t.putItem(bPending, it); err != nil {
			return err
		}
		if err := t.put(bBlob, []byte(it.ID), mail); err != nil {
			return err
		}
		if err := t.put(bDue, dueKey(it.NextAttempt, it.ID), dueVal); err != nil {
			return err
		}
		if getInt(t.tx, kBytes)+t.dBytes > s.limit {
			return ErrFull
		}
		return nil
	})
}

// --- delivery ---------------------------------------------------------------

// Due returns up to limit pending items whose next attempt is at or before
// now, earliest first.
func (s *Store) Due(now time.Time, limit int) ([]*Item, error) {
	var out []*Item
	err := s.db.View(func(tx *bolt.Tx) error {
		pending := tx.Bucket(bPending)
		c := tx.Bucket(bDue).Cursor()
		for k, _ := c.First(); k != nil && len(out) < limit; k, _ = c.Next() {
			if len(k) < 8 || int64(binary.BigEndian.Uint64(k)) > now.UnixNano() {
				break
			}
			it, err := decodeItem(pending.Get(k[8:]))
			if err != nil {
				continue // index entry without item; cannot happen transactionally
			}
			out = append(out, it)
		}
		return nil
	})
	return out, err
}

// NextDue returns the time of the earliest scheduled attempt.
func (s *Store) NextDue() (at time.Time, ok bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		if k, _ := tx.Bucket(bDue).Cursor().First(); len(k) >= 8 {
			at, ok = time.Unix(0, int64(binary.BigEndian.Uint64(k))), true
		}
		return nil
	})
	return
}

// Mail returns the stored encrypted mail of an item in any queue.
func (s *Store) Mail(id string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bBlob).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		out = bytes.Clone(v)
		return nil
	})
	return out, err
}

// finishDedup starts the retention clock of an item's idempotency record
// once the item has reached a final state. Grafana records keep their own
// fixed window.
func (t *txn) finishDedup(it *Item, now time.Time) error {
	if it.DedupKind != DedupIdem {
		return nil
	}
	v := t.get(bIdem, it.DedupKey)
	if len(v) < 8+idLen || string(v[8:8+idLen]) != it.ID {
		return nil
	}
	return t.put(bIdem, it.DedupKey, encodeDedup(now.Add(Retention), it.ID, v[8+idLen:]))
}

// dropDedup removes the de-duplication record and the replay mark that
// point at the item.
func (t *txn) dropDedup(it *Item) error {
	bucket := bIdem
	if it.DedupKind == DedupGrafana {
		bucket = bGrafana
	}
	for _, rec := range []struct{ bucket, key []byte }{{bucket, it.DedupKey}, {bReplay, it.ReplayKey}} {
		if len(rec.key) == 0 {
			continue
		}
		v := t.get(rec.bucket, rec.key)
		if len(v) < 8+idLen || string(v[8:8+idLen]) != it.ID {
			continue
		}
		if err := t.del(rec.bucket, rec.key); err != nil {
			return err
		}
	}
	return nil
}

// MarkDelivered removes a pending item after a successful SMTP hand-over.
func (s *Store) MarkDelivered(id string, now time.Time) error {
	return s.update(func(t *txn) error {
		it, err := t.getItem(bPending, id)
		if err != nil {
			return err
		}
		if err := t.del(bDue, dueKey(it.NextAttempt, id)); err != nil {
			return err
		}
		if err := t.del(bPending, []byte(id)); err != nil {
			return err
		}
		if err := t.del(bBlob, []byte(id)); err != nil {
			return err
		}
		return t.finishDedup(it, now)
	})
}

// Reschedule records a failed attempt on a pending item and sets its next
// attempt time.
func (s *Store) Reschedule(id string, next time.Time, errKind string, smtpCode int) error {
	return s.update(func(t *txn) error {
		it, err := t.getItem(bPending, id)
		if err != nil {
			return err
		}
		if err := t.del(bDue, dueKey(it.NextAttempt, id)); err != nil {
			return err
		}
		it.Attempts++
		it.NextAttempt = next
		it.LastErrorKind, it.LastSMTPCode = errKind, smtpCode
		if err := t.putItem(bPending, it); err != nil {
			return err
		}
		return t.put(bDue, dueKey(next, id), dueVal)
	})
}

// SessionFailed records, in one transaction, a failed attempt on every
// pending item that is due at now: nothing could be sent because no SMTP
// session could be opened. Items past their deadline are moved to the failed
// queue as expired instead. next gives an item's next attempt time and is
// called with the attempt already counted; IDs in skip are left alone. The
// returned items show the state after the change.
func (s *Store) SessionFailed(now time.Time, skip map[string]bool, next func(*Item) time.Time, errKind string, smtpCode int) (retried, expired []*Item, err error) {
	err = s.update(func(t *txn) error {
		retried, expired = nil, nil
		var due []*Item
		pending := t.tx.Bucket(bPending)
		c := t.tx.Bucket(bDue).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if len(k) < 8 || int64(binary.BigEndian.Uint64(k)) > now.UnixNano() {
				break
			}
			if it, err := decodeItem(pending.Get(k[8:])); err == nil && !skip[it.ID] {
				due = append(due, it)
			}
		}
		for _, it := range due {
			if err := t.del(bDue, dueKey(it.NextAttempt, it.ID)); err != nil {
				return err
			}
			if !now.Before(it.Deadline) {
				if err := t.del(bPending, []byte(it.ID)); err != nil {
					return err
				}
				it.FailReason, it.FailedAt = ReasonExpired, now
				if err := t.putItem(bFailed, it); err != nil {
					return err
				}
				expired = append(expired, it)
				continue
			}
			it.Attempts++
			it.LastErrorKind, it.LastSMTPCode = errKind, smtpCode
			it.NextAttempt = next(it)
			if err := t.putItem(bPending, it); err != nil {
				return err
			}
			if err := t.put(bDue, dueKey(it.NextAttempt, it.ID), dueVal); err != nil {
				return err
			}
			retried = append(retried, it)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return retried, expired, nil
}

// Fail moves a pending item to the failed queue. attempted says whether
// this follows a delivery attempt (as opposed to plain expiry).
func (s *Store) Fail(id, reason string, attempted bool, errKind string, smtpCode int, now time.Time) error {
	return s.update(func(t *txn) error {
		it, err := t.getItem(bPending, id)
		if err != nil {
			return err
		}
		if err := t.del(bDue, dueKey(it.NextAttempt, id)); err != nil {
			return err
		}
		if err := t.del(bPending, []byte(id)); err != nil {
			return err
		}
		if attempted {
			it.Attempts++
			it.LastErrorKind, it.LastSMTPCode = errKind, smtpCode
		}
		it.FailReason, it.FailedAt = reason, now
		return t.putItem(bFailed, it)
	})
}

// --- admin ------------------------------------------------------------------

func (s *Store) list(bucket []byte) ([]*Item, error) {
	var out []*Item
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(_, v []byte) error {
			it, err := decodeItem(v)
			if err != nil {
				return err
			}
			out = append(out, it)
			return nil
		})
	})
	return out, err
}

func (s *Store) ListFailed() ([]*Item, error)      { return s.list(bFailed) }
func (s *Store) ListQuarantined() ([]*Item, error) { return s.list(bQuarantine) }

// RetryFailed moves a failed item back to pending with a fresh retry window
// and backoff. ID, Message-ID and ciphertext stay the same.
func (s *Store) RetryFailed(id string, now time.Time) error {
	return s.update(func(t *txn) error {
		it, err := t.getItem(bFailed, id)
		if err != nil {
			return err
		}
		if err := t.del(bFailed, []byte(id)); err != nil {
			return err
		}
		it.FailReason, it.FailedAt = "", time.Time{}
		it.Attempts = 0
		it.Deadline, it.NextAttempt = now.Add(RetryWindow), now
		if err := t.putItem(bPending, it); err != nil {
			return err
		}
		return t.put(bDue, dueKey(now, id), dueVal)
	})
}

// DeleteFailed removes a failed item for good.
func (s *Store) DeleteFailed(id string, now time.Time) error {
	return s.update(func(t *txn) error {
		it, err := t.getItem(bFailed, id)
		if err != nil {
			return err
		}
		if err := t.del(bFailed, []byte(id)); err != nil {
			return err
		}
		if err := t.del(bBlob, []byte(id)); err != nil {
			return err
		}
		return t.finishDedup(it, now)
	})
}

// DeleteQuarantined removes a quarantined item for good.
func (s *Store) DeleteQuarantined(id string) error {
	return s.update(func(t *txn) error {
		if _, err := t.getItem(bQuarantine, id); err != nil {
			return err
		}
		if err := t.del(bQuarantine, []byte(id)); err != nil {
			return err
		}
		return t.del(bBlob, []byte(id))
	})
}

// Quarantine moves, in one transaction, every pending and failed item that
// was encrypted to one of the given primary key fingerprints into the
// quarantine queue and deletes their de-duplication records so callers can
// resend with the same Idempotency-Key.
func (s *Store) Quarantine(fingerprints []string, now time.Time) (moved int, err error) {
	if len(fingerprints) == 0 {
		return 0, nil
	}
	want := map[string]bool{}
	for _, fp := range fingerprints {
		want[fp] = true
	}
	err = s.update(func(t *txn) error {
		moved = 0
		for _, bucket := range [][]byte{bPending, bFailed} {
			var hit []*Item
			if err := t.tx.Bucket(bucket).ForEach(func(_, v []byte) error {
				it, err := decodeItem(v)
				if err != nil {
					return err
				}
				if want[it.KeyFingerprint] {
					hit = append(hit, it)
				}
				return nil
			}); err != nil {
				return err
			}
			for _, it := range hit {
				if err := t.del(bucket, []byte(it.ID)); err != nil {
					return err
				}
				if err := t.del(bDue, dueKey(it.NextAttempt, it.ID)); err != nil {
					return err
				}
				if err := t.dropDedup(it); err != nil {
					return err
				}
				it.QuarantinedAt = now
				if err := t.putItem(bQuarantine, it); err != nil {
					return err
				}
				moved++
			}
		}
		return nil
	})
	return moved, err
}

// SweepResult counts what a Sweep removed.
type SweepResult struct {
	Failed, Quarantined, Dedup int
}

// Sweep deletes failed and quarantined items past their retention and
// expired de-duplication records.
func (s *Store) Sweep(now time.Time) (res SweepResult, err error) {
	err = s.update(func(t *txn) error {
		res = SweepResult{}
		sweepItems := func(bucket []byte, at func(*Item) time.Time, final bool) (int, error) {
			var old []*Item
			if err := t.tx.Bucket(bucket).ForEach(func(_, v []byte) error {
				it, err := decodeItem(v)
				if err != nil {
					return err
				}
				if !now.Before(at(it).Add(Retention)) {
					old = append(old, it)
				}
				return nil
			}); err != nil {
				return 0, err
			}
			for _, it := range old {
				if err := t.del(bucket, []byte(it.ID)); err != nil {
					return 0, err
				}
				if err := t.del(bBlob, []byte(it.ID)); err != nil {
					return 0, err
				}
				if final {
					if err := t.finishDedup(it, now); err != nil {
						return 0, err
					}
				}
			}
			return len(old), nil
		}
		var err error
		if res.Failed, err = sweepItems(bFailed, func(it *Item) time.Time { return it.FailedAt }, true); err != nil {
			return err
		}
		if res.Quarantined, err = sweepItems(bQuarantine, func(it *Item) time.Time { return it.QuarantinedAt }, false); err != nil {
			return err
		}
		for _, bucket := range [][]byte{bIdem, bGrafana, bReplay} {
			var dead [][]byte
			if err := t.tx.Bucket(bucket).ForEach(func(k, v []byte) error {
				if len(v) < 8 {
					dead = append(dead, bytes.Clone(k))
				} else if exp := int64(binary.BigEndian.Uint64(v)); exp != 0 && exp <= now.UnixNano() {
					dead = append(dead, bytes.Clone(k))
				}
				return nil
			}); err != nil {
				return err
			}
			for _, k := range dead {
				if err := t.del(bucket, k); err != nil {
					return err
				}
			}
			res.Dedup += len(dead)
		}
		return nil
	})
	return res, err
}

// --- observability ----------------------------------------------------------

func (s *Store) Stats() (Stats, error) {
	var st Stats
	err := s.db.View(func(tx *bolt.Tx) error {
		st.Bytes = getInt(tx, kBytes)
		st.Pending = int(getInt(tx, countKey(bPending)))
		st.Failed = int(getInt(tx, countKey(bFailed)))
		st.Quarantined = int(getInt(tx, countKey(bQuarantine)))
		return nil
	})
	return st, err
}

// ProbeWrite commits a tiny write to prove the queue is writable.
func (s *Store) ProbeWrite(now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putInt(tx, kHealth, now.Unix())
	})
}
