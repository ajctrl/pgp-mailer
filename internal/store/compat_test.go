package store

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Frozen using bbolt v1.4.3 and the pre-update queue format. The blob is
// deliberately opaque test data; cryptographic compatibility is tested in
// mailmsg. Do not regenerate with the version being evaluated by an update PR.
func TestReadQueueWrittenByBboltV143(t *testing.T) {
	f, err := os.Open("testdata/queue-bbolt-v1.4.3.db.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	data, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, DefaultLimit)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	items, err := s.Due(at, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("legacy queue: items=%v err=%v", items, err)
	}
	it := items[0]
	if it.ID != id(1) || it.Source != "legacy" || it.Receiver != "ops" || !it.Deadline.Equal(at.Add(time.Hour)) {
		t.Fatalf("legacy metadata changed: %+v", it)
	}
	mail, err := s.Mail(it.ID)
	if err != nil || !bytes.Equal(mail, []byte("opaque legacy mail fixture")) {
		t.Fatalf("legacy mail changed: %q (%v)", mail, err)
	}
	gotID, hash, found, err := s.LookupIdem("legacy", "legacy-key", at)
	if err != nil || !found || gotID != it.ID || hash != sha256.Sum256([]byte("legacy content")) {
		t.Fatalf("legacy dedup: id=%s found=%v err=%v", gotID, found, err)
	}
	// Ensure the old database can be updated, not just read.
	if err := s.MarkDelivered(it.ID, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	items, err = s.Due(at.Add(time.Minute), 10)
	if err != nil || len(items) != 0 {
		t.Fatalf("legacy item remains queued: %v (%v)", items, err)
	}
	gotID, _, found, err = s.LookupIdem("legacy", "legacy-key", at.Add(2*time.Minute))
	if err != nil || !found || gotID != it.ID {
		t.Fatal("delivery lost legacy idempotency record")
	}
	recount(t, s)
}
