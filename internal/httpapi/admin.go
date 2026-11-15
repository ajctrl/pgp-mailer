package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"time"

	"pgp-mailer/internal/store"
)

var idRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// admin wraps a handler with ADMIN_TOKEN bearer authentication.
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearerToken(r)
		sum := sha256.Sum256([]byte(tok))
		if !ok || subtle.ConstantTimeCompare(sum[:], s.cfg.AdminTokenHash[:]) != 1 {
			s.log.Warn("admin request rejected", "result", ErrTypeUnauthorized)
			writeError(w, http.StatusUnauthorized, ErrTypeUnauthorized, "missing or invalid bearer token")
			return
		}
		next(w, r)
	}
}

// FailedEntry is one row of the failed-queue listing. It carries no
// content, only identifiers, the failure reason and timestamps.
type FailedEntry struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	Level      string    `json:"level"`
	Reason     string    `json:"reason"`
	AcceptedAt time.Time `json:"accepted_at"`
	FailedAt   time.Time `json:"failed_at"`
	DeleteAt   time.Time `json:"delete_at"`
}

// QuarantineEntry is one row of the quarantine listing.
type QuarantineEntry struct {
	ID             string    `json:"id"`
	Source         string    `json:"source"`
	Level          string    `json:"level"`
	KeyFingerprint string    `json:"key_fingerprint"`
	AcceptedAt     time.Time `json:"accepted_at"`
	QuarantinedAt  time.Time `json:"quarantined_at"`
	DeleteAt       time.Time `json:"delete_at"`
}

// failureReason renders e.g. "permanent (smtp 550)" or "expired (timeout)".
func failureReason(it *store.Item) string {
	r := it.FailReason
	switch {
	case it.LastSMTPCode != 0:
		r += " (smtp " + strconv.Itoa(it.LastSMTPCode) + ")"
	case it.LastErrorKind != "":
		r += " (" + it.LastErrorKind + ")"
	}
	return r
}

func (s *Server) handleListFailed(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListFailed()
	if err != nil {
		s.adminStoreError(w, err)
		return
	}
	out := make([]FailedEntry, 0, len(items))
	for _, it := range items {
		out = append(out, FailedEntry{
			ID: it.ID, Source: it.Source, Level: it.Level, Reason: failureReason(it),
			AcceptedAt: it.AcceptedAt.UTC(), FailedAt: it.FailedAt.UTC(),
			DeleteAt: it.FailedAt.Add(store.Retention).UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FailedAt.Before(out[j].FailedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleListQuarantine(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListQuarantined()
	if err != nil {
		s.adminStoreError(w, err)
		return
	}
	out := make([]QuarantineEntry, 0, len(items))
	for _, it := range items {
		out = append(out, QuarantineEntry{
			ID: it.ID, Source: it.Source, Level: it.Level, KeyFingerprint: it.KeyFingerprint,
			AcceptedAt: it.AcceptedAt.UTC(), QuarantinedAt: it.QuarantinedAt.UTC(),
			DeleteAt: it.QuarantinedAt.Add(store.Retention).UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QuarantinedAt.Before(out[j].QuarantinedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) adminStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, ErrTypeNotFound, "no such item in this queue")
		return
	}
	s.log.Error("admin operation failed", "result", "store_error", "error", err.Error())
	writeError(w, http.StatusInternalServerError, ErrTypeInternal, "queue operation failed")
}

// adminItem runs op on the item named in the path and reports the outcome.
func (s *Server) adminItem(w http.ResponseWriter, r *http.Request, result string, op func(id string) error) {
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		writeError(w, http.StatusNotFound, ErrTypeNotFound, "no such item in this queue")
		return
	}
	if err := op(id); err != nil {
		s.adminStoreError(w, err)
		return
	}
	s.log.Info("admin operation", "id", id, "result", result)
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "result": result})
}

func (s *Server) handleRetryFailed(w http.ResponseWriter, r *http.Request) {
	s.adminItem(w, r, "retry_scheduled", func(id string) error {
		if err := s.store.RetryFailed(id, s.now()); err != nil {
			return err
		}
		if s.wake != nil {
			s.wake()
		}
		return nil
	})
}

func (s *Server) handleDeleteFailed(w http.ResponseWriter, r *http.Request) {
	s.adminItem(w, r, "deleted", func(id string) error { return s.store.DeleteFailed(id, s.now()) })
}

func (s *Server) handleDeleteQuarantine(w http.ResponseWriter, r *http.Request) {
	s.adminItem(w, r, "deleted", func(id string) error { return s.store.DeleteQuarantined(id) })
}
