// Package httpapi implements the HTTP surface: the generic intake, the
// Grafana webhook adapter, the admin API, /healthz and /metrics.
package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pgp-mailer/internal/config"
	"pgp-mailer/internal/mailmsg"
	"pgp-mailer/internal/metrics"
	"pgp-mailer/internal/pgpkey"
	"pgp-mailer/internal/store"
)

const (
	// MaxBodyBytes is the largest accepted request body.
	MaxBodyBytes = 256 << 10
	// MaxMessageBytes is the largest accepted message field.
	MaxMessageBytes = 64 << 10
	// MaxTitleRunes is the largest accepted title, in code points.
	MaxTitleRunes = 200

	// SourceUnauthenticated labels rejections of callers that could not be
	// identified. The leading underscore keeps it apart from caller names.
	SourceUnauthenticated = "_unauthenticated"

	healthCacheTTL = 10 * time.Second
)

// Error types returned in the "error" field of failure responses.
const (
	ErrTypeUnauthorized  = "unauthorized"
	ErrTypeBadRequest    = "invalid_request"
	ErrTypeBadKey        = "invalid_idempotency_key"
	ErrTypeTooLarge      = "payload_too_large"
	ErrTypeValidation    = "validation_failed"
	ErrTypeConflict      = "idempotency_conflict"
	ErrTypeInProgress    = "idempotency_in_progress"
	ErrTypeQueueFull     = "queue_full"
	ErrTypeKeyExpired    = "key_expired"
	ErrTypeShuttingDown  = "shutting_down"
	ErrTypeInternal      = "internal_error"
	ErrTypeNotFound      = "not_found"
	ErrTypeEncryptFailed = "encryption_failed"
)

type Server struct {
	cfg     *config.Config
	key     *pgpkey.Key
	store   *store.Store
	builder *mailmsg.Builder
	metrics *metrics.Metrics
	log     *slog.Logger
	now     func() time.Time
	wake    func()

	draining atomic.Bool

	scopeMu    sync.Mutex
	scopes     map[string]*intakeScope
	inflightMu sync.Mutex
	inflight   map[string]struct{}

	healthMu   sync.Mutex
	healthAt   time.Time
	healthGood bool
}

type Options struct {
	Config  *config.Config
	Key     *pgpkey.Key
	Store   *store.Store
	Metrics *metrics.Metrics
	Log     *slog.Logger
	Now     func() time.Time
	// Wake is called after an item becomes deliverable.
	Wake func()
}

func New(o Options) *Server {
	return &Server{
		cfg:   o.Config,
		key:   o.Key,
		store: o.Store,
		builder: &mailmsg.Builder{
			From:    o.Config.MailFrom,
			To:      o.Config.ReceiverOps,
			Encrypt: o.Key.Encrypt,
		},
		metrics:  o.Metrics,
		log:      o.Log,
		now:      o.Now,
		wake:     o.Wake,
		inflight: map[string]struct{}{},
	}
}

// Drain makes the intake endpoints refuse new work (used on shutdown).
func (s *Server) Drain() { s.draining.Store(true) }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	inputs := s.cfg.Inputs
	if inputs == nil {
		inputs = config.DefaultInputs()
		inputs[1].Secret = s.cfg.GrafanaHMACSecret
	}
	for _, input := range inputs {
		mux.HandleFunc("POST "+input.Path, s.inputHandler(input))
	}
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /admin/v1/failed", s.admin(s.handleListFailed))
	mux.HandleFunc("POST /admin/v1/failed/{id}/retry", s.admin(s.handleRetryFailed))
	mux.HandleFunc("DELETE /admin/v1/failed/{id}", s.admin(s.handleDeleteFailed))
	mux.HandleFunc("GET /admin/v1/quarantine", s.admin(s.handleListQuarantine))
	mux.HandleFunc("DELETE /admin/v1/quarantine/{id}", s.admin(s.handleDeleteQuarantine))
	return mux
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, typ, msg string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	writeJSON(w, status, errorBody{Error: typ, Message: msg})
}

// reject answers an intake request with an error and records it.
func (s *Server) reject(w http.ResponseWriter, source string, status int, typ, msg string) {
	s.metrics.Rejected(source, status)
	s.log.Warn("request rejected", "source", source, "result", typ, "status", status)
	writeError(w, status, typ, msg)
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}

// caller identifies the API caller by bearer token. Every configured token
// is compared, each in constant time, so timing reveals nothing about which
// one (if any) matched.
func (s *Server) caller(r *http.Request) (string, bool) {
	tok, ok := bearerToken(r)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256([]byte(tok))
	name, found := "", 0
	for _, t := range s.cfg.APITokens {
		if subtle.ConstantTimeCompare(sum[:], t.Hash[:]) == 1 {
			name, found = t.Name, 1
		}
	}
	return name, found == 1
}

// readBody reads at most MaxBodyBytes. tooLarge is true when the body
// exceeds the limit.
func readBody(w http.ResponseWriter, r *http.Request) (body []byte, tooLarge bool, err error) {
	if r.ContentLength > MaxBodyBytes {
		return nil, true, nil
	}
	body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return body, false, nil
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// unavailable reports why intake is currently closed, if it is.
func (s *Server) unavailable() (typ, msg string, closed bool) {
	if s.draining.Load() {
		return ErrTypeShuttingDown, "service is shutting down", true
	}
	if !s.key.Valid(s.now()) {
		return ErrTypeKeyExpired, "recipient key has expired; new notifications are not accepted", true
	}
	return "", "", false
}

type acceptedBody struct {
	ID string `json:"id"`
}

var (
	errQueueFull = errors.New("queue full")
	errEncrypt   = errors.New("encryption failed")
)

// accept encrypts the notification and persists mail, queue entry and
// de-duplication record in one transaction. It returns only after the
// commit; nothing is ever stored or sent in plaintext.
func (s *Server) accept(source, publicSubject, protectedSubject string, m *Message, dedupKind string, dedupKey []byte, contentHash [32]byte, replay *store.Replay) (string, error) {
	now := s.now()
	id, err := newID()
	if err != nil {
		return "", err
	}
	built, err := s.builder.Build(mailmsg.Input{
		PublicSubject: publicSubject, ProtectedSubject: protectedSubject,
		ID: id, Source: source, Message: m.Message, Level: m.Level, Now: now,
	})
	if err != nil {
		if errors.Is(err, pgpkey.ErrExpired) {
			return "", pgpkey.ErrExpired
		}
		s.log.Error("encryption failed", "source", source, "result", "encryption_failed", "error", err.Error())
		return "", errEncrypt
	}
	it := &store.Item{
		ID:             id,
		Source:         source,
		Receiver:       m.Receiver,
		Level:          m.Level,
		AcceptedAt:     now,
		KeyFingerprint: s.key.Fingerprint(),
		EncSubkeyID:    built.SubkeyID,
		EnvelopeFrom:   s.cfg.MailFrom.Address,
		EnvelopeTo:     s.cfg.ReceiverOps.Address,
		MessageID:      built.MessageID,
		Deadline:       now.Add(store.RetryWindow),
		NextAttempt:    now,
		DedupKind:      dedupKind,
		DedupKey:       dedupKey,
	}
	if replay != nil && !replay.Expires.After(now) {
		replay = nil // the signature is no longer accepted; nothing to guard
	}
	if err := s.store.EnqueueSigned(it, built.Raw, contentHash, replay, now); err != nil {
		if errors.Is(err, store.ErrFull) {
			return "", errQueueFull
		}
		s.log.Error("queue write failed", "source", source, "result", "persist_failed", "error", err.Error())
		return "", err
	}
	s.metrics.Accepted(source)
	s.log.Info("accepted", "id", id, "source", source, "receiver", m.Receiver, "level", m.Level, "result", "accepted")
	if s.wake != nil {
		s.wake()
	}
	return id, nil
}

// rejectAcceptError maps an accept error to its HTTP response.
func (s *Server) rejectAcceptError(w http.ResponseWriter, source string, err error) {
	switch {
	case errors.Is(err, errQueueFull):
		s.reject(w, source, http.StatusServiceUnavailable, ErrTypeQueueFull, "queue storage limit reached")
	case errors.Is(err, pgpkey.ErrExpired):
		s.reject(w, source, http.StatusServiceUnavailable, ErrTypeKeyExpired, "recipient key has expired; new notifications are not accepted")
	case errors.Is(err, errEncrypt):
		s.reject(w, source, http.StatusInternalServerError, ErrTypeEncryptFailed, "encryption failed; nothing was sent")
	default:
		s.reject(w, source, http.StatusInternalServerError, ErrTypeInternal, "could not persist the notification")
	}
}

// --- health and metrics -----------------------------------------------------

func (s *Server) queueWritable(now time.Time) bool {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if !s.healthAt.IsZero() && now.Sub(s.healthAt) < healthCacheTTL && now.Sub(s.healthAt) >= 0 {
		return s.healthGood
	}
	err := s.store.ProbeWrite(now)
	if err != nil {
		s.log.Error("queue write probe failed", "error", err.Error())
	}
	s.healthAt, s.healthGood = now, err == nil
	return s.healthGood
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	keyOK := s.key.Valid(now)
	queueOK := s.queueWritable(now)
	status, text := http.StatusOK, "ok"
	if !keyOK || !queueOK {
		status, text = http.StatusServiceUnavailable, "unhealthy"
	}
	writeJSON(w, status, map[string]any{"status": text, "key_valid": keyOK, "queue_writable": queueOK})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	st, err := s.store.Stats()
	if err != nil {
		http.Error(w, "stats unavailable", http.StatusInternalServerError)
		return
	}
	g := metrics.Gauges{
		Pending: st.Pending, Failed: st.Failed, Quarantined: st.Quarantined,
		StorageBytes: st.Bytes, StorageLimit: s.store.Limit(),
		KeyValid: s.key.Valid(now),
	}
	if t, ok := s.key.Expiry(now); ok {
		g.KeyExpiry = t.Unix()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.Write(w, g)
}
