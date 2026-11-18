package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"pgp-mailer/internal/config"
	"pgp-mailer/internal/store"
)

// Template expansion is bounded independently of the incoming request size.
type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxBodyBytes {
		return 0, errors.New("template output too large")
	}
	return b.Buffer.Write(p)
}

func (b *boundedBuffer) WriteString(s string) (int, error) { return b.Write([]byte(s)) }

func convertInput(input config.Input, body []byte) (*Message, *parseError) {
	if input.Validation == "message" {
		return ParseMessage(body)
	}
	if !utf8.Valid(body) {
		return nil, badRequest("body is not valid UTF-8")
	}
	var data any = string(body)
	if input.Format == "json" {
		d := json.NewDecoder(bytes.NewReader(body))
		d.UseNumber()
		if d.Decode(&data) != nil {
			return nil, badRequest("body is not valid JSON")
		}
		if d.Decode(new(any)) != io.EOF {
			return nil, badRequest("unexpected data after JSON")
		}
	}
	if len(input.RequireAny) > 0 {
		fields, ok := data.(map[string]any)
		if !ok {
			return nil, badRequest("expected a JSON object")
		}
		found := false
		for _, key := range input.RequireAny {
			v := fields[key]
			if v != nil {
				if s, ok := v.(string); !ok || strings.TrimSpace(s) != "" {
					found = true
				}
			}
		}
		if !found {
			return nil, badRequest("required content is missing")
		}
	}
	values := [3]string{}
	for i, t := range input.Templates {
		if t == nil {
			continue
		}
		var out boundedBuffer
		if t.Execute(&out, data) != nil {
			return nil, invalid("could not render message template")
		}
		values[i] = out.String()
	}
	if input.Title == "" {
		values[0] = input.Source
	}
	if input.Body == "" {
		values[1] = string(body)
	}
	if input.Level == "" {
		values[2] = "info"
	}
	title := strings.TrimSpace(truncateRunes(strings.Map(func(r rune) rune {
		if isLineBreakOrControl(r) {
			return ' '
		}
		return r
	}, values[0]), MaxTitleRunes))
	if title == "" {
		title = input.Source
	}
	msg := values[1]
	if len(msg) > MaxMessageBytes {
		msg = truncateBytes(msg, MaxMessageBytes-len(truncationNote)) + truncationNote
	}
	if strings.TrimSpace(msg) == "" {
		return nil, invalid("message must not be blank")
	}
	if !levels[values[2]] {
		return nil, invalid("template produced an invalid level")
	}
	return &Message{Receiver: ReceiverOps, Title: title, Message: msg, Level: values[2]}, nil
}

func (s *Server) inputHandler(input config.Input) http.HandlerFunc {
	// Shared scopes are serialized across routes during lookup and acceptance.

	return func(w http.ResponseWriter, r *http.Request) {
		source := input.Source
		if input.Auth == "bearer" {
			caller, ok := s.caller(r)
			if !ok || input.Caller != "" && input.Caller != caller {
				s.reject(w, SourceUnauthenticated, 401, ErrTypeUnauthorized, "missing or invalid bearer token")
				return
			}
			source = caller
		}
		body, tooLarge, err := readBody(w, r)
		if tooLarge {
			s.reject(w, source, 413, ErrTypeTooLarge, "request body exceeds 256 KiB")
			return
		}
		if err != nil {
			s.reject(w, source, 400, ErrTypeBadRequest, "could not read request body")
			return
		}
		scope := source + "\x00" + input.Path
		// An explicit namespace supports stable deduplication across path changes.
		// Empty namespaces retain the historical caller-only storage keys.
		if input.DedupNamespace != nil {
			scope = source
			if *input.DedupNamespace != "" {
				scope += "\x00" + *input.DedupNamespace
			}
		}
		var replay *store.Replay
		if input.Auth == "hmac-sha256" {
			if err := verifySignature(input.Secret, r.Header, body, s.now(), input.SignatureHeader, input.TimestampHeader); err != nil {
				s.log.Warn("request rejected", "source", source, "reason", err.Error())
				s.reject(w, source, 401, ErrTypeUnauthorized, "unauthorized")
				return
			}
			sig, _ := hex.DecodeString(r.Header.Get(input.SignatureHeader))
			sec, _ := strconv.ParseInt(r.Header.Get(input.TimestampHeader), 10, 64)
			replay = &store.Replay{Key: store.ReplayKey(scope, sig), Expires: time.Unix(sec, 0).Add(signatureMaxSkew + time.Second)}
		}
		if typ, msg, closed := s.unavailable(); closed {
			s.reject(w, source, 503, typ, msg)
			return
		}
		key := ""
		if input.Dedup == "idempotency-key" {
			keys := r.Header.Values("Idempotency-Key")
			if len(keys) != 1 || !validIdempotencyKey(keys[0]) {
				s.reject(w, source, 400, ErrTypeBadKey, "exactly one Idempotency-Key header of 1 to 128 printable ASCII characters is required")
				return
			}
			key = keys[0]
		}
		if input.Dedup == "idempotency-key" {
			flightKey := scope + "\x00" + key
			s.inflightMu.Lock()
			if _, busy := s.inflight[flightKey]; busy {
				s.inflightMu.Unlock()
				s.reject(w, source, 409, ErrTypeInProgress, "an earlier request with this Idempotency-Key is still being processed; retry later with the same key")
				return
			}
			s.inflight[flightKey] = struct{}{}
			s.inflightMu.Unlock()
			defer func() { s.inflightMu.Lock(); delete(s.inflight, flightKey); s.inflightMu.Unlock() }()
		}
		m, perr := convertInput(input, body)
		if perr != nil {
			s.reject(w, source, perr.status, perr.typ, perr.msg)
			return
		}
		hash := m.ContentHash()
		unlock := s.lockScope(scope)
		defer unlock()
		var id string
		var found bool
		var oldHash [32]byte
		kind := store.DedupIdem
		var dedupKey []byte
		switch input.Dedup {
		case "idempotency-key":
			dedupKey = store.IdemKey(scope, key)
			id, oldHash, found, err = s.store.LookupIdem(scope, key, s.now())
			if err == nil && found && oldHash != hash {
				s.reject(w, source, 409, ErrTypeConflict, "this Idempotency-Key was already used with different content")
				return
			}
		case "body":
			kind = store.DedupGrafana
			bodyHash := sha256.Sum256(body)
			dedupKey = store.GrafanaKey(scope, bodyHash)
			id, found, err = s.store.LookupGrafana(scope, bodyHash, s.now())
		case "none":
			// A random internal key reuses queue retention without suppressing requests.
			key, err = newID()
			dedupKey = store.IdemKey(scope, key)
		}
		result := "duplicate"
		if err == nil && !found && replay != nil {
			result = "replay"
			id, found, err = s.store.LookupReplay(replay.Key, s.now())
		}
		if err != nil {
			s.reject(w, source, 500, ErrTypeInternal, "could not read de-duplication state")
			return
		}
		if found {
			s.log.Info("duplicate suppressed", "id", id, "source", source, "result", result)
			writeJSON(w, 202, acceptedBody{ID: id})
			return
		}
		var subject boundedBuffer
		renderErr := input.WriteProtectedSubject(&subject, m.Level, m.Title)
		protectedSubject := subject.String()
		if renderErr != nil || strings.TrimSpace(protectedSubject) == "" || !utf8.ValidString(protectedSubject) || strings.IndexFunc(protectedSubject, isLineBreakOrControl) >= 0 {
			protectedSubject = config.DefaultProtectedSubject(m.Level, m.Title)
			s.log.Warn("using default protected subject", "source", source)
		}
		id, err = s.accept(source, input.PublicSubject, protectedSubject, m, kind, dedupKey, hash, replay)
		if err != nil {
			s.rejectAcceptError(w, source, err)
			return
		}
		writeJSON(w, 202, acceptedBody{ID: id})
	}
}

// References include waiting requests so locks are removed only after the
// last holder/waiter leaves, without retaining caller-controlled keys.
type intakeScope struct {
	mu   sync.Mutex
	refs int
}

func (s *Server) lockScope(scope string) func() {
	s.scopeMu.Lock()
	if s.scopes == nil {
		s.scopes = make(map[string]*intakeScope)
	}
	lock := s.scopes[scope]
	if lock == nil {
		lock = &intakeScope{}
		s.scopes[scope] = lock
	}
	lock.refs++
	s.scopeMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.scopeMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(s.scopes, scope)
		}
		s.scopeMu.Unlock()
	}
}
