package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"pgp-mailer/internal/store"
)

// ReceiverOps is the only receiver of the initial version.
const ReceiverOps = "ops"

var levels = map[string]bool{
	"trace": true, "debug": true, "info": true, "warn": true,
	"error": true, "fatal": true, "unknown": true,
}

// Message is a notification in the common format, after validation and
// defaulting.
type Message struct {
	Receiver string
	Title    string
	Message  string
	Level    string
}

// ContentHash is the SHA-256 over the length-prefixed fields. It is what
// "same content" means for an Idempotency-Key; JSON key order and
// whitespace do not influence it.
func (m *Message) ContentHash() [32]byte {
	h := sha256.New()
	for _, f := range []string{m.Receiver, m.Title, m.Message, m.Level} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

type parseError struct {
	status int
	typ    string
	msg    string
}

func (e *parseError) Error() string { return e.msg }

func badRequest(msg string) *parseError {
	return &parseError{http.StatusBadRequest, ErrTypeBadRequest, msg}
}

func invalid(msg string) *parseError {
	return &parseError{http.StatusUnprocessableEntity, ErrTypeValidation, msg}
}

// isLineBreakOrControl reports characters that must not appear in a title.
func isLineBreakOrControl(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

// ParseMessage decodes and validates a common-format request body.
func ParseMessage(body []byte) (*Message, *parseError) {
	if !utf8.Valid(body) {
		return nil, badRequest("body is not valid UTF-8")
	}
	// The keys are matched here, exactly and case-sensitively, rather than
	// by encoding/json, whose struct matching ignores case and reports
	// unknown fields only through the text of an error.
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&fields); err != nil {
		return nil, badRequest("body is not a valid JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, badRequest("unexpected data after the JSON object")
	}
	var raw struct{ Receiver, Title, Message, Level *string }
	known := map[string]**string{
		"receiver": &raw.Receiver, "title": &raw.Title, "message": &raw.Message, "level": &raw.Level,
	}
	for name := range fields {
		if known[name] == nil {
			return nil, invalid("unknown field in request; only receiver, title, message and level are accepted")
		}
	}
	for _, name := range []string{"receiver", "title", "message", "level"} {
		v, present := fields[name]
		if !present {
			continue
		}
		// null leaves the pointer nil, i.e. the field counts as absent.
		if err := json.Unmarshal(v, known[name]); err != nil {
			return nil, invalid("field " + name + " must be a string")
		}
	}

	m := &Message{Level: "info"}
	switch {
	case raw.Receiver == nil:
		return nil, invalid("receiver is required")
	case *raw.Receiver != ReceiverOps:
		return nil, invalid(`receiver must be "ops"`)
	}
	m.Receiver = *raw.Receiver

	if raw.Title == nil {
		return nil, invalid("title is required")
	}
	m.Title = *raw.Title
	switch n := utf8.RuneCountInString(m.Title); {
	case n < 1 || n > MaxTitleRunes:
		return nil, invalid("title must be 1 to 200 characters")
	case strings.TrimSpace(m.Title) == "":
		return nil, invalid("title must not be blank")
	case strings.IndexFunc(m.Title, isLineBreakOrControl) >= 0:
		return nil, invalid("title must not contain line breaks or control characters")
	}

	if raw.Message == nil {
		return nil, invalid("message is required")
	}
	m.Message = *raw.Message
	switch {
	case len(m.Message) > MaxMessageBytes:
		return nil, invalid("message must be at most 64 KiB")
	case strings.TrimSpace(m.Message) == "":
		return nil, invalid("message must not be blank")
	}

	if raw.Level != nil {
		if !levels[*raw.Level] {
			return nil, invalid("level must be one of trace, debug, info, warn, error, fatal, unknown")
		}
		m.Level = *raw.Level
	}
	return m, nil
}

// validIdempotencyKey accepts 1 to 128 printable ASCII characters.
func validIdempotencyKey(k string) bool {
	if len(k) < 1 || len(k) > 128 {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request) {
	source, ok := s.caller(r)
	if !ok {
		s.reject(w, SourceUnauthenticated, http.StatusUnauthorized, ErrTypeUnauthorized, "missing or invalid bearer token")
		return
	}
	if typ, msg, closed := s.unavailable(); closed {
		s.reject(w, source, http.StatusServiceUnavailable, typ, msg)
		return
	}

	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !validIdempotencyKey(keys[0]) {
		s.reject(w, source, http.StatusBadRequest, ErrTypeBadKey,
			"exactly one Idempotency-Key header of 1 to 128 printable ASCII characters is required")
		return
	}
	idemKey := keys[0]

	body, tooLarge, err := readBody(w, r)
	switch {
	case tooLarge:
		s.reject(w, source, http.StatusRequestEntityTooLarge, ErrTypeTooLarge, "request body exceeds 256 KiB")
		return
	case err != nil:
		s.reject(w, source, http.StatusBadRequest, ErrTypeBadRequest, "could not read request body")
		return
	}
	m, perr := ParseMessage(body)
	if perr != nil {
		s.reject(w, source, perr.status, perr.typ, perr.msg)
		return
	}
	hash := m.ContentHash()

	// The in-flight marker covers the window between the lookup and the
	// commit, so two concurrent requests with one key cannot both enqueue.
	flightKey := source + "\x00" + idemKey
	s.inflightMu.Lock()
	if _, busy := s.inflight[flightKey]; busy {
		s.inflightMu.Unlock()
		s.reject(w, source, http.StatusConflict, ErrTypeInProgress,
			"an earlier request with this Idempotency-Key is still being processed; retry later with the same key")
		return
	}
	s.inflight[flightKey] = struct{}{}
	s.inflightMu.Unlock()
	defer func() {
		s.inflightMu.Lock()
		delete(s.inflight, flightKey)
		s.inflightMu.Unlock()
	}()

	prevID, prevHash, found, err := s.store.LookupIdem(source, idemKey, s.now())
	if err != nil {
		s.log.Error("queue read failed", "source", source, "result", "lookup_failed", "error", err.Error())
		s.reject(w, source, http.StatusInternalServerError, ErrTypeInternal, "could not read de-duplication state")
		return
	}
	if found {
		if prevHash != hash {
			s.reject(w, source, http.StatusConflict, ErrTypeConflict,
				"this Idempotency-Key was already used with different content")
			return
		}
		s.log.Info("duplicate suppressed", "id", prevID, "source", source, "receiver", m.Receiver, "level", m.Level, "result", "duplicate")
		writeJSON(w, http.StatusAccepted, acceptedBody{ID: prevID})
		return
	}

	id, err := s.accept(source, m, store.DedupIdem, store.IdemKey(source, idemKey), hash, nil)
	if err != nil {
		s.rejectAcceptError(w, source, err)
		return
	}
	writeJSON(w, http.StatusAccepted, acceptedBody{ID: id})
}
