package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"pgp-mailer/internal/config"
	"pgp-mailer/internal/store"
)

const (
	GrafanaSignatureHeader = "X-Grafana-Alerting-Signature"
	GrafanaTimestampHeader = "X-Grafana-Alerting-Timestamp"

	grafanaMaxSkew = 5 * time.Minute

	truncationNote = "\n\n[pgp-mailer] 本文が 64 KiB を超えたため、末尾を切り詰めました。"
	fallbackTitle  = "Grafana alert"
	fallbackBody   = "(Grafana の Webhook に message がありませんでした)"
)

// VerifyGrafanaSignature checks the timestamped HMAC-SHA256 that Grafana's
// webhook contact point adds: hex(HMAC(secret, timestamp + ":" + body)).
// The returned error says why verification failed; it is for logs only.
func VerifyGrafanaSignature(secret []byte, h http.Header, body []byte, now time.Time) error {
	sigs, tss := h.Values(GrafanaSignatureHeader), h.Values(GrafanaTimestampHeader)
	if len(sigs) != 1 || sigs[0] == "" {
		return errors.New("signature_missing")
	}
	if len(tss) != 1 || tss[0] == "" {
		return errors.New("timestamp_missing")
	}
	ts := tss[0]
	if len(ts) > 12 {
		return errors.New("timestamp_malformed")
	}
	for i := 0; i < len(ts); i++ {
		if ts[i] < '0' || ts[i] > '9' {
			return errors.New("timestamp_malformed")
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("timestamp_malformed")
	}
	got, err := hex.DecodeString(sigs[0])
	if err != nil || len(got) != sha256.Size {
		return errors.New("signature_malformed")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts))
	mac.Write([]byte(":"))
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("signature_mismatch")
	}
	// Checked after the MAC so that an unauthenticated sender learns
	// nothing about the server clock.
	if d := now.Sub(time.Unix(sec, 0)); d > grafanaMaxSkew || d < -grafanaMaxSkew {
		return errors.New("timestamp_out_of_range")
	}
	return nil
}

// truncateRunes cuts s to at most n code points.
func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// truncateBytes cuts s to at most n bytes without splitting a code point.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// looseString returns a JSON string's value, "" for a missing or null
// field, and the JSON text itself for any other type.
func looseString(raw json.RawMessage) string {
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil {
		return string(raw)
	}
	if s == nil {
		return ""
	}
	return *s
}

// ConvertGrafana maps a Grafana webhook body to the common format. An alert
// is never dropped for cosmetic reasons: over-long fields are truncated and
// empty ones replaced. Only a body without status, title and message is
// refused.
func ConvertGrafana(body []byte) (*Message, *parseError) {
	if !utf8.Valid(body) {
		return nil, badRequest("body is not valid UTF-8")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, badRequest("body is not a valid Grafana webhook JSON object")
	}
	// A field of an unexpected type (a custom payload can produce one) is
	// carried as its JSON text rather than costing the alert.
	hook := struct{ Status, Title, Message string }{
		looseString(fields["status"]), looseString(fields["title"]), looseString(fields["message"]),
	}

	// Every Grafana webhook carries a status. A body with none of the three
	// fields is some other payload (or null, or {}) and would only produce
	// a mail without content.
	if hook.Status == "" && strings.TrimSpace(hook.Title) == "" && strings.TrimSpace(hook.Message) == "" {
		return nil, badRequest("body is not a Grafana webhook: status, title and message are all missing")
	}

	m := &Message{Receiver: ReceiverOps}
	switch hook.Status {
	case "firing":
		m.Level = "error"
	case "resolved":
		m.Level = "info"
	default:
		m.Level = "unknown"
	}

	title := strings.Map(func(r rune) rune {
		if isLineBreakOrControl(r) {
			return ' '
		}
		return r
	}, hook.Title)
	title = strings.TrimSpace(truncateRunes(title, MaxTitleRunes))
	if title == "" {
		title = fallbackTitle
		if hook.Status != "" {
			title += " (" + truncateRunes(strings.Map(func(r rune) rune {
				if isLineBreakOrControl(r) {
					return ' '
				}
				return r
			}, hook.Status), 32) + ")"
		}
	}
	m.Title = title

	msg := hook.Message
	if strings.TrimSpace(msg) == "" {
		msg = fallbackBody
	}
	if len(msg) > MaxMessageBytes {
		msg = truncateBytes(msg, MaxMessageBytes-len(truncationNote)) + truncationNote
	}
	m.Message = msg
	return m, nil
}

func (s *Server) handleGrafana(w http.ResponseWriter, r *http.Request) {
	const source = config.ReservedSource

	body, tooLarge, err := readBody(w, r)
	switch {
	case tooLarge:
		s.reject(w, source, http.StatusRequestEntityTooLarge, ErrTypeTooLarge, "request body exceeds 256 KiB")
		return
	case err != nil:
		s.reject(w, source, http.StatusBadRequest, ErrTypeBadRequest, "could not read request body")
		return
	}
	// The signature is verified over the raw bytes before anything is parsed.
	if err := VerifyGrafanaSignature(s.cfg.GrafanaHMACSecret, r.Header, body, s.now()); err != nil {
		s.metrics.Rejected(source, http.StatusUnauthorized)
		s.log.Warn("request rejected", "source", source, "result", ErrTypeUnauthorized, "status", http.StatusUnauthorized, "reason", err.Error())
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: ErrTypeUnauthorized, Message: "unauthorized"})
		return
	}
	if typ, msg, closed := s.unavailable(); closed {
		s.reject(w, source, http.StatusServiceUnavailable, typ, msg)
		return
	}

	// Grafana intake is serialised: a concurrent identical delivery then
	// simply finds the first one's suppression record.
	s.grafanaMu.Lock()
	defer s.grafanaMu.Unlock()

	bodyHash := sha256.Sum256(body)
	prevID, found, err := s.store.LookupGrafana(source, bodyHash, s.now())
	result := "duplicate"
	// The signature of a request stays valid until its timestamp is older
	// than grafanaMaxSkew, which is after the body suppression has ended
	// whenever Grafana's clock is ahead of ours. Each accepted signature is
	// therefore remembered for as long as it is valid, and the same signed
	// request arriving again is answered like any other duplicate. Both
	// headers were validated by VerifyGrafanaSignature above.
	sig, _ := hex.DecodeString(r.Header.Get(GrafanaSignatureHeader))
	sec, _ := strconv.ParseInt(r.Header.Get(GrafanaTimestampHeader), 10, 64)
	replay := &store.Replay{
		Key:     store.ReplayKey(source, sig),
		Expires: time.Unix(sec, 0).Add(grafanaMaxSkew + time.Second),
	}
	if err == nil && !found {
		prevID, found, err = s.store.LookupReplay(replay.Key, s.now())
		result = "replay"
	}
	if err != nil {
		s.log.Error("queue read failed", "source", source, "result", "lookup_failed", "error", err.Error())
		s.reject(w, source, http.StatusInternalServerError, ErrTypeInternal, "could not read de-duplication state")
		return
	}
	if found {
		s.log.Info("duplicate suppressed", "id", prevID, "source", source, "receiver", ReceiverOps, "result", result)
		writeJSON(w, http.StatusAccepted, acceptedBody{ID: prevID})
		return
	}

	m, perr := ConvertGrafana(body)
	if perr != nil {
		s.reject(w, source, perr.status, perr.typ, perr.msg)
		return
	}
	id, err := s.accept(source, m, store.DedupGrafana, store.GrafanaKey(source, bodyHash), [32]byte{}, replay)
	if err != nil {
		s.rejectAcceptError(w, source, err)
		return
	}
	writeJSON(w, http.StatusAccepted, acceptedBody{ID: id})
}
