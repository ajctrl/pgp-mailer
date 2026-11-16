package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	GrafanaSignatureHeader = "X-Grafana-Alerting-Signature"
	GrafanaTimestampHeader = "X-Grafana-Alerting-Timestamp"

	signatureMaxSkew = 5 * time.Minute

	truncationNote = "\n\n[pgp-mailer] 本文が 64 KiB を超えたため、末尾を切り詰めました。"
)

func verifySignature(secret []byte, h http.Header, body []byte, now time.Time, signatureHeader, timestampHeader string) error {

	sigs, tss := h.Values(signatureHeader), h.Values(timestampHeader)
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
	if d := now.Sub(time.Unix(sec, 0)); d > signatureMaxSkew || d < -signatureMaxSkew {
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
