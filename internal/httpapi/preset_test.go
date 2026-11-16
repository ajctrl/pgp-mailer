package httpapi

import (
	"net/http"
	"pgp-mailer/internal/config"
	"time"
)

const fallbackTitle = "Grafana alert"

// VerifyGrafanaSignature checks the timestamped HMAC-SHA256 that Grafana's
// webhook contact point adds: hex(HMAC(secret, timestamp + ":" + body)).
// The returned error says why verification failed; it is for logs only.
func VerifyGrafanaSignature(secret []byte, h http.Header, body []byte, now time.Time) error {
	return verifySignature(secret, h, body, now, GrafanaSignatureHeader, GrafanaTimestampHeader)
}

func ConvertGrafana(body []byte) (*Message, *parseError) {
	return convertInput(config.DefaultInputs()[1], body)
}
