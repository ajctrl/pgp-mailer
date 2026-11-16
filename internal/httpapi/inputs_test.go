package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http/httptest"
	"net/mail"
	"pgp-mailer/internal/config"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestConfiguredIntake(t *testing.T) {
	e := setup(t, envOpts{})
	inputs, err := config.ParseInputs([]byte(`[
 {"path":"/hooks/alerts","source":"alerts","auth":"bearer","caller":"app-a","format":"json","dedup":"body","title":"{{ (index . 0).labels.alertname }}","body":"{{ toPrettyJSON . }}"},
 {"path":"/hooks/raw","source":"raw","auth":"bearer","format":"text","dedup":"none"},
 {"path":"/hooks/other","source":"other","auth":"bearer","format":"json","dedup":"body"}
 ]`))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Inputs = inputs
	e.h = e.srv.Handler()
	body := []byte(`[{"labels":{"alertname":"PrivateAlert"},"annotations":{"summary":"PrivateDetail"}}]`)
	send := func(path, token string, body []byte) resp { return e.do("POST", path, token, nil, body) }
	expect(t, send("/v1/messages", tokenA, body), 404, "")
	expect(t, send("/webhooks/grafana", tokenA, body), 404, "")
	expect(t, send("/hooks/alerts", tokenB, body), 401, ErrTypeUnauthorized)
	first := send("/hooks/alerts", tokenA, body)
	expect(t, first, 202, "")
	second := send("/hooks/alerts", tokenA, body)
	expect(t, second, 202, "")
	if first.id() != second.id() {
		t.Fatal("body duplicate was enqueued")
	}
	other := send("/hooks/other", tokenA, body)
	expect(t, other, 202, "")
	if other.id() == first.id() {
		t.Fatal("routes share suppression keys")
	}
	for i := 0; i < 2; i++ {
		expect(t, send("/hooks/raw", tokenA, []byte("plain text")), 202, "")
	}
	if len(e.pending()) != 4 {
		t.Fatalf("queue length %d", len(e.pending()))
	}
	expect(t, send("/hooks/alerts", tokenA, []byte("{}")), 422, ErrTypeValidation)
	expect(t, send("/hooks/alerts", tokenA, []byte("[")), 400, ErrTypeBadRequest)
	raw, err := e.st.Mail(first.id())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("PrivateDetail")) {
		t.Fatal("plaintext persisted")
	}
	start := bytes.Index(raw, []byte("-----BEGIN PGP MESSAGE-----"))
	end := bytes.Index(raw, []byte("-----END PGP MESSAGE-----"))
	plain, err := e.tk.Decrypt(raw[start:end+len("-----END PGP MESSAGE-----")], e.clock)
	if err != nil {
		t.Fatal(err)
	}

	inner, err := mail.ReadMessage(bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(inner.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(inner.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	part, err := multipart.NewReader(inner.Body, params["boundary"]).NextPart()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, part))
	if err != nil {
		t.Fatal(err)
	}
	if subject != "[info] PrivateAlert" || !bytes.Contains(decoded, []byte("PrivateDetail")) {
		t.Fatal("missing rendered content")
	}

	if strings.Contains(e.logs.String(), "Private") {
		t.Fatal("payload leaked in logs")
	}
}

func TestTemplateExpansionLimit(t *testing.T) {
	inputs, err := config.ParseInputs([]byte(`[{"path":"/x","source":"x","auth":"bearer","format":"json","dedup":"none","body":"{{range .}}{{range $v := $}}{{$v}}{{end}}{{end}}"}]`))
	if err != nil {
		t.Fatal(err)
	}
	body := "[" + strings.TrimSuffix(strings.Repeat("\""+strings.Repeat("x", 1024)+"\",", 20), ",") + "]"
	if _, err := convertInput(inputs[0], []byte(body)); err == nil {
		t.Fatal("unbounded expansion accepted")
	}
}

func TestCustomHMACAndDisabledRoutes(t *testing.T) {
	e := setup(t, envOpts{})
	inputs, err := config.ParseInputs([]byte(`[{"path":"/hooks/signed","source":"signed","auth":"hmac-sha256","secret_env":"SIGNING_SECRET","signature_header":"X-Signature","timestamp_header":"X-Time","format":"text","dedup":"none"}]`))
	if err != nil {
		t.Fatal(err)
	}
	inputs[0].Secret = []byte(hmacSecret)
	e.srv.cfg.Inputs = inputs
	e.h = e.srv.Handler()
	body := []byte("signed text")
	ts := strconv.FormatInt(e.clock.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(ts + ":"))
	mac.Write(body)
	headers := map[string]string{"X-Signature": hex.EncodeToString(mac.Sum(nil)), "X-Time": ts}
	first := e.do("POST", "/hooks/signed", "", headers, body)
	expect(t, first, 202, "")
	second := e.do("POST", "/hooks/signed", "", headers, body)
	expect(t, second, 202, "")
	if first.id() != second.id() {
		t.Fatal("signed replay was accepted twice")
	}
	expect(t, e.do("POST", "/hooks/signed", "", headers, []byte("tampered")), 401, ErrTypeUnauthorized)
	e.srv.cfg.Inputs = []config.Input{}
	e.h = e.srv.Handler()
	expect(t, e.do("POST", "/hooks/signed", "", headers, body), 404, "")
	expect(t, e.do("POST", "/v1/messages", tokenA, nil, []byte(validBody)), 404, "")
}

func TestSharedNamespaceConcurrentRequests(t *testing.T) {
	e := setup(t, envOpts{})
	inputs, err := config.ParseInputs([]byte(`[
 {"path":"/one","source":"one","auth":"bearer","format":"text","dedup":"body","dedup_namespace":"shared"},
 {"path":"/two","source":"two","auth":"bearer","format":"text","dedup":"body","dedup_namespace":"shared"}
 ]`))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Inputs = inputs
	e.h = e.srv.Handler()
	e.srv.wake = nil
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 20)
	for i := 0; i < 20; i++ {
		path := inputs[i%2].Path
		go func() {
			<-start
			r := httptest.NewRequest("POST", path, strings.NewReader("identical"))
			r.Header.Set("Authorization", "Bearer "+tokenA)
			w := httptest.NewRecorder()
			e.h.ServeHTTP(w, r)
			results <- w
		}()
	}
	close(start)
	var first string
	for i := 0; i < 20; i++ {
		w := <-results
		if w.Code != 202 {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if first == "" {
			first = w.Body.String()
		} else if first != w.Body.String() {
			t.Fatal("different acceptance IDs")
		}
	}
	if len(e.pending()) != 1 {
		t.Fatal("duplicate messages queued")
	}
	e.srv.scopeMu.Lock()
	defer e.srv.scopeMu.Unlock()
	if len(e.srv.scopes) != 0 {
		t.Fatal("scope lock leaked")
	}
}

func TestEncryptionFailureDoesNotPersistOrConsumeDedup(t *testing.T) {
	for _, route := range []string{"api", "signed", "raw"} {
		t.Run(route, func(t *testing.T) {
			e := setup(t, envOpts{})
			if route == "raw" {
				inputs, err := config.ParseInputs([]byte(`[{"path":"/raw","source":"raw","auth":"bearer","format":"text","dedup":"body"}]`))
				if err != nil {
					t.Fatal(err)
				}
				e.srv.cfg.Inputs = inputs
				e.h = e.srv.Handler()
			}
			send := func() resp {
				switch route {
				case "api":
					return e.post(tokenA, "encryption-retry", validBody)
				case "signed":
					return e.grafana(firing, e.clock)
				default:
					return e.do("POST", "/raw", tokenA, nil, []byte("private raw message"))
				}
			}
			before, err := e.st.Stats()
			if err != nil {
				t.Fatal(err)
			}
			encrypt := e.srv.builder.Encrypt
			e.srv.builder.Encrypt = func(time.Time, []byte) ([]byte, string, error) {
				return nil, "", errors.New("injected encryption failure")
			}
			expect(t, send(), 500, ErrTypeEncryptFailed)
			after, err := e.st.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if after != before || len(e.pending()) != 0 || e.woken != 0 {
				t.Fatalf("failed encryption changed queue or woke delivery: before=%+v after=%+v wake=%d", before, after, e.woken)
			}
			e.srv.builder.Encrypt = encrypt
			expect(t, send(), 202, "")
			if len(e.pending()) != 1 || e.woken != 1 {
				t.Fatal("retry was suppressed or not queued")
			}
		})
	}
}
