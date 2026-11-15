package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"pgp-mailer/internal/config"
	"pgp-mailer/internal/metrics"
	"pgp-mailer/internal/pgpkey"
	"pgp-mailer/internal/pgptest"
	"pgp-mailer/internal/store"
)

const (
	tokenA     = "token-a-0123456789abcdef0123456789abcdef"
	tokenB     = "token-b-0123456789abcdef0123456789abcdef"
	adminToken = "admin-0123456789abcdef0123456789abcdef"
	hmacSecret = "grafana-secret-0123456789abcdef0123456789"
)

var t0 = time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

type env struct {
	t     *testing.T
	srv   *Server
	h     http.Handler
	st    *store.Store
	tk    *pgptest.Key
	clock time.Time
	logs  *bytes.Buffer
	woken int
}

type envOpts struct {
	limit       int64
	keyLifetime uint32
}

func setup(t *testing.T, o envOpts) *env {
	t.Helper()
	if o.limit == 0 {
		o.limit = store.DefaultLimit
	}
	e := &env{t: t, clock: t0, logs: &bytes.Buffer{}}
	e.tk = pgptest.New(t0.Add(-time.Hour), o.keyLifetime)
	key, err := pgpkey.Load(e.tk.PublicBase64(), e.tk.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	e.st, err = store.Open(t.TempDir(), o.limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.st.Close() })
	cfg := &config.Config{
		MailFrom:    &mail.Address{Address: "mailer@example.com"},
		ReceiverOps: &mail.Address{Address: "ops@example.net"},
		APITokens: []config.Token{
			{Name: "app-a", Hash: sha256.Sum256([]byte(tokenA))},
			{Name: "app-b", Hash: sha256.Sum256([]byte(tokenB))},
		},
		GrafanaHMACSecret: []byte(hmacSecret),
		AdminTokenHash:    sha256.Sum256([]byte(adminToken)),
	}
	e.srv = New(Options{
		Config: cfg, Key: key, Store: e.st,
		Metrics: metrics.New([]string{"grafana", "app-a", "app-b"}, []string{"expired", "permanent"}),
		Log:     slog.New(slog.NewJSONHandler(e.logs, nil)),
		Now:     func() time.Time { return e.clock },
		Wake:    func() { e.woken++ },
	})
	e.h = e.srv.Handler()
	return e
}

type resp struct {
	code int
	body string
	json map[string]any
}

func (e *env) do(method, path, token string, hdr map[string]string, body []byte) resp {
	e.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	r := resp{code: rec.Code, body: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &r.json)
	return r
}

func (e *env) post(token, key, body string) resp {
	hdr := map[string]string{}
	if key != "" {
		hdr["Idempotency-Key"] = key
	}
	return e.do("POST", "/v1/messages", token, hdr, []byte(body))
}

func (r resp) id() string      { s, _ := r.json["id"].(string); return s }
func (r resp) errType() string { s, _ := r.json["error"].(string); return s }

func (e *env) pending() []*store.Item {
	e.t.Helper()
	items, err := e.st.Due(e.clock.Add(time.Hour), 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return items
}

const validBody = `{"receiver":"ops","title":"アプリのエラー増加","message":"直近5分でエラーが15件発生しました。","level":"error"}`

func expect(t *testing.T, r resp, code int, errType string) {
	t.Helper()
	if r.code != code || r.errType() != errType {
		t.Fatalf("got %d %q (%s), want %d %q", r.code, r.errType(), strings.TrimSpace(r.body), code, errType)
	}
}

func TestMessagesAuthentication(t *testing.T) {
	e := setup(t, envOpts{})
	expect(t, e.post("", "k", validBody), 401, ErrTypeUnauthorized)
	expect(t, e.post("wrong-token-0123456789abcdef0123456789", "k", validBody), 401, ErrTypeUnauthorized)
	expect(t, e.post(adminToken, "k", validBody), 401, ErrTypeUnauthorized)
	if len(e.pending()) != 0 {
		t.Fatal("unauthenticated request was queued")
	}
}

func TestAcceptEncryptsAndPersistsBeforeAnswering(t *testing.T) {
	e := setup(t, envOpts{})
	r := e.post(tokenA, "key-1", validBody)
	expect(t, r, 202, "")
	items := e.pending()
	if len(items) != 1 || items[0].ID != r.id() || len(r.id()) != 32 {
		t.Fatalf("queue = %+v, response id = %q", items, r.id())
	}
	it := items[0]
	if it.Source != "app-a" || it.Receiver != "ops" || it.Level != "error" ||
		it.KeyFingerprint != e.tk.Fingerprint() || it.EncSubkeyID == "" ||
		it.EnvelopeTo != "ops@example.net" || !it.Deadline.Equal(t0.Add(time.Hour)) {
		t.Fatalf("item = %+v", it)
	}
	if e.woken != 1 {
		t.Errorf("worker woken %d times", e.woken)
	}

	raw, err := e.st.Mail(it.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"アプリ", "直近", "エラー"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("stored mail contains plaintext %q", leak)
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Message-ID") != it.MessageID {
		t.Errorf("Message-ID header %q != stored %q", msg.Header.Get("Message-ID"), it.MessageID)
	}
	all, _ := io.ReadAll(msg.Body)
	start := bytes.Index(all, []byte("-----BEGIN PGP MESSAGE-----"))
	end := bytes.Index(all, []byte("-----END PGP MESSAGE-----"))
	plain, err := e.tk.Decrypt(all[start:end+len("-----END PGP MESSAGE-----")], e.clock)
	if err != nil {
		t.Fatalf("stored mail does not decrypt: %v", err)
	}
	inner, err := mail.ReadMessage(bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(inner.Header.Get("Subject"))
	if subject != "[error] アプリのエラー増加" {
		t.Errorf("protected subject = %q", subject)
	}

	// Neither title nor message nor tokens appear in the logs.
	for _, secret := range []string{"アプリ", "直近", tokenA, "key-1"} {
		if strings.Contains(e.logs.String(), secret) {
			t.Errorf("log contains %q:\n%s", secret, e.logs.String())
		}
	}
	if !strings.Contains(e.logs.String(), r.id()) {
		t.Error("acceptance id missing from log")
	}
}

func TestIdempotency(t *testing.T) {
	e := setup(t, envOpts{})
	first := e.post(tokenA, "key-1", validBody)
	expect(t, first, 202, "")

	// Same key, same content (different JSON spelling): same id, no new mail.
	reordered := `{ "level":"error", "message":"直近5分でエラーが15件発生しました。",
		"title":"\u30a2\u30d7\u30ea\u306e\u30a8\u30e9\u30fc\u5897\u52a0", "receiver":"ops" }`
	again := e.post(tokenA, "key-1", reordered)
	expect(t, again, 202, "")
	if again.id() != first.id() {
		t.Fatalf("replay returned id %q, want %q", again.id(), first.id())
	}

	// Omitting level equals level=info, which differs from the original.
	expect(t, e.post(tokenA, "key-1", `{"receiver":"ops","title":"アプリのエラー増加","message":"直近5分でエラーが15件発生しました。"}`),
		409, ErrTypeConflict)
	expect(t, e.post(tokenA, "key-1", strings.Replace(validBody, "15件", "16件", 1)), 409, ErrTypeConflict)
	if n := len(e.pending()); n != 1 {
		t.Fatalf("queue has %d items after replays, want 1", n)
	}

	// Another caller's identical key is independent.
	other := e.post(tokenB, "key-1", validBody)
	expect(t, other, 202, "")
	// A new key is a new notification even with the same title.
	second := e.post(tokenA, "key-2", validBody)
	expect(t, second, 202, "")
	if other.id() == first.id() || second.id() == first.id() || len(e.pending()) != 3 {
		t.Fatalf("ids %q %q %q, queue %d", first.id(), other.id(), second.id(), len(e.pending()))
	}

	// The replay still answers after the mail has been delivered.
	if err := e.st.MarkDelivered(first.id(), e.clock); err != nil {
		t.Fatal(err)
	}
	if r := e.post(tokenA, "key-1", validBody); r.code != 202 || r.id() != first.id() {
		t.Fatalf("replay after delivery = %d %q", r.code, r.id())
	}
	if len(e.pending()) != 2 {
		t.Fatal("replay after delivery enqueued a new mail")
	}
}

func TestIdempotencyKeyRules(t *testing.T) {
	e := setup(t, envOpts{})
	expect(t, e.post(tokenA, "", validBody), 400, ErrTypeBadKey)
	expect(t, e.post(tokenA, strings.Repeat("k", 129), validBody), 400, ErrTypeBadKey)
	expect(t, e.post(tokenA, "キー", validBody), 400, ErrTypeBadKey)
	expect(t, e.post(tokenA, "tab\tkey", validBody), 400, ErrTypeBadKey)
	expect(t, e.post(tokenA, strings.Repeat("k", 128), validBody), 202, "")

	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(validBody))
	req.Header.Set("Authorization", "Bearer "+tokenA)
	req.Header.Add("Idempotency-Key", "a")
	req.Header.Add("Idempotency-Key", "b")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("two Idempotency-Key headers = %d", rec.Code)
	}
}

func TestInProgressIsDistinguishedFromConflict(t *testing.T) {
	e := setup(t, envOpts{})
	e.srv.inflight["app-a\x00key-1"] = struct{}{}
	expect(t, e.post(tokenA, "key-1", validBody), 409, ErrTypeInProgress)
	if len(e.pending()) != 0 {
		t.Fatal("request was queued while the key was in progress")
	}
	delete(e.srv.inflight, "app-a\x00key-1")
	expect(t, e.post(tokenA, "key-1", validBody), 202, "")
	if len(e.srv.inflight) != 0 {
		t.Fatal("in-flight marker leaked")
	}
}

func TestValidation(t *testing.T) {
	e := setup(t, envOpts{})
	body := func(title, message, extra string) string {
		t, _ := json.Marshal(title)
		m, _ := json.Marshal(message)
		return fmt.Sprintf(`{"receiver":"ops","title":%s,"message":%s%s}`, t, m, extra)
	}
	cases := []struct {
		name string
		body string
		code int
		typ  string
	}{
		{"invalid UTF-8", "{\"receiver\":\"ops\",\"title\":\"\xff\",\"message\":\"m\"}", 400, ErrTypeBadRequest},
		{"malformed JSON", `{"receiver":"ops"`, 400, ErrTypeBadRequest},
		{"not an object", `["ops"]`, 400, ErrTypeBadRequest},
		{"trailing data", body("t", "m", "") + `{}`, 400, ErrTypeBadRequest},
		{"receiver missing", `{"title":"t","message":"m"}`, 422, ErrTypeValidation},
		{"receiver not ops", `{"receiver":"dev","title":"t","message":"m"}`, 422, ErrTypeValidation},
		{"receiver is an address", `{"receiver":"evil@example.org","title":"t","message":"m"}`, 422, ErrTypeValidation},
		{"extra address field", body("t", "m", `,"to":"evil@example.org"`), 422, ErrTypeValidation},
		{"title missing", `{"receiver":"ops","message":"m"}`, 422, ErrTypeValidation},
		{"title empty", body("", "m", ""), 422, ErrTypeValidation},
		{"title blank", body(" \u3000 ", "m", ""), 422, ErrTypeValidation},
		{"title with newline", body("a\nb", "m", ""), 422, ErrTypeValidation},
		{"title with CR", body("a\rb", "m", ""), 422, ErrTypeValidation},
		{"title 201 chars", body(strings.Repeat("あ", 201), "m", ""), 422, ErrTypeValidation},
		{"title not a string", `{"receiver":"ops","title":1,"message":"m"}`, 422, ErrTypeValidation},
		{"message is an object", `{"receiver":"ops","title":"t","message":{"text":"m"}}`, 422, ErrTypeValidation},
		{"receiver null", `{"receiver":null,"title":"t","message":"m"}`, 422, ErrTypeValidation},
		{"known key in another case", body("t", "m", `,"Level":"error"`), 422, ErrTypeValidation},
		{"unknown key that folds to a known one", body("t", "m", `,"TITLE":"other"`), 422, ErrTypeValidation},
		{"body is a string", `"ops"`, 400, ErrTypeBadRequest},
		{"message missing", `{"receiver":"ops","title":"t"}`, 422, ErrTypeValidation},
		{"message blank", body("t", " \n\t ", ""), 422, ErrTypeValidation},
		{"message over 64 KiB", body("t", strings.Repeat("a", MaxMessageBytes+1), ""), 422, ErrTypeValidation},
		{"level upper case", body("t", "m", `,"level":"ERROR"`), 422, ErrTypeValidation},
		{"level unknown value", body("t", "m", `,"level":"critical"`), 422, ErrTypeValidation},
		{"level empty", body("t", "m", `,"level":""`), 422, ErrTypeValidation},
	}
	for i, c := range cases {
		key := fmt.Sprint("bad-", i)
		expect(t, e.post(tokenA, key, c.body), c.code, c.typ)
		if _, _, found, _ := e.st.LookupIdem("app-a", key, e.clock); found {
			t.Fatalf("%s: a rejected request recorded its key", c.name)
		}
	}
	if len(e.pending()) != 0 {
		t.Fatal("an invalid request was queued")
	}

	// A key used by a rejected request is free for the corrected retry.
	expect(t, e.post(tokenA, "bad-0", validBody), 202, "")

	ok := []string{
		body(strings.Repeat("あ", 200), "m", ""), // 200 code points, 600 bytes
		body("t", strings.Repeat("a", MaxMessageBytes), ""),
		body("t", "m", `,"level":"trace"`),
		body("t", "m", `,"level":"unknown"`),
		body("t", "m", `,"level":null`),
	}
	for i, b := range ok {
		expect(t, e.post(tokenA, fmt.Sprint("ok-", i), b), 202, "")
	}
	for _, it := range e.pending() {
		if it.Level == "" {
			t.Fatalf("item without level: %+v", it)
		}
	}
	// level omitted or null defaults to info.
	r := e.post(tokenB, "default-level", body("t", "m", ""))
	expect(t, r, 202, "")
	for _, it := range e.pending() {
		if it.ID == r.id() && it.Level != "info" {
			t.Fatalf("default level = %q", it.Level)
		}
	}
}

func TestBodySizeLimit(t *testing.T) {
	e := setup(t, envOpts{})
	big := `{"receiver":"ops","title":"t","message":"m","pad":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	expect(t, e.post(tokenA, "big", big), 413, ErrTypeTooLarge)

	// Also when the length is not announced up front.
	req := httptest.NewRequest("POST", "/v1/messages", io.NopCloser(strings.NewReader(big)))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+tokenA)
	req.Header.Set("Idempotency-Key", "big-chunked")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("chunked oversize body = %d", rec.Code)
	}
}

func TestQueueFullIs503AndKeyStaysFree(t *testing.T) {
	e := setup(t, envOpts{limit: 3000})
	expect(t, e.post(tokenA, "k1", validBody), 202, "")
	expect(t, e.post(tokenA, "k2", validBody), 503, ErrTypeQueueFull)
	if _, _, found, _ := e.st.LookupIdem("app-a", "k2", e.clock); found {
		t.Fatal("refused request recorded its key")
	}
	// A replay of an accepted request is still answered while full.
	expect(t, e.post(tokenA, "k1", validBody), 202, "")
	// Space is freed by delivery; the same key then goes through.
	items := e.pending()
	if err := e.st.MarkDelivered(items[0].ID, e.clock); err != nil {
		t.Fatal(err)
	}
	expect(t, e.post(tokenA, "k2", validBody), 202, "")
}

// --- Grafana -----------------------------------------------------------------

func sign(ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(ts + ":"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (e *env) grafana(body string, at time.Time) resp {
	ts := strconv.FormatInt(at.Unix(), 10)
	return e.do("POST", "/webhooks/grafana", "", map[string]string{
		GrafanaSignatureHeader: sign(ts, []byte(body)),
		GrafanaTimestampHeader: ts,
	}, []byte(body))
}

const firing = `{"receiver":"pgp","status":"firing","alerts":[{"status":"firing"}],"title":"[FIRING:1] HighErrorRate","state":"alerting","message":"**Firing**\n\nValue: 15"}`

func TestGrafanaSignature(t *testing.T) {
	e := setup(t, envOpts{})
	ts := strconv.FormatInt(e.clock.Unix(), 10)
	good := sign(ts, []byte(firing))
	cases := map[string]map[string]string{
		"no headers":        {},
		"no timestamp":      {GrafanaSignatureHeader: good},
		"no signature":      {GrafanaTimestampHeader: ts},
		"wrong signature":   {GrafanaSignatureHeader: sign(ts, []byte(firing+" ")), GrafanaTimestampHeader: ts},
		"sha256= prefix":    {GrafanaSignatureHeader: "sha256=" + good, GrafanaTimestampHeader: ts},
		"not hex":           {GrafanaSignatureHeader: strings.Repeat("z", 64), GrafanaTimestampHeader: ts},
		"body-only HMAC":    {GrafanaSignatureHeader: hex.EncodeToString(hmacOnly([]byte(firing))), GrafanaTimestampHeader: ts},
		"timestamp swapped": {GrafanaSignatureHeader: good, GrafanaTimestampHeader: strconv.FormatInt(e.clock.Unix()+1, 10)},
		"timestamp garbage": {GrafanaSignatureHeader: good, GrafanaTimestampHeader: ts + "x"},
	}
	for name, hdr := range cases {
		r := e.do("POST", "/webhooks/grafana", "", hdr, []byte(firing))
		if r.code != 401 {
			t.Errorf("%s: status %d, want 401", name, r.code)
		}
		// The reason is logged, never returned.
		if strings.Contains(r.body, "signature") || strings.Contains(r.body, "timestamp") {
			t.Errorf("%s: response reveals the reason: %s", name, r.body)
		}
	}
	// A correctly signed request outside the ±5 minute window.
	for _, skew := range []time.Duration{-5*time.Minute - time.Second, 5*time.Minute + time.Second} {
		if r := e.grafana(firing, e.clock.Add(skew)); r.code != 401 {
			t.Errorf("skew %v: status %d, want 401", skew, r.code)
		}
	}
	if !strings.Contains(e.logs.String(), "timestamp_out_of_range") || !strings.Contains(e.logs.String(), "signature_mismatch") {
		t.Error("rejection reasons are not logged")
	}
	if len(e.pending()) != 0 {
		t.Fatal("unauthenticated webhook was queued")
	}
	// An API bearer token is not a substitute for the signature.
	if r := e.do("POST", "/webhooks/grafana", tokenA, nil, []byte(firing)); r.code != 401 {
		t.Errorf("bearer token on webhook = %d", r.code)
	}
	for _, skew := range []time.Duration{-5 * time.Minute, 5 * time.Minute} {
		body := firing + strings.Repeat(" ", int(skew/time.Minute)+10)
		if r := e.grafana(body, e.clock.Add(skew)); r.code != 202 {
			t.Errorf("skew %v: status %d, want 202", skew, r.code)
		}
	}
}

func TestGrafanaSignedRequestCannotBeReplayedAfterSuppression(t *testing.T) {
	e := setup(t, envOpts{})
	// Grafana's clock is four minutes ahead: the signature stays valid
	// until t0+9m, four minutes longer than the body suppression.
	signedAt := t0.Add(4 * time.Minute)
	first := e.grafana(firing, signedAt)
	expect(t, first, 202, "")

	for _, at := range []time.Duration{5*time.Minute + time.Second, 9 * time.Minute} {
		e.clock = t0.Add(at)
		r := e.grafana(firing, signedAt)
		if r.code != 202 || r.id() != first.id() || len(e.pending()) != 1 {
			t.Fatalf("replay at +%v = %d %q, queue %d; want the original id and no new mail", at, r.code, r.id(), len(e.pending()))
		}
	}
	if !strings.Contains(e.logs.String(), `result=replay`) && !strings.Contains(e.logs.String(), `"result":"replay"`) {
		t.Error("replay is not logged as such")
	}
	// Once the signature itself has expired the request is refused.
	e.clock = t0.Add(9*time.Minute + time.Second)
	if r := e.grafana(firing, signedAt); r.code != 401 {
		t.Fatalf("expired signature = %d, want 401", r.code)
	}
	// Grafana sending the same alert again signs it anew: a new mail.
	again := e.grafana(firing, e.clock.Add(4*time.Minute))
	if again.code != 202 || again.id() == first.id() || len(e.pending()) != 2 {
		t.Fatalf("freshly signed repeat = %d %q, queue %d", again.code, again.id(), len(e.pending()))
	}
}

func hmacOnly(body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write(body)
	return mac.Sum(nil)
}

func TestGrafanaConversionAndSuppression(t *testing.T) {
	e := setup(t, envOpts{})
	first := e.grafana(firing, e.clock)
	expect(t, first, 202, "")
	items := e.pending()
	if len(items) != 1 || items[0].Source != "grafana" || items[0].Level != "error" || items[0].Receiver != "ops" {
		t.Fatalf("queue = %+v", items)
	}

	// Identical body: suppressed with the original id, whatever the
	// timestamp header says, and the window is not extended.
	e.clock = t0.Add(4 * time.Minute)
	dup := e.grafana(firing, e.clock)
	if dup.code != 202 || dup.id() != first.id() || len(e.pending()) != 1 {
		t.Fatalf("duplicate = %d %q, queue %d", dup.code, dup.id(), len(e.pending()))
	}

	// A different body (the resolved notification) is a new mail.
	resolved := strings.Replace(strings.Replace(firing, `"status":"firing","alerts"`, `"status":"resolved","alerts"`, 1), "FIRING", "RESOLVED", 1)
	res := e.grafana(resolved, e.clock)
	expect(t, res, 202, "")
	if res.id() == first.id() {
		t.Fatal("resolved notification was suppressed")
	}
	var level string
	for _, it := range e.pending() {
		if it.ID == res.id() {
			level = it.Level
		}
	}
	if level != "info" {
		t.Fatalf("resolved level = %q, want info", level)
	}

	// Five minutes after the first receipt the same body is new again.
	e.clock = t0.Add(5 * time.Minute)
	later := e.grafana(firing, e.clock)
	if later.code != 202 || later.id() == first.id() || len(e.pending()) != 3 {
		t.Fatalf("after window = %d %q, queue %d", later.code, later.id(), len(e.pending()))
	}

	// Oversized and malformed bodies.
	big := `{"status":"firing","title":"t","message":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	if r := e.grafana(big, e.clock); r.code != 413 {
		t.Errorf("oversized webhook = %d", r.code)
	}
	if r := e.grafana(`{"status":`, e.clock); r.code != 400 {
		t.Errorf("malformed webhook = %d", r.code)
	}
	// A signed body that is not a Grafana webhook is refused, not mailed,
	// and leaves no suppression record behind.
	queued := len(e.pending())
	for i := 0; i < 2; i++ {
		if r := e.grafana(`{}`, e.clock); r.code != 400 {
			t.Errorf("empty webhook = %d, want 400", r.code)
		}
	}
	if len(e.pending()) != queued {
		t.Error("an empty webhook was queued")
	}
}

func TestConvertGrafana(t *testing.T) {
	long := strings.Repeat("あ", MaxMessageBytes) // 3 bytes each: far over 64 KiB
	body, _ := json.Marshal(map[string]any{
		"status":  "firing",
		"title":   "line1\r\nline2\ttab " + strings.Repeat("x", 300),
		"message": long,
	})
	m, perr := ConvertGrafana(body)
	if perr != nil {
		t.Fatal(perr)
	}
	if utf8.RuneCountInString(m.Title) > MaxTitleRunes || strings.ContainsAny(m.Title, "\r\n\t") || !strings.HasPrefix(m.Title, "line1  line2 tab") {
		t.Errorf("title = %q", m.Title)
	}
	if len(m.Message) > MaxMessageBytes || !utf8.ValidString(m.Message) || !strings.HasSuffix(m.Message, truncationNote) {
		t.Errorf("message: len=%d valid=%v suffix ok=%v", len(m.Message), utf8.ValidString(m.Message), strings.HasSuffix(m.Message, truncationNote))
	}
	// The converted message must itself satisfy the common-format rules.
	re, _ := json.Marshal(map[string]string{"receiver": m.Receiver, "title": m.Title, "message": m.Message, "level": m.Level})
	if _, perr := ParseMessage(re); perr != nil {
		t.Errorf("converted message fails common validation: %v", perr)
	}

	// Nothing is rejected for being empty or unusual.
	m, perr = ConvertGrafana([]byte(`{"status":"paused","title":" \n ","message":""}`))
	if perr != nil || m.Level != "unknown" || strings.TrimSpace(m.Title) == "" || strings.TrimSpace(m.Message) == "" {
		t.Errorf("fallbacks: %+v %v", m, perr)
	}
	for _, b := range []string{`{"title":"only a title"}`, `{"message":"only a message"}`, `{"status":"firing"}`} {
		if m, perr = ConvertGrafana([]byte(b)); perr != nil || strings.TrimSpace(m.Title) == "" || strings.TrimSpace(m.Message) == "" {
			t.Errorf("%s: %+v %v", b, m, perr)
		}
	}
	// A field of the wrong type does not cost the alert either.
	m, perr = ConvertGrafana([]byte(`{"status":"firing","title":{"alert":"HighErrorRate"},"message":123}`))
	if perr != nil || m.Level != "error" || m.Title != `{"alert":"HighErrorRate"}` || m.Message != "123" {
		t.Errorf("wrong types: %+v %v", m, perr)
	}
	m, perr = ConvertGrafana([]byte(`{"status":["firing"],"title":null,"message":"text"}`))
	if perr != nil || m.Level != "unknown" || !strings.HasPrefix(m.Title, fallbackTitle) || m.Message != "text" {
		t.Errorf("wrong types: %+v %v", m, perr)
	}
	// Except a body that is no Grafana webhook at all.
	for _, b := range []string{`null`, `{}`, `{"text":"hello","channel":"#ops"}`, `{"status":"","title":" ","message":"\n"}`} {
		if _, perr = ConvertGrafana([]byte(b)); perr == nil || perr.status != 400 {
			t.Errorf("%s: err = %v, want 400", b, perr)
		}
	}
}

// --- key expiry, health, metrics, admin --------------------------------------

func TestDeliveryOnlyModeAfterKeyExpiry(t *testing.T) {
	e := setup(t, envOpts{keyLifetime: 7200}) // created t0-1h, expires t0+1h
	first := e.post(tokenA, "k1", validBody)
	expect(t, first, 202, "")
	if r := e.do("GET", "/healthz", "", nil, nil); r.code != 200 {
		t.Fatalf("healthz before expiry = %d %s", r.code, r.body)
	}
	if r := e.do("GET", "/metrics", "", nil, nil); !strings.Contains(r.body, "pgp_mailer_key_valid 1") ||
		!strings.Contains(r.body, fmt.Sprintf("pgp_mailer_key_expiry_timestamp_seconds %d", t0.Add(time.Hour).Unix())) {
		t.Fatalf("metrics before expiry:\n%s", r.body)
	}

	e.clock = t0.Add(time.Hour + 2*time.Second)
	// Authentication still comes first.
	expect(t, e.post("", "k2", validBody), 401, ErrTypeUnauthorized)
	expect(t, e.post(tokenA, "k2", validBody), 503, ErrTypeKeyExpired)
	// Even a replay of an accepted request gets 503 in this mode.
	expect(t, e.post(tokenA, "k1", validBody), 503, ErrTypeKeyExpired)
	if r := e.do("POST", "/webhooks/grafana", "", nil, []byte(firing)); r.code != 401 {
		t.Fatalf("unsigned webhook in delivery-only mode = %d", r.code)
	}
	expect(t, e.grafana(firing, e.clock), 503, ErrTypeKeyExpired)

	if r := e.do("GET", "/healthz", "", nil, nil); r.code != 503 {
		t.Fatalf("healthz after expiry = %d", r.code)
	}
	if r := e.do("GET", "/metrics", "", nil, nil); r.code != 200 || !strings.Contains(r.body, "pgp_mailer_key_valid 0") {
		t.Fatalf("metrics after expiry: %d\n%s", r.code, r.body)
	}
	if r := e.do("GET", "/admin/v1/failed", adminToken, nil, nil); r.code != 200 {
		t.Fatalf("admin API after expiry = %d", r.code)
	}
	// The mail accepted before expiry is still queued for delivery.
	if items := e.pending(); len(items) != 1 || items[0].ID != first.id() {
		t.Fatalf("queue after expiry = %+v", items)
	}
}

func TestHealthzAndMetrics(t *testing.T) {
	e := setup(t, envOpts{})
	if r := e.do("GET", "/healthz", "", nil, nil); r.code != 200 {
		t.Fatalf("healthz = %d %s", r.code, r.body)
	}
	expect(t, e.post(tokenA, "k1", validBody), 202, "")
	expect(t, e.post("", "k1", validBody), 401, ErrTypeUnauthorized)
	expect(t, e.post(tokenB, "k1", `{}`), 422, ErrTypeValidation)
	expect(t, e.grafana(firing, e.clock), 202, "")

	r := e.do("GET", "/metrics", "", nil, nil)
	st, _ := e.st.Stats()
	for _, want := range []string{
		`pgp_mailer_accepted_total{source="app-a"} 1`,
		`pgp_mailer_accepted_total{source="app-b"} 0`,
		`pgp_mailer_accepted_total{source="grafana"} 1`,
		`pgp_mailer_rejected_total{source="_unauthenticated",code="401"} 1`,
		`pgp_mailer_rejected_total{source="app-b",code="422"} 1`,
		`pgp_mailer_delivered_total 0`,
		`pgp_mailer_failed_total{reason="expired"} 0`,
		`pgp_mailer_failed_total{reason="permanent"} 0`,
		`pgp_mailer_queue_messages{state="pending"} 2`,
		`pgp_mailer_queue_messages{state="failed"} 0`,
		`pgp_mailer_queue_messages{state="quarantined"} 0`,
		fmt.Sprintf("pgp_mailer_storage_bytes %d", st.Bytes),
		fmt.Sprintf("pgp_mailer_storage_limit_bytes %d", 256<<20),
		`pgp_mailer_key_valid 1`,
	} {
		if !strings.Contains(r.body, want+"\n") {
			t.Errorf("metrics lack %q", want)
		}
	}
	if strings.Contains(r.body, "pgp_mailer_key_expiry_timestamp_seconds") {
		t.Error("expiry metric present for a key that never expires")
	}
	if st.Bytes == 0 {
		t.Error("storage bytes not counted")
	}

	// A closed database makes the service unhealthy.
	e.st.Close()
	e.clock = e.clock.Add(time.Minute)
	if r := e.do("GET", "/healthz", "", nil, nil); r.code != 503 {
		t.Fatalf("healthz with unwritable queue = %d", r.code)
	}
}

func TestDrainRefusesNewWork(t *testing.T) {
	e := setup(t, envOpts{})
	e.srv.Drain()
	expect(t, e.post(tokenA, "k1", validBody), 503, ErrTypeShuttingDown)
	expect(t, e.grafana(firing, e.clock), 503, ErrTypeShuttingDown)
}

func TestAdminAPI(t *testing.T) {
	e := setup(t, envOpts{})
	for _, tok := range []string{"", tokenA, "x"} {
		for _, rq := range [][2]string{{"GET", "/admin/v1/failed"}, {"GET", "/admin/v1/quarantine"},
			{"DELETE", "/admin/v1/failed/" + strings.Repeat("0", 32)}} {
			if r := e.do(rq[0], rq[1], tok, nil, nil); r.code != 401 {
				t.Fatalf("%s %s with token %q = %d", rq[0], rq[1], tok, r.code)
			}
		}
	}

	a := e.post(tokenA, "k1", validBody).id()
	b := e.post(tokenA, "k2", validBody).id()
	if err := e.st.Fail(a, store.ReasonPermanent, true, "smtp", 550, e.clock); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Fail(b, store.ReasonExpired, false, "", 0, e.clock); err != nil {
		t.Fatal(err)
	}

	r := e.do("GET", "/admin/v1/failed", adminToken, nil, nil)
	if r.code != 200 {
		t.Fatalf("list = %d %s", r.code, r.body)
	}
	for _, leak := range []string{"アプリ", "直近", "ops@example.net", "message_id", "envelope"} {
		if strings.Contains(r.body, leak) {
			t.Errorf("listing contains %q: %s", leak, r.body)
		}
	}
	rows := r.json["items"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	reasons := map[string]string{}
	for _, row := range rows {
		m := row.(map[string]any)
		reasons[m["id"].(string)] = m["reason"].(string)
		if m["source"] != "app-a" || m["level"] != "error" || m["failed_at"] == nil || m["delete_at"] == nil {
			t.Errorf("row = %v", m)
		}
	}
	if reasons[a] != "permanent (smtp 550)" || reasons[b] != "expired" {
		t.Errorf("reasons = %v", reasons)
	}

	// Retry: back to pending with the same id, fresh window.
	e.clock = e.clock.Add(3 * time.Hour)
	if r := e.do("POST", "/admin/v1/failed/"+a+"/retry", adminToken, nil, nil); r.code != 200 {
		t.Fatalf("retry = %d %s", r.code, r.body)
	}
	items := e.pending()
	if len(items) != 1 || items[0].ID != a || !items[0].Deadline.Equal(e.clock.Add(time.Hour)) {
		t.Fatalf("pending after retry = %+v", items)
	}
	if r := e.do("POST", "/admin/v1/failed/"+a+"/retry", adminToken, nil, nil); r.code != 404 {
		t.Fatalf("second retry = %d", r.code)
	}

	// Delete: gone, and the key is remembered for another 24h.
	if r := e.do("DELETE", "/admin/v1/failed/"+b, adminToken, nil, nil); r.code != 200 {
		t.Fatalf("delete = %d %s", r.code, r.body)
	}
	if r := e.do("DELETE", "/admin/v1/failed/"+b, adminToken, nil, nil); r.code != 404 {
		t.Fatalf("second delete = %d", r.code)
	}
	if r := e.post(tokenA, "k2", validBody); r.code != 202 || r.id() != b {
		t.Fatalf("replay after delete = %d %q", r.code, r.id())
	}
	if r := e.do("DELETE", "/admin/v1/failed/not-an-id", adminToken, nil, nil); r.code != 404 {
		t.Fatalf("bad id = %d", r.code)
	}

	// Quarantine: list and delete only.
	if _, err := e.st.Quarantine([]string{e.tk.Fingerprint()}, e.clock); err != nil {
		t.Fatal(err)
	}
	r = e.do("GET", "/admin/v1/quarantine", adminToken, nil, nil)
	rows = r.json["items"].([]any)
	if r.code != 200 || len(rows) != 1 || rows[0].(map[string]any)["id"] != a ||
		rows[0].(map[string]any)["key_fingerprint"] != e.tk.Fingerprint() {
		t.Fatalf("quarantine list = %d %s", r.code, r.body)
	}
	if r := e.do("POST", "/admin/v1/quarantine/"+a+"/retry", adminToken, nil, nil); r.code != 404 && r.code != 405 {
		t.Fatalf("retry of a quarantined item must not exist, got %d", r.code)
	}
	// The caller may resend with the same key after quarantine.
	if r := e.post(tokenA, "k1", validBody); r.code != 202 || r.id() == a {
		t.Fatalf("resend after quarantine = %d %q", r.code, r.id())
	}
	if r := e.do("DELETE", "/admin/v1/quarantine/"+a, adminToken, nil, nil); r.code != 200 {
		t.Fatalf("quarantine delete = %d", r.code)
	}
	if r := e.do("GET", "/admin/v1/quarantine", adminToken, nil, nil); len(r.json["items"].([]any)) != 0 {
		t.Fatalf("quarantine not empty: %s", r.body)
	}
}
