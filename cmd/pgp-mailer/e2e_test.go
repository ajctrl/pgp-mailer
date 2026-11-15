package main

// End-to-end tests: build the real binary, run it against an in-process
// SMTP server with TLS and drive it over HTTP and its own subcommands.
// Skipped with -short.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"pgp-mailer/internal/pgptest"
	"pgp-mailer/internal/smtptest"
)

const (
	apiToken   = "e2e-api-token-0123456789abcdef0123456789"
	adminToken = "e2e-admin-token-0123456789abcdef01234567"
	hmacSecret = "e2e-hmac-secret-0123456789abcdef01234567"
	smtpUser   = "mailer"
	smtpPass   = "smtp-password"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pgp-mailer-e2e")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "pgp-mailer")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type service struct {
	t    *testing.T
	env  []string
	base string
	cmd  *exec.Cmd
	out  *syncBuffer
	done chan error
}

type fixture struct {
	t        *testing.T
	smtp     *smtptest.Server
	caFile   string
	queueDir string
	port     int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test skipped with -short")
	}
	srv, err := smtptest.Start(smtptest.Options{Username: smtpUser, Password: smtpPass})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, srv.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return &fixture{t: t, smtp: srv, caFile: caFile, queueDir: filepath.Join(dir, "queue"), port: port}
}

func (f *fixture) env(key *pgptest.Key, extra ...string) []string {
	return append([]string{
		"PATH=" + os.Getenv("PATH"),
		"SSL_CERT_FILE=" + f.caFile, // trust the test CA instead of the system store
		"LISTEN_ADDR=127.0.0.1:" + strconv.Itoa(f.port),
		"PGP_PUBLIC_KEY_BASE64=" + key.PublicBase64(),
		"PGP_FINGERPRINT=" + key.Fingerprint(),
		"SMTP_HOST=" + f.smtp.Host,
		"SMTP_PORT=" + strconv.Itoa(f.smtp.Port),
		"SMTP_TLS_MODE=starttls",
		"SMTP_USERNAME=" + smtpUser,
		"SMTP_PASSWORD=" + smtpPass,
		"MAIL_FROM=mailer@example.com",
		"RECEIVER_OPS=ops@example.net",
		"API_TOKENS=e2e-app:" + apiToken,
		"GRAFANA_HMAC_SECRET=" + hmacSecret,
		"ADMIN_TOKEN=" + adminToken,
		"QUEUE_DIR=" + f.queueDir,
	}, extra...)
}

// launch starts the service without waiting for it to become ready.
func (f *fixture) launch(env []string) *service {
	s := &service{t: f.t, env: env, base: "http://127.0.0.1:" + strconv.Itoa(f.port), out: &syncBuffer{}, done: make(chan error, 1)}
	s.cmd = exec.Command(binary)
	s.cmd.Env = env
	s.cmd.Stdout, s.cmd.Stderr = s.out, s.out
	if err := s.cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	go func() { s.done <- s.cmd.Wait() }()
	f.t.Cleanup(func() {
		if s.cmd.ProcessState == nil {
			s.cmd.Process.Kill()
		}
	})
	return s
}

// start launches the service and waits until it answers HTTP.
func (f *fixture) start(env []string) *service {
	f.t.Helper()
	s := f.launch(env)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			f.t.Fatalf("service exited during startup: %v\n%s", err, s.out.String())
		default:
		}
		if resp, err := http.Get(s.base + "/healthz"); err == nil {
			resp.Body.Close()
			return s
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.t.Fatalf("service did not start:\n%s", s.out.String())
	return nil
}

// stop sends SIGTERM and returns the exit code.
func (s *service) stop() int {
	s.t.Helper()
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
		return s.cmd.ProcessState.ExitCode()
	case <-time.After(15 * time.Second):
		s.t.Fatalf("service did not stop after SIGTERM:\n%s", s.out.String())
		return -1
	}
}

// sub runs a subcommand of the binary in the service's environment.
func (s *service) sub(args ...string) (string, int) {
	cmd := exec.Command(binary, args...)
	cmd.Env = s.env
	out, _ := cmd.CombinedOutput()
	return string(out), cmd.ProcessState.ExitCode()
}

func (s *service) request(method, path string, hdr map[string]string, body string) (int, map[string]any, string) {
	s.t.Helper()
	req, _ := http.NewRequest(method, s.base+path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatalf("%s %s: %v\n%s", method, path, err, s.out.String())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var js map[string]any
	_ = json.Unmarshal(raw, &js)
	return resp.StatusCode, js, string(raw)
}

func (s *service) post(key, title, message string) (int, map[string]any) {
	body, _ := json.Marshal(map[string]string{"receiver": "ops", "title": title, "message": message, "level": "error"})
	code, js, _ := s.request("POST", "/v1/messages", map[string]string{
		"Authorization": "Bearer " + apiToken, "Idempotency-Key": key,
	}, string(body))
	return code, js
}

func (s *service) metric(line string) bool {
	_, _, body := s.request("GET", "/metrics", nil, "")
	return strings.Contains(body, line+"\n")
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// open decrypts a delivered mail and returns the protected subject and body.
func open(t *testing.T, key *pgptest.Key, m smtptest.Message) (outer *mail.Message, subject, body string) {
	t.Helper()
	outer, err := mail.ReadMessage(bytes.NewReader(m.Data))
	if err != nil {
		t.Fatal(err)
	}
	all, _ := io.ReadAll(outer.Body)
	const begin, end = "-----BEGIN PGP MESSAGE-----", "-----END PGP MESSAGE-----"
	i, j := bytes.Index(all, []byte(begin)), bytes.Index(all, []byte(end))
	if i < 0 || j < 0 {
		t.Fatalf("no PGP message in delivered mail:\n%s", m.Data)
	}
	plain, err := key.Decrypt(all[i:j+len(end)], time.Now())
	if err != nil {
		t.Fatalf("delivered mail does not decrypt: %v", err)
	}
	inner, err := mail.ReadMessage(bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ = new(mime.WordDecoder).DecodeHeader(inner.Header.Get("Subject"))
	_, params, err := mime.ParseMediaType(inner.Header.Get("Content-Type"))
	if err != nil || params["protected-headers"] != "v1" {
		t.Fatalf("inner Content-Type = %q (%v)", inner.Header.Get("Content-Type"), err)
	}
	part, err := multipart.NewReader(inner.Body, params["boundary"]).NextRawPart()
	if err != nil {
		t.Fatalf("inner part: %v", err)
	}
	dec, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, part))
	if err != nil {
		t.Fatalf("inner body: %v", err)
	}
	return outer, subject, string(dec)
}

func TestEndToEnd(t *testing.T) {
	f := newFixture(t)
	keyA := pgptest.New(time.Now().Add(-time.Hour), 0)
	svc := f.start(f.env(keyA))

	if out, code := svc.sub("healthcheck"); code != 0 {
		t.Fatalf("healthcheck = %d %s\n%s", code, out, svc.out.String())
	}

	// 1. Generic intake -> encrypted mail over STARTTLS.
	code, js := svc.post("e2e-1", "アプリのエラー増加", "直近5分でエラーが15件発生しました。")
	if code != 202 {
		t.Fatalf("POST = %d %v", code, js)
	}
	id1 := js["id"].(string)
	waitFor(t, "first delivery", func() bool { return len(f.smtp.Messages()) == 1 })
	got := f.smtp.Messages()[0]
	if got.From != "mailer@example.com" || got.To != "ops@example.net" {
		t.Errorf("envelope = %s -> %s", got.From, got.To)
	}
	if bytes.Contains(got.Data, []byte("アプリ")) || bytes.Contains(got.Data, []byte("直近")) {
		t.Fatal("plaintext on the wire")
	}
	outer, subject, body := open(t, keyA, got)
	if outer.Header.Get("Subject") != "[pgp-mailer] encrypted notification" {
		t.Errorf("outer subject = %q", outer.Header.Get("Subject"))
	}
	if outer.Header.Get("Message-ID") != "<"+id1+"@example.com>" {
		t.Errorf("Message-ID = %q", outer.Header.Get("Message-ID"))
	}
	if subject != "[error] アプリのエラー増加" || !strings.HasPrefix(body, "直近5分でエラーが15件発生しました。\r\n") {
		t.Errorf("decrypted subject=%q body=%q", subject, body)
	}
	waitFor(t, "delivered metric", func() bool { return svc.metric("pgp_mailer_delivered_total 1") })

	// A replay returns the same id and sends nothing.
	if code, js := svc.post("e2e-1", "アプリのエラー増加", "直近5分でエラーが15件発生しました。"); code != 202 || js["id"] != id1 {
		t.Fatalf("replay = %d %v", code, js)
	}

	// 2. Grafana webhook with a timestamped HMAC.
	hook := `{"status":"resolved","title":"[RESOLVED] HighErrorRate","message":"**Resolved**"}`
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(ts + ":" + hook))
	hdr := map[string]string{
		"X-Grafana-Alerting-Signature": hex.EncodeToString(mac.Sum(nil)),
		"X-Grafana-Alerting-Timestamp": ts,
	}
	if code, js, _ := svc.request("POST", "/webhooks/grafana", hdr, hook); code != 202 {
		t.Fatalf("grafana = %d %v", code, js)
	}
	waitFor(t, "grafana delivery", func() bool { return len(f.smtp.Messages()) == 2 })
	if _, subject, body := open(t, keyA, f.smtp.Messages()[1]); subject != "[info] [RESOLVED] HighErrorRate" || !strings.HasPrefix(body, "**Resolved**") {
		t.Errorf("grafana mail: subject=%q body=%q", subject, body)
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(f.smtp.Messages()); n != 2 {
		t.Fatalf("replay caused an extra mail: %d", n)
	}

	// 3. Permanent SMTP error -> failed queue, visible through the CLI.
	f.smtp.SetReply(func(stage string) (int, string) {
		if stage == "data" {
			return 550, "5.7.1 rejected"
		}
		return 0, ""
	})
	code, js = svc.post("e2e-2", "second", "to be rejected")
	if code != 202 {
		t.Fatalf("POST = %d %v", code, js)
	}
	id2 := js["id"].(string)
	waitFor(t, "failed metric", func() bool { return svc.metric(`pgp_mailer_failed_total{reason="permanent"} 1`) })
	if out, code := svc.sub("admin", "failed", "list"); code != 0 || !strings.Contains(out, id2) || !strings.Contains(out, "permanent (smtp 550)") {
		t.Fatalf("admin failed list = %d\n%s", code, out)
	}

	// Logs: ids and codes yes, content and secrets no.
	logs := svc.out.String()
	for _, banned := range []string{"アプリ", "直近", "second", "to be rejected", apiToken, adminToken, hmacSecret, smtpPass, "HighErrorRate"} {
		if strings.Contains(logs, banned) {
			t.Errorf("log contains %q", banned)
		}
	}
	if !strings.Contains(logs, id1) || !strings.Contains(logs, `"smtp_code":550`) {
		t.Errorf("log lacks id or SMTP code:\n%s", logs)
	}
	// Every line is JSON with the log severity and, separately, the
	// notification level.
	sawLevel := false
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if strings.Count(line, `"severity":`) != 1 {
			t.Errorf("log line without exactly one severity: %s", line)
		}
		if rec["result"] == "accepted" && rec["id"] == id1 {
			sawLevel = rec["level"] == "error" && rec["severity"] == "INFO" && rec["source"] == "e2e-app" && rec["receiver"] == "ops"
		}
	}
	if !sawLevel {
		t.Errorf("accept log lacks level/source/receiver:\n%s", logs)
	}

	// 4. Graceful stop; the failed queue survives the restart.
	if code := svc.stop(); code != 0 {
		t.Fatalf("exit code after SIGTERM = %d\n%s", code, svc.out.String())
	}
	if _, code := svc.sub("healthcheck"); code == 0 {
		t.Fatal("healthcheck succeeds while the service is down")
	}
	svc = f.start(f.env(keyA))
	if out, _ := svc.sub("admin", "failed", "list"); !strings.Contains(out, id2) {
		t.Fatalf("failed item lost across restart:\n%s", out)
	}
	f.smtp.SetReply(nil)
	if out, code := svc.sub("admin", "failed", "retry", id2); code != 0 {
		t.Fatalf("admin failed retry = %d %s", code, out)
	}
	waitFor(t, "delivery after manual retry", func() bool { return len(f.smtp.Messages()) == 3 })
	if outer, subject, _ := open(t, keyA, f.smtp.Messages()[2]); subject != "[error] second" || outer.Header.Get("Message-ID") != "<"+id2+"@example.com>" {
		t.Errorf("retried mail: subject=%q id=%q", subject, outer.Header.Get("Message-ID"))
	}
	if out, _ := svc.sub("admin", "failed", "list"); !strings.Contains(out, "0 item(s)") {
		t.Fatalf("failed queue not empty after retry:\n%s", out)
	}
	if out, code := svc.sub("admin", "failed", "retry", id2); code == 0 {
		t.Fatalf("retry of a delivered item succeeded: %s", out)
	}

	// 5. Emergency revocation: new key, old key quarantined at startup.
	f.smtp.SetReply(func(stage string) (int, string) {
		if stage == "data" {
			return 550, "rejected"
		}
		return 0, ""
	})
	code, js = svc.post("e2e-3", "third", "encrypted to the old key")
	id3 := js["id"].(string)
	waitFor(t, "third item failed", func() bool { return svc.metric(`pgp_mailer_failed_total{reason="permanent"} 1`) })
	svc.stop()
	f.smtp.SetReply(nil)

	keyB := pgptest.New(time.Now().Add(-time.Hour), 0)
	svc = f.start(f.env(keyB, "PGP_QUARANTINE_FINGERPRINTS="+keyA.Fingerprint()))
	if out, code := svc.sub("admin", "quarantine", "list"); code != 0 || !strings.Contains(out, id3) || !strings.Contains(out, keyA.Fingerprint()) {
		t.Fatalf("admin quarantine list = %d\n%s", code, out)
	}
	if out, _ := svc.sub("admin", "failed", "list"); !strings.Contains(out, "0 item(s)") {
		t.Fatalf("failed queue after quarantine:\n%s", out)
	}
	// The caller resends with the same key; it is encrypted to the new key.
	if code, js := svc.post("e2e-3", "third", "encrypted to the old key"); code != 202 || js["id"] == id3 {
		t.Fatalf("resend after quarantine = %d %v", code, js)
	}
	waitFor(t, "delivery with the new key", func() bool { return len(f.smtp.Messages()) == 4 })
	if _, subject, _ := open(t, keyB, f.smtp.Messages()[3]); subject != "[error] third" {
		t.Errorf("subject = %q", subject)
	}
	if out, code := svc.sub("admin", "quarantine", "delete", id3); code != 0 {
		t.Fatalf("admin quarantine delete = %d %s", code, out)
	}
	if !svc.metric(`pgp_mailer_queue_messages{state="quarantined"} 0`) {
		t.Error("quarantine not empty after delete")
	}
	svc.stop()
}

func TestKeyExpiryWhileRunningAndAtStartup(t *testing.T) {
	f := newFixture(t)
	// Valid for about four more seconds.
	created := time.Now().Add(-time.Hour)
	key := pgptest.New(created, 3600+4)
	svc := f.start(f.env(key))

	f.smtp.SetReply(func(stage string) (int, string) {
		if stage == "data" {
			return 550, "rejected"
		}
		return 0, ""
	})
	code, js := svc.post("exp-1", "before expiry", "accepted while the key was valid")
	if code != 202 {
		t.Fatalf("POST before expiry = %d %v", code, js)
	}
	id := js["id"].(string)
	waitFor(t, "item in failed queue", func() bool { return svc.metric(`pgp_mailer_queue_messages{state="failed"} 1`) })
	if !svc.metric(fmt.Sprintf("pgp_mailer_key_expiry_timestamp_seconds %d", created.Add(3604*time.Second).Unix())) {
		t.Error("expiry timestamp metric missing or wrong")
	}

	// The key expires under the running service.
	waitFor(t, "key expiry", func() bool { return svc.metric("pgp_mailer_key_valid 0") })
	if code, js := svc.post("exp-2", "after expiry", "x"); code != 503 || js["error"] != "key_expired" {
		t.Fatalf("POST after expiry = %d %v", code, js)
	}
	if code, _, _ := svc.request("POST", "/v1/messages", nil, "{}"); code != 401 {
		t.Fatalf("unauthenticated POST after expiry = %d", code)
	}
	if _, code := svc.sub("healthcheck"); code != 1 {
		t.Fatalf("healthcheck after expiry = %d", code)
	}

	// Existing ciphertext is still delivered.
	f.smtp.SetReply(nil)
	if out, code := svc.sub("admin", "failed", "retry", id); code != 0 {
		t.Fatalf("retry in delivery-only mode = %d %s", code, out)
	}
	waitFor(t, "delivery in delivery-only mode", func() bool { return len(f.smtp.Messages()) == 1 })

	// Put another item into the queue's failed state for the restart check.
	if code := svc.stop(); code != 0 {
		t.Fatalf("exit code = %d", code)
	}

	// Starting with an expired key is not a startup failure.
	svc = f.start(f.env(key))
	if !strings.Contains(svc.out.String(), "delivery-only") {
		t.Errorf("startup log does not mention delivery-only mode:\n%s", svc.out.String())
	}
	if code, js := svc.post("exp-3", "t", "m"); code != 503 || js["error"] != "key_expired" {
		t.Fatalf("POST in delivery-only mode = %d %v", code, js)
	}
	if code, _, _ := svc.request("GET", "/healthz", nil, ""); code != 503 {
		t.Fatalf("healthz in delivery-only mode = %d", code)
	}
	if !svc.metric("pgp_mailer_key_valid 0") {
		t.Error("key_valid is not 0 in delivery-only mode")
	}
	if out, code := svc.sub("admin", "failed", "list"); code != 0 {
		t.Fatalf("admin API in delivery-only mode = %d %s", code, out)
	}
	svc.stop()
}

func TestStartupFailures(t *testing.T) {
	f := newFixture(t)
	good := pgptest.New(time.Now().Add(-time.Hour), 0)
	other := pgptest.New(time.Now().Add(-time.Hour), 0)
	revoked := pgptest.New(time.Now().Add(-time.Hour), 0)
	revoked.Revoke(time.Now().Add(-time.Minute))
	noEnc := pgptest.New(time.Now().Add(-time.Hour), 0)
	noEnc.Entity.Subkeys = nil

	cases := map[string][]string{
		"fingerprint mismatch":     f.env(good, "PGP_FINGERPRINT="+other.Fingerprint()),
		"revoked key":              f.env(revoked),
		"no encryption subkey":     f.env(noEnc),
		"unparsable key":           f.env(good, "PGP_PUBLIC_KEY_BASE64=aGVsbG8="),
		"secret key configured":    f.env(good, "PGP_PUBLIC_KEY_BASE64="+good.SecretBase64()),
		"missing setting":          f.env(good, "RECEIVER_OPS="),
		"active key quarantined":   f.env(good, "PGP_QUARANTINE_FINGERPRINTS="+good.Fingerprint()),
		"secret set twice":         f.env(good, "ADMIN_TOKEN_FILE=/nonexistent"),
		"plaintext SMTP requested": f.env(good, "SMTP_TLS_MODE=none"),
	}
	for name, env := range cases {
		svc := f.launch(env)
		select {
		case <-svc.done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: service kept running\n%s", name, svc.out.String())
		}
		if code := svc.cmd.ProcessState.ExitCode(); code != 1 {
			t.Errorf("%s: exit code %d, want 1", name, code)
		}
		if !strings.Contains(svc.out.String(), "startup failed") {
			t.Errorf("%s: no startup failure in log:\n%s", name, svc.out.String())
		}
		for _, secret := range []string{apiToken, adminToken, hmacSecret, smtpPass} {
			if strings.Contains(svc.out.String(), secret) {
				t.Errorf("%s: log contains a secret", name)
			}
		}
		if _, err := os.Stat(filepath.Join(f.queueDir, "queue.db")); err == nil {
			t.Errorf("%s: queue database was opened despite the startup failure", name)
		}
	}
}
