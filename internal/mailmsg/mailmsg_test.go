package mailmsg

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"pgp-mailer/internal/pgpkey"
	"pgp-mailer/internal/pgptest"
)

var now = time.Date(2026, 11, 15, 1, 2, 3, 0, time.UTC)

func build(t *testing.T, in Input) (*Built, *pgptest.Key) {
	t.Helper()
	tk := pgptest.New(now.Add(-time.Hour), 0)
	key, err := pgpkey.Load(tk.PublicBase64(), tk.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{
		From:    &mail.Address{Name: "PGP Mailer", Address: "mailer@example.com"},
		To:      &mail.Address{Address: "ops@example.net"},
		Encrypt: key.Encrypt,
	}
	built, err := b.Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return built, tk
}

func parts(t *testing.T, h mail.Header, body io.Reader, wantType string) (map[string]string, []*bytes.Buffer, []string) {
	t.Helper()
	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || mt != wantType {
		t.Fatalf("Content-Type = %q (%v), want %s", h.Get("Content-Type"), err, wantType)
	}
	mr := multipart.NewReader(body, params["boundary"])
	var bodies []*bytes.Buffer
	var types []string
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		io.Copy(&buf, p)
		bodies = append(bodies, &buf)
		types = append(types, p.Header.Get("Content-Type"))
	}
	return params, bodies, types
}

func TestBuildStructureAndProtectedHeaders(t *testing.T) {
	title := "アプリのエラー増加 " + strings.Repeat("長い件名", 30)
	message := "直近5分でエラーが15件発生しました。\nline2\r\nline3\n" + strings.Repeat("x", 2000)
	built, tk := build(t, Input{
		ID: "0123456789abcdef0123456789abcdef", Source: "app-1",
		Title: title, Message: message, Level: "error", Now: now,
	})

	// Wire format: CRLF only, no over-long lines, nothing sensitive outside.
	raw := string(built.Raw)
	if strings.Contains(strings.ReplaceAll(raw, "\r\n", ""), "\n") || strings.Contains(strings.ReplaceAll(raw, "\r\n", ""), "\r") {
		t.Fatal("message contains bare CR or LF")
	}
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) > 78 {
			t.Fatalf("line longer than 78 columns: %q", line)
		}
	}
	for _, leak := range []string{"エラー", "app-1", "line2", "error"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("outer message leaks %q", leak)
		}
	}

	outer, err := mail.ReadMessage(bytes.NewReader(built.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := outer.Header.Get("Subject"); got != OuterSubject {
		t.Errorf("outer Subject = %q", got)
	}
	wantID := "<0123456789abcdef0123456789abcdef@example.com>"
	if built.MessageID != wantID || outer.Header.Get("Message-ID") != wantID {
		t.Errorf("Message-ID = %q / %q", built.MessageID, outer.Header.Get("Message-ID"))
	}
	if d, err := outer.Header.Date(); err != nil || !d.Equal(now) {
		t.Errorf("Date = %v (%v)", d, err)
	}
	params, bodies, types := parts(t, outer.Header, outer.Body, "multipart/encrypted")
	if params["protocol"] != "application/pgp-encrypted" {
		t.Errorf("protocol = %q", params["protocol"])
	}
	if len(bodies) != 2 || types[0] != "application/pgp-encrypted" || !strings.HasPrefix(types[1], "application/octet-stream") {
		t.Fatalf("unexpected parts: %v", types)
	}
	if strings.TrimSpace(bodies[0].String()) != "Version: 1" {
		t.Errorf("version part = %q", bodies[0].String())
	}

	plain, err := tk.Decrypt(bodies[1].Bytes(), now)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	inner, err := mail.ReadMessage(bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	iparams, ibodies, itypes := parts(t, inner.Header, inner.Body, "multipart/mixed")
	if iparams["protected-headers"] != "v1" {
		t.Errorf("protected-headers = %q", iparams["protected-headers"])
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(inner.Header.Get("Subject"))
	if err != nil || subject != "[error] "+title {
		t.Errorf("protected Subject = %q (%v)", subject, err)
	}
	for _, h := range []string{"From", "To", "Date", "Message-ID"} {
		if inner.Header.Get(h) != outer.Header.Get(h) {
			t.Errorf("protected %s = %q, outer = %q", h, inner.Header.Get(h), outer.Header.Get(h))
		}
	}
	if len(ibodies) != 1 || itypes[0] != "text/plain; charset=utf-8" {
		t.Fatalf("inner parts: %v", itypes)
	}
	// NextRawPart leaves the transfer encoding in place.
	text, err := io.ReadAll(newBase64Reader(ibodies[0]))
	if err != nil {
		t.Fatal(err)
	}
	wantBody := "直近5分でエラーが15件発生しました。\r\nline2\r\nline3\r\n" + strings.Repeat("x", 2000) +
		"\r\n\r\n-- \r\npgp-mailer id=0123456789abcdef0123456789abcdef source=app-1 level=error\r\n"
	if string(text) != wantBody {
		t.Errorf("body mismatch:\n got %q\nwant %q", text, wantBody)
	}
}

func TestSubjectCannotSmuggleEncodedWords(t *testing.T) {
	got := encodeHeader("=?UTF-8?B?aGFja2Vk?=", 9)
	if !strings.HasPrefix(got, "=?UTF-8?B?") {
		t.Fatalf("not re-encoded: %q", got)
	}
	dec, err := new(mime.WordDecoder).DecodeHeader(got)
	if err != nil || dec != "=?UTF-8?B?aGFja2Vk?=" {
		t.Errorf("round trip = %q (%v)", dec, err)
	}
}

func TestEncryptFailureFailsBuild(t *testing.T) {
	tk := pgptest.New(now.Add(-48*time.Hour), 3600) // expired a day ago
	key, err := pgpkey.Load(tk.PublicBase64(), tk.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{From: &mail.Address{Address: "a@example.com"}, To: &mail.Address{Address: "b@example.com"}, Encrypt: key.Encrypt}
	if built, err := b.Build(Input{ID: "id", Title: "t", Message: "m", Level: "info", Now: now}); err == nil || built != nil {
		t.Fatalf("Build with an expired key returned %v, %v", built, err)
	}
}

func newBase64Reader(r io.Reader) io.Reader { return base64.NewDecoder(base64.StdEncoding, r) }

// TestGnuPGInterop encrypts to a key generated by the real gpg binary and
// lets gpg decrypt the result. Skipped when gpg is not installed.
func TestGnuPGInterop(t *testing.T) {
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}
	home, err := os.MkdirTemp("", "gpgi") // short path: gpg-agent socket limit
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	os.Chmod(home, 0o700)
	gpg := func(stdin []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(gpgPath, append([]string{"--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
		cmd.Stdin = bytes.NewReader(stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, stderr.String())
		}
		return out
	}
	defer exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()

	for _, algo := range []string{"default", "rsa3072"} {
		uid := algo + "@example.net"
		gpg(nil, "--quick-generate-key", uid, algo, "default", "1y")
		var fp string
		for _, line := range strings.Split(string(gpg(nil, "--with-colons", "--list-keys", uid)), "\n") {
			if f := strings.Split(line, ":"); f[0] == "fpr" && fp == "" {
				fp = f[9]
			}
		}
		if algo != "default" {
			// An explicit algorithm yields a sign/certify-only primary key,
			// which must be refused until an encryption subkey exists.
			if key, err := pgpkey.Load(base64.StdEncoding.EncodeToString(gpg(nil, "--export", uid)), fp); err != nil {
				t.Fatalf("%s: Load: %v", algo, err)
			} else if err := key.Check(time.Now()); err == nil || errors.Is(err, pgpkey.ErrExpired) {
				t.Fatalf("%s: key without encryption subkey: Check = %v", algo, err)
			}
			gpg(nil, "--quick-add-key", fp, algo, "encr", "1y")
		}
		pub := gpg(nil, "--export", uid)
		key, err := pgpkey.Load(base64.StdEncoding.EncodeToString(pub), fp)
		if err != nil {
			t.Fatalf("%s: Load: %v", algo, err)
		}
		at := time.Now()
		if err := key.SelfTest(at); err != nil {
			t.Fatalf("%s: SelfTest: %v", algo, err)
		}
		if _, ok := key.Expiry(at); !ok {
			t.Errorf("%s: 1y key reports no expiry", algo)
		}
		b := &Builder{From: &mail.Address{Address: "mailer@example.com"}, To: &mail.Address{Address: uid}, Encrypt: key.Encrypt}
		built, err := b.Build(Input{ID: "abc", Source: "app", Title: "日本語の件名", Message: "日本語の本文", Level: "warn", Now: at})
		if err != nil {
			t.Fatalf("%s: Build: %v", algo, err)
		}
		outer, _ := mail.ReadMessage(bytes.NewReader(built.Raw))
		_, bodies, _ := parts(t, outer.Header, outer.Body, "multipart/encrypted")
		plain := gpg(bodies[1].Bytes(), "--decrypt")
		inner, err := mail.ReadMessage(bytes.NewReader(plain))
		if err != nil {
			t.Fatalf("%s: gpg output is not a MIME entity: %v", algo, err)
		}
		subject, _ := new(mime.WordDecoder).DecodeHeader(inner.Header.Get("Subject"))
		_, ibodies, _ := parts(t, inner.Header, inner.Body, "multipart/mixed")
		text, _ := io.ReadAll(newBase64Reader(ibodies[0]))
		if subject != "[warn] 日本語の件名" || !strings.HasPrefix(string(text), "日本語の本文\r\n") {
			t.Errorf("%s: subject=%q body=%q", algo, subject, text)
		}
	}
}
