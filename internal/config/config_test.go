package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgp-mailer/internal/smtpsend"
)

const (
	fpA = "0123456789ABCDEF0123456789ABCDEF01234567"
	fpB = "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
	tok = "0123456789abcdef0123456789abcdef"
)

func base() map[string]string {
	return map[string]string{
		"PGP_PUBLIC_KEY_BASE64": "AAAA",
		"PGP_FINGERPRINT":       "0123 4567 89ab cdef 0123  4567 89ab cdef 0123 4567",
		"SMTP_HOST":             "smtp.example.com",
		"SMTP_PORT":             "465",
		"SMTP_TLS_MODE":         "implicit",
		"SMTP_USERNAME":         "mailer",
		"SMTP_PASSWORD":         "pw",
		"MAIL_FROM":             "PGP Mailer <mailer@example.com>",
		"RECEIVER_OPS":          "ops@example.net",
		"API_TOKENS":            "app-a:a" + tok + ", app-b:b" + tok,
		"GRAFANA_HMAC_SECRET":   "g" + tok,
		"QUEUE_DIR":             "/var/lib/pgp-mailer",
		"ADMIN_TOKEN":           "x" + tok,
	}
}

func load(env map[string]string) (*Config, error) {
	return Load(func(k string) string { return env[k] })
}

func TestLoadValid(t *testing.T) {
	env := base()
	env["PGP_QUARANTINE_FINGERPRINTS"] = strings.ToLower(fpB) + " , "
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint != fpA || len(c.QuarantineFingerprints) != 1 || c.QuarantineFingerprints[0] != fpB {
		t.Errorf("fingerprints = %q %q", c.Fingerprint, c.QuarantineFingerprints)
	}
	if c.ListenAddr != DefaultListenAddr || c.SMTPPort != 465 || c.SMTPTLSMode != smtpsend.ModeImplicit {
		t.Errorf("config = %+v", c)
	}
	if c.MailFrom.Address != "mailer@example.com" || c.MailFrom.Name != "PGP Mailer" || c.ReceiverOps.Address != "ops@example.net" {
		t.Errorf("addresses = %v %v", c.MailFrom, c.ReceiverOps)
	}
	if len(c.APITokens) != 2 || c.APITokens[0].Name != "app-a" || c.APITokens[1].Name != "app-b" {
		t.Errorf("tokens = %+v", c.APITokens)
	}
}

func TestLoadRejectsMissingAndInvalid(t *testing.T) {
	for name := range base() {
		env := base()
		delete(env, name)
		if _, err := load(env); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("missing %s: err = %v", name, err)
		}
	}
	bad := map[string]map[string]string{
		"short key id":            {"PGP_FINGERPRINT": "0123456789ABCDEF"},
		"non-hex fingerprint":     {"PGP_FINGERPRINT": strings.Repeat("Z", 40)},
		"quarantine = active key": {"PGP_QUARANTINE_FINGERPRINTS": fpB + "," + fpA},
		"bad quarantine entry":    {"PGP_QUARANTINE_FINGERPRINTS": "nope"},
		"host with port":          {"SMTP_HOST": "smtp.example.com:465"},
		"host with path":          {"SMTP_HOST": "smtp.example.com/"},
		"bracketed IPv6 host":     {"SMTP_HOST": "[2001:db8::1]"},
		"IPv6 host with port":     {"SMTP_HOST": "[2001:db8::1]:465"},
		"port not a number":       {"SMTP_PORT": "smtp"},
		"port out of range":       {"SMTP_PORT": "70000"},
		"plain SMTP":              {"SMTP_TLS_MODE": "none"},
		"two addresses":           {"RECEIVER_OPS": "a@example.com, b@example.com"},
		"not an address":          {"MAIL_FROM": "mailer"},
		"token without name":      {"API_TOKENS": tok},
		"short token":             {"API_TOKENS": "app:short"},
		"bad name":                {"API_TOKENS": "App_A:" + tok},
		"name too long":           {"API_TOKENS": strings.Repeat("a", 33) + ":" + tok},
		"reserved name":           {"API_TOKENS": "grafana:" + tok},
		"duplicate name":          {"API_TOKENS": "app:a" + tok + ",app:b" + tok},
		"duplicate token":         {"API_TOKENS": "app-a:" + tok + ",app-b:" + tok},
		"empty token list":        {"API_TOKENS": " , "},
		"short admin token":       {"ADMIN_TOKEN": "short"},
		"admin token = API token": {"ADMIN_TOKEN": "a" + tok},
		"short hmac secret":       {"GRAFANA_HMAC_SECRET": "short"},
	}
	for name, override := range bad {
		env := base()
		for k, v := range override {
			env[k] = v
		}
		_, err := load(env)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// Secrets must never be echoed in error messages.
		for _, k := range []string{"API_TOKENS", "ADMIN_TOKEN", "GRAFANA_HMAC_SECRET", "SMTP_PASSWORD"} {
			if v := env[k]; len(v) >= MinTokenLength && strings.Contains(err.Error(), v) {
				t.Errorf("%s: error message contains the value of %s", name, k)
			}
		}
	}
}

func TestSMTPHostForms(t *testing.T) {
	for _, host := range []string{"smtp.example.com", "192.0.2.10", "2001:db8::1"} {
		env := base()
		env["SMTP_HOST"] = host
		if c, err := load(env); err != nil || c.SMTPHost != host {
			t.Errorf("%s: err = %v", host, err)
		}
	}
}

func TestSecretsAreTakenVerbatim(t *testing.T) {
	env := base()
	env["SMTP_PASSWORD"] = "  pass word\t"
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.SMTPPassword != "  pass word\t" {
		t.Errorf("password from the environment was altered: %q", c.SMTPPassword)
	}

	// From a file only the trailing line ending goes.
	p := filepath.Join(t.TempDir(), "smtp")
	if err := os.WriteFile(p, []byte("  pass word \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	delete(env, "SMTP_PASSWORD")
	env["SMTP_PASSWORD_FILE"] = p
	if c, err = load(env); err != nil {
		t.Fatal(err)
	}
	if c.SMTPPassword != "  pass word " {
		t.Errorf("password from a file was altered: %q", c.SMTPPassword)
	}

	// Tokens cannot contain spaces, so stray whitespace is a startup error
	// rather than a token that silently differs from the caller's.
	env = base()
	env["ADMIN_TOKEN"] = "x" + tok + " "
	if _, err := load(env); err == nil {
		t.Error("ADMIN_TOKEN with trailing space accepted")
	}
}

func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env := base()
	delete(env, "SMTP_PASSWORD")
	delete(env, "API_TOKENS")
	delete(env, "GRAFANA_HMAC_SECRET")
	delete(env, "ADMIN_TOKEN")
	env["SMTP_PASSWORD_FILE"] = write("smtp", "file-password\n")
	env["API_TOKENS_FILE"] = write("tokens", "app-a:a"+tok+"\n")
	env["GRAFANA_HMAC_SECRET_FILE"] = write("hmac", "g"+tok+"\r\n")
	env["ADMIN_TOKEN_FILE"] = write("admin", "x"+tok+"\n")
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.SMTPPassword != "file-password" || string(c.GrafanaHMACSecret) != "g"+tok || len(c.APITokens) != 1 {
		t.Errorf("secrets from files not loaded correctly")
	}

	for _, name := range []string{"SMTP_PASSWORD", "API_TOKENS", "GRAFANA_HMAC_SECRET", "ADMIN_TOKEN"} {
		both := map[string]string{}
		for k, v := range env {
			both[k] = v
		}
		both[name] = base()[name]
		if _, err := load(both); err == nil || !strings.Contains(err.Error(), name+"_FILE are both set") {
			t.Errorf("%s set twice: err = %v", name, err)
		}
	}

	env["ADMIN_TOKEN_FILE"] = filepath.Join(dir, "missing")
	if _, err := load(env); err == nil {
		t.Error("missing secret file accepted")
	}
	env["ADMIN_TOKEN_FILE"] = write("empty", "\n")
	if _, err := load(env); err == nil {
		t.Error("empty secret file accepted")
	}
}
