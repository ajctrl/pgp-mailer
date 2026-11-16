// Package config loads and validates the service configuration from the
// environment. Any missing or malformed setting is a startup failure.
package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"regexp"
	"strconv"
	"strings"

	"pgp-mailer/internal/smtpsend"
)

const (
	// ReservedSource is the fixed caller name of the Grafana adapter.
	ReservedSource = "grafana"
	// MinTokenLength is the minimum length of any bearer token or shared secret.
	MinTokenLength = 32

	DefaultListenAddr = ":8080"
)

// Token is a named API caller. Only the SHA-256 of the token is kept.
type Token struct {
	Name string
	Hash [32]byte
}

type Config struct {
	ListenAddr string
	Inputs     []Input

	PublicKeyBase64        string
	Fingerprint            string   // upper-case hex, no spaces
	QuarantineFingerprints []string // same normalisation

	SMTPHost     string
	SMTPPort     int
	SMTPTLSMode  string
	SMTPUsername string
	SMTPPassword string

	MailFrom    *mail.Address
	ReceiverOps *mail.Address

	APITokens         []Token
	GrafanaHMACSecret []byte
	AdminTokenHash    [32]byte

	QueueDir string
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	hexRe  = regexp.MustCompile(`^[0-9A-F]+$`)
)

// Load reads the configuration through getenv (os.Getenv in production).
// Error messages name the offending variable but never include its value.
func Load(getenv func(string) string) (*Config, error) {
	l := &loader{getenv: getenv}
	c := &Config{}

	c.ListenAddr = strings.TrimSpace(getenv("LISTEN_ADDR"))
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}

	c.PublicKeyBase64 = l.required("PGP_PUBLIC_KEY_BASE64")
	if fp := l.required("PGP_FINGERPRINT"); fp != "" {
		n, err := NormalizeFingerprint(fp)
		if err != nil {
			l.fail("PGP_FINGERPRINT: %v", err)
		}
		c.Fingerprint = n
	}
	for _, part := range splitList(getenv("PGP_QUARANTINE_FINGERPRINTS")) {
		n, err := NormalizeFingerprint(part)
		if err != nil {
			l.fail("PGP_QUARANTINE_FINGERPRINTS: %v", err)
			continue
		}
		if n == c.Fingerprint {
			l.fail("PGP_QUARANTINE_FINGERPRINTS must not contain PGP_FINGERPRINT (the active key cannot be quarantined)")
		}
		c.QuarantineFingerprints = append(c.QuarantineFingerprints, n)
	}

	c.SMTPHost = l.required("SMTP_HOST")
	// A colon is only valid inside an IPv6 address: "host:port" and
	// "[::1]" would otherwise pass here and fail on every connection.
	if strings.ContainsAny(c.SMTPHost, " \t\r\n/[]") ||
		(strings.Contains(c.SMTPHost, ":") && net.ParseIP(c.SMTPHost) == nil) {
		l.fail("SMTP_HOST must be a bare host name or IP address; the port belongs in SMTP_PORT")
	}
	if p := l.required("SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			l.fail("SMTP_PORT must be a port number between 1 and 65535")
		}
		c.SMTPPort = n
	}
	switch mode := l.required("SMTP_TLS_MODE"); mode {
	case "":
	case smtpsend.ModeImplicit, smtpsend.ModeStartTLS:
		c.SMTPTLSMode = mode
	default:
		l.fail("SMTP_TLS_MODE must be %q or %q", smtpsend.ModeImplicit, smtpsend.ModeStartTLS)
	}
	c.SMTPUsername = l.required("SMTP_USERNAME")
	c.SMTPPassword = l.secret("SMTP_PASSWORD")

	c.MailFrom = l.address("MAIL_FROM")
	c.ReceiverOps = l.address("RECEIVER_OPS")

	c.Inputs = DefaultInputs()
	if file := strings.TrimSpace(getenv("INPUTS_FILE")); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			l.fail("INPUTS_FILE: cannot read file")
		} else {
			inputs, err := ParseInputs(raw)
			if err != nil {
				l.fail("INPUTS_FILE: %v", err)
			} else {
				c.Inputs = inputs
			}
		}
	}
	needsBearer := false
	for _, input := range c.Inputs {
		if input.Auth == "bearer" {
			needsBearer = true
		}
	}
	if needsBearer {
		if raw := l.secret("API_TOKENS"); raw != "" {
			tokens, err := parseTokens(raw)
			if err != nil {
				l.fail("API_TOKENS: %v", err)
			}
			c.APITokens = tokens
		}
	}
	for i := range c.Inputs {
		input := &c.Inputs[i]
		if input.Auth == "hmac-sha256" {
			secret := l.secret(input.SecretEnv)
			if len(secret) < MinTokenLength {
				l.fail("%s must be at least %d characters", input.SecretEnv, MinTokenLength)
			}
			input.Secret = []byte(secret)
			if input.SecretEnv == "GRAFANA_HMAC_SECRET" {
				c.GrafanaHMACSecret = input.Secret
			}
		}
		if input.Caller != "" {
			found := false
			for _, t := range c.APITokens {
				if t.Name == input.Caller {
					found = true
				}
			}
			if input.Auth != "bearer" || !found {
				l.fail("input %s: caller must name an API_TOKENS entry", input.Path)
			}
		}
	}
	if s := l.secret("ADMIN_TOKEN"); s != "" {
		if err := checkToken(s); err != nil {
			l.fail("ADMIN_TOKEN: %v", err)
		}
		c.AdminTokenHash = sha256.Sum256([]byte(s))
		for _, t := range c.APITokens {
			if t.Hash == c.AdminTokenHash {
				l.fail("ADMIN_TOKEN must differ from every token in API_TOKENS")
			}
		}
	}

	c.QueueDir = l.required("QUEUE_DIR")

	if len(l.errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(l.errs...))
	}
	return c, nil
}

// NormalizeFingerprint strips spaces and an optional 0x prefix and upper-cases
// the value. Only full fingerprints are accepted (40 hex digits for v4 keys,
// 64 for v6); short and long key IDs are rejected.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToUpper(strings.Join(strings.Fields(s), ""))
	s = strings.TrimPrefix(s, "0X")
	if !hexRe.MatchString(s) || (len(s) != 40 && len(s) != 64) {
		return "", errors.New("must be a full fingerprint (40 or 64 hex digits)")
	}
	return s, nil
}

type loader struct {
	getenv func(string) string
	errs   []error
}

func (l *loader) fail(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *loader) required(name string) string {
	v := strings.TrimSpace(l.getenv(name))
	if v == "" {
		l.fail("%s is required", name)
	}
	return v
}

func (l *loader) secret(name string) string {
	v, err := Secret(l.getenv, name)
	if err != nil {
		l.errs = append(l.errs, err)
	}
	return v
}

// Secret reads the secret NAME or, for Docker secrets, the file named by
// NAME_FILE. Setting both is an error, as is setting neither. The value is
// used exactly as given, except that the line ending which editors and
// `echo` put at the end of a secret file is dropped. The server and the
// admin subcommand both read secrets through this function.
func Secret(getenv func(string) string, name string) (string, error) {
	direct := getenv(name)
	path := strings.TrimSpace(getenv(name + "_FILE"))
	switch {
	case direct != "" && path != "":
		return "", fmt.Errorf("%s and %s_FILE are both set; use only one", name, name)
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("%s_FILE: cannot read file: %v", name, err)
		}
		v := strings.TrimRight(string(b), "\r\n")
		if v == "" {
			return "", fmt.Errorf("%s_FILE: file is empty", name)
		}
		return v, nil
	case direct == "":
		return "", fmt.Errorf("%s (or %s_FILE) is required", name, name)
	}
	return direct, nil
}

func (l *loader) address(name string) *mail.Address {
	v := l.required(name)
	if v == "" {
		return nil
	}
	a, err := mail.ParseAddress(v)
	if err != nil || !strings.Contains(a.Address, "@") {
		l.fail("%s must be a single valid mail address", name)
		return nil
	}
	return a
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func checkToken(tok string) error {
	if len(tok) < MinTokenLength {
		return fmt.Errorf("token must be at least %d characters", MinTokenLength)
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= 0x20 || tok[i] > 0x7e {
			return errors.New("token must consist of printable ASCII without spaces")
		}
	}
	return nil
}

func parseTokens(raw string) ([]Token, error) {
	parts := splitList(raw)
	if len(parts) == 0 {
		return nil, errors.New("at least one name:token pair is required")
	}
	var out []Token
	names := map[string]bool{}
	hashes := map[[32]byte]bool{}
	for i, p := range parts {
		name, tok, ok := strings.Cut(p, ":")
		if !ok {
			return nil, fmt.Errorf("entry %d: expected name:token", i+1)
		}
		if !nameRe.MatchString(name) {
			return nil, fmt.Errorf("entry %d: name must match [a-z0-9-]{1,32}", i+1)
		}
		if name == ReservedSource {
			return nil, fmt.Errorf("entry %d: name %q is reserved", i+1, ReservedSource)
		}
		if err := checkToken(tok); err != nil {
			return nil, fmt.Errorf("entry %d (%s): %v", i+1, name, err)
		}
		h := sha256.Sum256([]byte(tok))
		if names[name] {
			return nil, fmt.Errorf("duplicate name %q", name)
		}
		if hashes[h] {
			return nil, fmt.Errorf("entry %d (%s): token is used more than once", i+1, name)
		}
		names[name], hashes[h] = true, true
		out = append(out, Token{Name: name, Hash: h})
	}
	return out, nil
}
