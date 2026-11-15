// Package smtpsend hands messages to an SMTP server over verified TLS
// (implicit TLS or mandatory STARTTLS) and classifies failures.
package smtpsend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ModeImplicit = "implicit"
	ModeStartTLS = "starttls"

	dialTimeout    = 15 * time.Second
	sessionTimeout = 30 * time.Second // greeting, EHLO, STARTTLS, AUTH
	messageTimeout = 60 * time.Second // MAIL .. end of DATA
)

// Error kinds reported by Classify for non-SMTP failures.
const (
	KindSMTP       = "smtp"
	KindTLSCert    = "tls_certificate"
	KindTLS        = "tls"
	KindDNS        = "dns"
	KindTimeout    = "timeout"
	KindConnect    = "connect"
	KindNoStartTLS = "starttls_unavailable"
	KindNoAuth     = "auth_unavailable"
	KindIO         = "io"
)

var (
	errNoStartTLS = errors.New("server does not offer STARTTLS")
	errNoAuth     = errors.New("server offers no supported AUTH mechanism")
)

type Config struct {
	Host     string
	Port     int
	Mode     string
	Username string
	Password string

	// RootCAs overrides the system trust store (tests only).
	RootCAs *x509.CertPool
}

// Sender opens SMTP sessions.
type Sender struct{ cfg Config }

func New(cfg Config) *Sender { return &Sender{cfg: cfg} }

// Session is one authenticated SMTP connection.
type Session struct {
	once   sync.Once
	conn   net.Conn
	client *smtp.Client
}

func helloName() string {
	h, err := os.Hostname()
	if err != nil || h == "" || strings.ContainsAny(h, " \t\r\n") {
		return "localhost"
	}
	return h
}

// Open connects, negotiates TLS with certificate verification and
// authenticates. Cancelling ctx aborts the dial.
func (s *Sender) Open(ctx context.Context) (*Session, error) {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	tlsCfg := &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: s.cfg.RootCAs}

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(sessionTimeout))

	if s.cfg.Mode == ModeImplicit {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sess := &Session{conn: conn, client: c}
	if err := c.Hello(helloName()); err != nil {
		sess.Close()
		return nil, err
	}
	if s.cfg.Mode == ModeStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			sess.Close()
			return nil, errNoStartTLS
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			sess.Close()
			return nil, err
		}
	}
	if _, ok := c.TLSConnectionState(); !ok {
		sess.Close()
		return nil, errors.New("internal error: SMTP session is not encrypted")
	}
	ok, mechs := c.Extension("AUTH")
	if !ok {
		sess.Close()
		return nil, errNoAuth
	}
	var auth smtp.Auth
	switch fields := strings.Fields(strings.ToUpper(mechs)); {
	case slices.Contains(fields, "PLAIN"):
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	case slices.Contains(fields, "LOGIN"):
		auth = &loginAuth{s.cfg.Username, s.cfg.Password}
	default:
		sess.Close()
		return nil, errNoAuth
	}
	if err := c.Auth(auth); err != nil {
		sess.Close()
		return nil, err
	}
	return sess, nil
}

// Send transmits one message. A nil error means the server accepted it
// after the final dot. After a non-SMTP error the session is unusable.
func (s *Session) Send(from, to string, msg []byte) error {
	_ = s.conn.SetDeadline(time.Now().Add(messageTimeout))
	if err := s.client.Mail(from); err != nil {
		return err
	}
	if err := s.client.Rcpt(to); err != nil {
		return err
	}
	w, err := s.client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}

// Reset aborts the current mail transaction so the session can be reused.
func (s *Session) Reset() error {
	_ = s.conn.SetDeadline(time.Now().Add(sessionTimeout))
	return s.client.Reset()
}

// Close ends the session politely (QUIT) and closes the connection.
func (s *Session) Close() {
	s.once.Do(func() {
		_ = s.conn.SetDeadline(time.Now().Add(5 * time.Second))
		_ = s.client.Quit()
	})
	_ = s.conn.Close()
}

// Abort closes the connection immediately; an in-flight Send fails. It is
// safe to call from another goroutine.
func (s *Session) Abort() { _ = s.conn.Close() }

// loginAuth implements the non-standard but widespread AUTH LOGIN. It is
// only ever used on a TLS-protected session (Open enforces that).
type loginAuth struct{ username, password string }

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch p := strings.ToLower(string(fromServer)); {
	case strings.HasPrefix(p, "username"):
		return []byte(a.username), nil
	case strings.HasPrefix(p, "password"):
		return []byte(a.password), nil
	}
	return nil, fmt.Errorf("unexpected AUTH LOGIN challenge")
}

// Result is the classification of a delivery error.
type Result struct {
	Permanent bool   // SMTP 5xx: do not retry
	SMTP      bool   // the server answered with an SMTP reply code
	Code      int    // SMTP reply code, 0 if none
	Kind      string // one of the Kind* constants
}

// Classify sorts an error into transient or permanent. Only SMTP 5xx
// replies are permanent; connection, DNS, timeout and TLS problems
// (including certificate verification failures) are transient.
func Classify(err error) Result {
	var tp *textproto.Error
	if errors.As(err, &tp) {
		return Result{Permanent: tp.Code >= 500 && tp.Code <= 599, SMTP: true, Code: tp.Code, Kind: KindSMTP}
	}
	var (
		certErr    *tls.CertificateVerificationError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
		dnsErr     *net.DNSError
		netErr     net.Error
		opErr      *net.OpError
		recErr     tls.RecordHeaderError
		alertErr   tls.AlertError
	)
	switch {
	case errors.Is(err, errNoStartTLS):
		return Result{Kind: KindNoStartTLS}
	case errors.Is(err, errNoAuth):
		return Result{Kind: KindNoAuth}
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidErr):
		return Result{Kind: KindTLSCert}
	case errors.As(err, &recErr), errors.As(err, &alertErr):
		return Result{Kind: KindTLS}
	case errors.As(err, &dnsErr):
		return Result{Kind: KindDNS}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return Result{Kind: KindTimeout}
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return Result{Kind: KindConnect}
	}
	return Result{Kind: KindIO}
}
