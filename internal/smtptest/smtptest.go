// Package smtptest is a minimal in-process SMTP server with TLS for tests.
// It records accepted messages and lets a test inject reply codes.
package smtptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// Message is one mail accepted by the server.
type Message struct {
	From string
	To   string
	Data []byte
}

type Options struct {
	Implicit   bool   // implicit TLS instead of STARTTLS
	NoStartTLS bool   // do not advertise STARTTLS (plain mode only)
	AuthMechs  string // advertised after TLS; default "PLAIN LOGIN"
	Username   string
	Password   string
	// Reply may override the reply at a stage: "greeting", "auth", "mail",
	// "rcpt", "data" (after the final dot). Returning 0 keeps the default.
	Reply func(stage string) (code int, msg string)
}

type Server struct {
	Host  string
	Port  int
	CAPEM []byte
	Roots *x509.CertPool

	opts   Options
	ln     net.Listener
	tlsCfg *tls.Config

	mu    sync.Mutex
	msgs  []Message
	conns int
	wg    sync.WaitGroup
}

// Start launches a server on 127.0.0.1 with a fresh CA and leaf certificate.
func Start(opts Options) (*Server, error) {
	if opts.AuthMechs == "" {
		opts.AuthMechs = "PLAIN LOGIN"
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smtptest CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	s := &Server{
		Host:  "127.0.0.1",
		CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		Roots: roots,
		opts:  opts,
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER}, PrivateKey: leafKey,
		}}},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if opts.Implicit {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	s.ln = ln
	s.Port = ln.Addr().(*net.TCPAddr).Port
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *Server) Close() {
	s.ln.Close()
	s.wg.Wait()
}

// SetReply replaces the reply hook.
func (s *Server) SetReply(f func(stage string) (int, string)) {
	s.mu.Lock()
	s.opts.Reply = f
	s.mu.Unlock()
}

// Messages returns the mails accepted so far.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.msgs...)
}

// Connections returns how many connections were accepted.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			s.serve(c)
		}()
	}
}

func (s *Server) reply(stage string, defCode int, defMsg string) (int, string) {
	s.mu.Lock()
	f := s.opts.Reply
	s.mu.Unlock()
	if f != nil {
		if code, msg := f(stage); code != 0 {
			return code, msg
		}
	}
	return defCode, defMsg
}

func (s *Server) serve(c net.Conn) {
	tp := textproto.NewConn(c)
	secure := s.opts.Implicit
	authed := false
	var from, to string

	say := func(code int, msg string) { _ = tp.PrintfLine("%d %s", code, msg) }

	if code, msg := s.reply("greeting", 220, "smtptest ESMTP"); code != 220 {
		say(code, msg)
		return
	} else {
		say(code, msg)
	}
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			lines := []string{"smtptest"}
			if !secure && !s.opts.NoStartTLS {
				lines = append(lines, "STARTTLS")
			}
			if secure {
				lines = append(lines, "AUTH "+s.opts.AuthMechs)
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				_ = tp.PrintfLine("250%s%s", sep, l)
			}
		case "STARTTLS":
			if secure || s.opts.NoStartTLS {
				say(502, "not available")
				continue
			}
			say(220, "go ahead")
			tc := tls.Server(c, s.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, tp, secure = tc, textproto.NewConn(tc), true
		case "AUTH":
			if !secure {
				say(530, "must issue STARTTLS first")
				continue
			}
			mech, initial, _ := strings.Cut(arg, " ")
			var user, pass string
			switch strings.ToUpper(mech) {
			case "PLAIN":
				raw, _ := base64.StdEncoding.DecodeString(initial)
				parts := strings.Split(string(raw), "\x00")
				if len(parts) == 3 {
					user, pass = parts[1], parts[2]
				}
			case "LOGIN":
				say(334, base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, err := tp.ReadLine()
				if err != nil {
					return
				}
				say(334, base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, err := tp.ReadLine()
				if err != nil {
					return
				}
				ub, _ := base64.StdEncoding.DecodeString(u)
				pb, _ := base64.StdEncoding.DecodeString(p)
				user, pass = string(ub), string(pb)
			default:
				say(504, "unsupported mechanism")
				continue
			}
			if code, msg := s.reply("auth", 0, ""); code != 0 {
				say(code, msg)
				continue
			}
			if user != s.opts.Username || pass != s.opts.Password {
				say(535, "5.7.8 authentication failed")
				continue
			}
			authed = true
			say(235, "2.7.0 ok")
		case "MAIL":
			if !authed {
				say(530, "authentication required")
				continue
			}
			code, msg := s.reply("mail", 250, "ok")
			if code == 250 {
				from = addrOf(arg)
			}
			say(code, msg)
		case "RCPT":
			code, msg := s.reply("rcpt", 250, "ok")
			if code == 250 {
				to = addrOf(arg)
			}
			say(code, msg)
		case "DATA":
			if from == "" || to == "" {
				say(503, "bad sequence")
				continue
			}
			say(354, "end with <CRLF>.<CRLF>")
			data, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			code, msg := s.reply("data", 250, "queued")
			if code == 250 {
				s.mu.Lock()
				s.msgs = append(s.msgs, Message{From: from, To: to, Data: data})
				s.mu.Unlock()
			}
			from, to = "", ""
			say(code, msg)
		case "RSET":
			from, to = "", ""
			say(250, "ok")
		case "NOOP":
			say(250, "ok")
		case "QUIT":
			say(221, "bye")
			return
		default:
			say(500, fmt.Sprintf("unknown command %q", verb))
		}
	}
}

func addrOf(arg string) string {
	i, j := strings.Index(arg, "<"), strings.Index(arg, ">")
	if i < 0 || j < i {
		return ""
	}
	return arg[i+1 : j]
}
