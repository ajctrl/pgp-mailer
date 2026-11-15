package smtpsend

import (
	"context"
	"net"
	"strings"
	"testing"

	"pgp-mailer/internal/smtptest"
)

const (
	user = "mailer"
	pass = "correct horse battery staple"
)

func start(t *testing.T, o smtptest.Options) *smtptest.Server {
	t.Helper()
	o.Username, o.Password = user, pass
	srv, err := smtptest.Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func sender(srv *smtptest.Server, mode, password string, trust bool) *Sender {
	cfg := Config{Host: srv.Host, Port: srv.Port, Mode: mode, Username: user, Password: password}
	if trust {
		cfg.RootCAs = srv.Roots
	}
	return New(cfg)
}

func TestSendOverBothTLSModes(t *testing.T) {
	msg := "Subject: x\r\n\r\n.leading dot\r\nbody\r\n"
	for _, c := range []struct {
		name string
		opts smtptest.Options
		mode string
	}{
		{"implicit TLS", smtptest.Options{Implicit: true}, ModeImplicit},
		{"STARTTLS", smtptest.Options{}, ModeStartTLS},
		{"STARTTLS with AUTH LOGIN only", smtptest.Options{AuthMechs: "LOGIN"}, ModeStartTLS},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := start(t, c.opts)
			sess, err := sender(srv, c.mode, pass, true).Open(context.Background())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			for i := 0; i < 2; i++ { // the session is reusable
				if err := sess.Send("a@example.com", "b@example.com", []byte(msg)); err != nil {
					t.Fatalf("Send %d: %v", i, err)
				}
			}
			sess.Close()
			got := srv.Messages()
			if len(got) != 2 || got[0].From != "a@example.com" || got[0].To != "b@example.com" {
				t.Fatalf("server received %+v", got)
			}
			if !strings.Contains(string(got[0].Data), "\n.leading dot\n") {
				t.Errorf("dot-stuffing broken: %q", got[0].Data)
			}
			if srv.Connections() != 1 {
				t.Errorf("connections = %d", srv.Connections())
			}
		})
	}
}

func TestErrorClassification(t *testing.T) {
	t.Run("untrusted certificate is transient", func(t *testing.T) {
		for _, c := range []struct {
			opts smtptest.Options
			mode string
		}{{smtptest.Options{Implicit: true}, ModeImplicit}, {smtptest.Options{}, ModeStartTLS}} {
			srv := start(t, c.opts)
			_, err := sender(srv, c.mode, pass, false).Open(context.Background())
			if err == nil {
				t.Fatal("Open succeeded without trusting the CA")
			}
			if r := Classify(err); r.Permanent || r.Kind != KindTLSCert {
				t.Errorf("%s: Classify(%v) = %+v", c.mode, err, r)
			}
			if len(srv.Messages()) != 0 {
				t.Error("mail was sent over an unverified connection")
			}
		}
	})

	t.Run("wrong password (535) is permanent", func(t *testing.T) {
		srv := start(t, smtptest.Options{})
		_, err := sender(srv, ModeStartTLS, "wrong", true).Open(context.Background())
		if r := Classify(err); err == nil || !r.Permanent || r.Code != 535 {
			t.Errorf("Classify(%v) = %+v", err, r)
		}
	})

	t.Run("STARTTLS is mandatory", func(t *testing.T) {
		srv := start(t, smtptest.Options{NoStartTLS: true})
		_, err := sender(srv, ModeStartTLS, pass, true).Open(context.Background())
		if r := Classify(err); err == nil || r.Permanent || r.Kind != KindNoStartTLS {
			t.Errorf("Classify(%v) = %+v", err, r)
		}
		if len(srv.Messages()) != 0 {
			t.Error("mail was sent without TLS")
		}
	})

	t.Run("4xx is transient, 5xx is permanent, session survives", func(t *testing.T) {
		srv := start(t, smtptest.Options{})
		sess, err := sender(srv, ModeStartTLS, pass, true).Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		code := 451
		srv.SetReply(func(stage string) (int, string) {
			if stage == "data" {
				return code, "try later"
			}
			return 0, ""
		})
		err = sess.Send("a@example.com", "b@example.com", []byte("x\r\n"))
		if r := Classify(err); err == nil || r.Permanent || !r.SMTP || r.Code != 451 {
			t.Errorf("451: Classify(%v) = %+v", err, r)
		}
		code = 554
		if err := sess.Reset(); err != nil {
			t.Fatal(err)
		}
		err = sess.Send("a@example.com", "b@example.com", []byte("x\r\n"))
		if r := Classify(err); err == nil || !r.Permanent || r.Code != 554 {
			t.Errorf("554: Classify(%v) = %+v", err, r)
		}
		srv.SetReply(nil)
		if err := sess.Reset(); err != nil {
			t.Fatal(err)
		}
		if err := sess.Send("a@example.com", "b@example.com", []byte("x\r\n")); err != nil {
			t.Fatalf("send after reset: %v", err)
		}
		if len(srv.Messages()) != 1 {
			t.Errorf("messages = %d", len(srv.Messages()))
		}
	})

	t.Run("connection refused is transient", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		_, err := New(Config{Host: "127.0.0.1", Port: port, Mode: ModeImplicit}).Open(context.Background())
		if r := Classify(err); err == nil || r.Permanent || r.Kind != KindConnect {
			t.Errorf("Classify(%v) = %+v", err, r)
		}
	})

	t.Run("DNS failure is transient", func(t *testing.T) {
		_, err := New(Config{Host: "smtp.invalid", Port: 465, Mode: ModeImplicit}).Open(context.Background())
		if r := Classify(err); err == nil || r.Permanent || r.Kind != KindDNS {
			t.Errorf("Classify(%v) = %+v", err, r)
		}
	})
}
