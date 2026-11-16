// pgp-mailer is a generic PGP mail notification service: it accepts
// notifications over HTTP, encrypts them to a configured OpenPGP public key,
// persists the ciphertext and delivers it over SMTP.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pgp-mailer/internal/cli"
	"pgp-mailer/internal/config"
	"pgp-mailer/internal/delivery"
	"pgp-mailer/internal/httpapi"
	"pgp-mailer/internal/metrics"
	"pgp-mailer/internal/pgpkey"
	"pgp-mailer/internal/smtpsend"
	"pgp-mailer/internal/store"
)

const (
	shutdownGrace = 30 * time.Second
	sweepInterval = time.Minute
	keyCheckEvery = 15 * time.Second
)

const usage = `usage:
  pgp-mailer [serve]        run the service
  pgp-mailer healthcheck    query /healthz; exit 0 if healthy
  pgp-mailer admin ...      manage the failed and quarantine queues`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		os.Exit(serve())
	case "healthcheck":
		os.Exit(cli.Healthcheck(os.Getenv, os.Stderr))
	case "admin":
		os.Exit(cli.Admin(args, os.Getenv, os.Stdout, os.Stderr))
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

// newLogger writes JSON lines to stdout. slog's own level is emitted as
// "severity" so that "level" can carry the notification level.
func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Only slog's built-in attribute has a slog.Level value; a
			// "level" attribute passed by the code is left alone.
			if _, builtin := a.Value.Any().(slog.Level); builtin && len(groups) == 0 && a.Key == slog.LevelKey {
				a.Key = "severity"
			}
			return a
		},
	}))
}

func serve() int {
	log := newLogger()
	now := time.Now

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Error("startup failed", "stage", "config", "error", err.Error())
		return 1
	}

	// Key verification and a real encryption test come before anything
	// else: on any failure other than plain expiry neither intake nor the
	// delivery of the existing queue is started.
	key, err := pgpkey.Load(cfg.PublicKeyBase64, cfg.Fingerprint)
	if err != nil {
		log.Error("startup failed", "stage", "pgp_key", "error", err.Error())
		return 1
	}
	deliveryOnly := false
	switch err := key.Check(now()); {
	case err == nil:
		if err := key.SelfTest(now()); errors.Is(err, pgpkey.ErrExpired) {
			deliveryOnly = true
		} else if err != nil {
			log.Error("startup failed", "stage", "encryption_self_test", "error", err.Error())
			return 1
		}
	case errors.Is(err, pgpkey.ErrExpired):
		deliveryOnly = true
	default:
		log.Error("startup failed", "stage", "pgp_key", "error", err.Error())
		return 1
	}
	if deliveryOnly {
		log.Error("recipient key has expired: starting in delivery-only mode; new notifications are refused with 503",
			"fingerprint", key.Fingerprint())
	} else {
		log.Info("recipient key verified and encryption self-test passed", "fingerprint", key.Fingerprint())
	}

	st, err := store.Open(cfg.QueueDir, store.DefaultLimit)
	if err != nil {
		log.Error("startup failed", "stage", "queue", "error", err.Error())
		return 1
	}
	defer st.Close()

	// Quarantine happens before the first delivery attempt.
	moved, err := st.Quarantine(cfg.QuarantineFingerprints, now())
	if err != nil {
		log.Error("startup failed", "stage", "quarantine", "error", err.Error())
		return 1
	}
	if len(cfg.QuarantineFingerprints) > 0 {
		log.Warn("quarantine applied", "fingerprints", cfg.QuarantineFingerprints, "moved", moved)
	}

	sources := []string{}
	for _, input := range cfg.Inputs {
		if input.Auth == "hmac-sha256" {
			sources = append(sources, input.Source)
		}
	}
	for _, t := range cfg.APITokens {
		sources = append(sources, t.Name)
	}
	m := metrics.New(sources, []string{store.ReasonExpired, store.ReasonPermanent})

	worker := delivery.New(st, delivery.SMTP(smtpsend.New(smtpsend.Config{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Mode:     cfg.SMTPTLSMode,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
	})), m, log, now)

	api := httpapi.New(httpapi.Options{
		Config: cfg, Key: key, Store: st, Metrics: m, Log: log, Now: now, Wake: worker.Wake,
	})
	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("startup failed", "stage", "listen", "error", err.Error())
		return 1
	}

	sigCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()
	bgCtx, cancelBg := context.WithCancel(context.Background())
	defer cancelBg()

	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.Run(bgCtx)
	}()
	janitorDone := make(chan struct{})
	go func() {
		defer close(janitorDone)
		janitor(bgCtx, st, key, log, now, !deliveryOnly)
	}()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	log.Info("service started", "listen", cfg.ListenAddr, "delivery_only", deliveryOnly)

	exit := 0
	select {
	case <-sigCtx.Done():
		log.Info("shutdown requested")
	case err := <-serveErr:
		log.Error("http server stopped", "error", err.Error())
		exit = 1
	}

	// Stop intake, then give an SMTP transmission in progress up to the
	// grace period. Whatever is unfinished stays queued for the next start.
	api.Drain()
	cancelBg()
	graceCtx, cancelGrace := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancelGrace()
	httpDone := make(chan struct{})
	go func() {
		defer close(httpDone)
		if err := srv.Shutdown(graceCtx); err != nil {
			_ = srv.Close()
		}
	}()
	select {
	case <-workerDone:
	case <-graceCtx.Done():
		log.Warn("SMTP transmission did not finish within the grace period; it stays queued")
		worker.Abort()
		select {
		case <-workerDone:
		case <-time.After(5 * time.Second):
		}
	}
	<-httpDone
	<-janitorDone
	log.Info("service stopped")
	return exit
}

// janitor periodically removes expired failed/quarantined items and
// de-duplication records, and reports the moment the key expires while the
// service is running.
func janitor(ctx context.Context, st *store.Store, key *pgpkey.Key, log *slog.Logger, now func() time.Time, keyWasValid bool) {
	sweep := func() {
		res, err := st.Sweep(now())
		if err != nil {
			log.Error("sweep failed", "error", err.Error())
			return
		}
		if res.Failed+res.Quarantined > 0 {
			log.Info("retention sweep", "failed_deleted", res.Failed, "quarantined_deleted", res.Quarantined)
		}
	}
	sweep()
	sweepT := time.NewTicker(sweepInterval)
	defer sweepT.Stop()
	keyT := time.NewTicker(keyCheckEvery)
	defer keyT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweepT.C:
			sweep()
		case <-keyT.C:
			if keyWasValid && !key.Valid(now()) {
				keyWasValid = false
				log.Error("recipient key has expired: switching to delivery-only mode; new notifications are refused with 503",
					"fingerprint", key.Fingerprint())
			}
		}
	}
}
