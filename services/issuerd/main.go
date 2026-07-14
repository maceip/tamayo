// Command issuerd is the mailproof reference issuer: a tamayo token issuer
// gated on proof of mailbox control, packaged as a single network service.
//
// It speaks HTTP (sessions, mint, issuer discovery) and — depending on
// configuration — receives verification emails over an embedded SMTP
// listener, an MTA pipe (`issuerd deliver`), or an HTTPS webhook fed by an
// inbound-email provider. Operators who cannot receive mail at all can run
// the code direction instead, which only needs an outbound SMTP relay.
//
// The privacy contract: the plaintext email address lives exactly long
// enough to compute the keyed mailbox bucket (HMAC), then is dropped. Mint
// budgets, sessions and logs only ever hold the bucket.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "deliver" {
		os.Exit(runDeliver(os.Args[2:]))
	}

	cfg, err := configFromFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := newServer(cfg, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cfg.SMTPAddr != "" {
		go func() {
			if err := srv.serveSMTP(); err != nil {
				log.Error("smtp listener exited", "err", err)
				os.Exit(1)
			}
		}()
	}

	id := srv.issuer.TokenKeyID()
	fmt.Printf("issuerd — mailproof reference issuer\n")
	fmt.Printf("  http:          %s\n", cfg.HTTPAddr)
	if cfg.SMTPAddr != "" {
		fmt.Printf("  smtp ingress:  %s (domain %s)\n", cfg.SMTPAddr, cfg.MailDomain)
	}
	fmt.Printf("  verify addr:   %s+<session>@%s\n", cfg.VerifyLocalPart, cfg.MailDomain)
	fmt.Printf("  token_key_id:  %x\n", id[:8])
	fmt.Printf("  dev mode:      %v\n", cfg.Dev)

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Error("http server exited", "err", err)
		os.Exit(1)
	}
}

type config struct {
	HTTPAddr        string
	SMTPAddr        string
	MailDomain      string
	VerifyLocalPart string
	PublicBase      string
	WebhookSecret   string
	SeedFile        string
	PolicyFile      string
	Dev             bool

	// Outbound relay for the code direction. Empty RelayAddr disables it
	// (codes are printed to stderr in dev mode instead).
	RelayAddr string
	RelayUser string
	RelayPass string
	RelayFrom string

	SessionTTL time.Duration
}

func configFromFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("issuerd", flag.ContinueOnError)
	cfg := config{}
	fs.StringVar(&cfg.HTTPAddr, "http", envOr("ISSUERD_HTTP", ":8788"), "HTTP listen address")
	fs.StringVar(&cfg.SMTPAddr, "smtp", envOr("ISSUERD_SMTP", ""), "embedded SMTP ingress listen address (empty = disabled)")
	fs.StringVar(&cfg.MailDomain, "domain", envOr("ISSUERD_DOMAIN", "localhost"), "mail domain verification emails are addressed to")
	fs.StringVar(&cfg.VerifyLocalPart, "verify-local", envOr("ISSUERD_VERIFY_LOCAL", "verify"), "local part of the verification address")
	fs.StringVar(&cfg.PublicBase, "public-base", envOr("ISSUERD_PUBLIC_BASE", ""), "public base URL of this issuer (informational)")
	fs.StringVar(&cfg.WebhookSecret, "webhook-secret", envOr("ISSUERD_WEBHOOK_SECRET", ""), "shared secret required on POST /v1/ingress/webhook (empty = webhook disabled unless dev)")
	fs.StringVar(&cfg.SeedFile, "seed-file", envOr("ISSUERD_SEED_FILE", ""), "issuer key seed file (created if missing; empty = ephemeral key)")
	fs.StringVar(&cfg.PolicyFile, "policy", envOr("ISSUERD_POLICY", ""), "tokenauth policy JSON (empty = built-in dev policy)")
	fs.BoolVar(&cfg.Dev, "dev", os.Getenv("ISSUERD_DEV") == "1", "dev mode: webhook needs no secret, DKIM optional, codes print to stderr")
	fs.StringVar(&cfg.RelayAddr, "relay", envOr("ISSUERD_RELAY", ""), "outbound SMTP relay host:port for the code direction")
	fs.StringVar(&cfg.RelayUser, "relay-user", envOr("ISSUERD_RELAY_USER", ""), "outbound relay username")
	fs.StringVar(&cfg.RelayPass, "relay-pass", envOr("ISSUERD_RELAY_PASS", ""), "outbound relay password")
	fs.StringVar(&cfg.RelayFrom, "relay-from", envOr("ISSUERD_RELAY_FROM", ""), "From address for outbound verification codes")
	ttl := fs.Duration("session-ttl", 15*time.Minute, "session lifetime")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	cfg.SessionTTL = *ttl
	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
