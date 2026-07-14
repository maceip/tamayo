package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// runDeliver is the MTA pipe adapter: an MTA (opensmtpd, postfix, exim)
// pipes a raw message to `issuerd deliver`, which forwards it to the
// issuerd webhook. Example opensmtpd.conf:
//
//	action "verify" mda "/usr/local/bin/issuerd deliver --url http://127.0.0.1:8788 --secret-file /etc/issuerd/webhook.secret" user issuerd
//	match from any for rcpt-to regex "^verify\+.*@secure\.build$" action "verify"
func runDeliver(args []string) int {
	fs := flag.NewFlagSet("issuerd deliver", flag.ContinueOnError)
	url := fs.String("url", envOr("ISSUERD_URL", "http://127.0.0.1:8788"), "issuerd base URL")
	secret := fs.String("secret", envOr("ISSUERD_WEBHOOK_SECRET", ""), "webhook shared secret")
	secretFile := fs.String("secret-file", "", "read the webhook secret from this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *secretFile != "" {
		data, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "deliver:", err)
			return 1
		}
		*secret = string(bytes.TrimSpace(data))
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxMailBytes))
	if err != nil {
		fmt.Fprintln(os.Stderr, "deliver: read stdin:", err)
		return 1
	}

	req, err := http.NewRequest(http.MethodPost, *url+"/v1/ingress/webhook", bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, "deliver:", err)
		return 1
	}
	req.Header.Set("Content-Type", "message/rfc822")
	if *secret != "" {
		req.Header.Set("X-Issuerd-Secret", *secret)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "deliver:", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		// Exit 0 anyway: a rejected verification mail (wrong tag, no DKIM)
		// must not bounce back to the sender or clog the MTA queue.
		fmt.Fprintf(os.Stderr, "deliver: issuerd said %d: %s\n", resp.StatusCode, bytes.TrimSpace(body))
	}
	return 0
}
