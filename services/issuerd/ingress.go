package main

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/maceip/tamayo/mailbox"
)

const maxMailBytes = 1 << 20 // verification emails are one-liners; 1 MiB is generous

// handleIncomingMail is the single funnel every ingress adapter (embedded
// SMTP, MTA pipe via webhook, provider webhook) feeds raw RFC822 bytes into.
//
// Trust model: the *sender address* is only believed if the message carries
// a valid DKIM signature aligned with the From domain. In dev mode the DKIM
// requirement is dropped so local demos work without mail infrastructure.
func (s *server) handleIncomingMail(raw []byte) error {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	sessionID, err := s.sessionTagFromRecipients(msg)
	if err != nil {
		return err
	}
	sess, ok := s.getSession(sessionID)
	if !ok {
		return fmt.Errorf("no pending session for tag %q", sessionID)
	}
	if sess.Mode != "send" {
		return fmt.Errorf("session %q is not in send mode", sessionID)
	}

	fromAddr, err := senderAddress(msg)
	if err != nil {
		return err
	}
	if !s.cfg.Dev {
		if err := verifyAlignedDKIM(raw, fromAddr); err != nil {
			return fmt.Errorf("dkim: %w", err)
		}
	}

	canonical, err := canonicalOrErr(fromAddr)
	if err != nil {
		return err
	}
	if !s.markVerified(sess, canonical) {
		return fmt.Errorf("session %q is already verified", sessionID)
	}
	return nil
}

// sessionTagFromRecipients finds verify+<tag>@domain in To / Cc /
// Delivered-To / X-Original-To headers.
func (s *server) sessionTagFromRecipients(msg *mail.Message) (string, error) {
	prefix := s.cfg.VerifyLocalPart + "+"
	suffix := "@" + strings.ToLower(s.cfg.MailDomain)

	var candidates []string
	for _, header := range []string{"To", "Cc", "Delivered-To", "X-Original-To"} {
		value := msg.Header.Get(header)
		if value == "" {
			continue
		}
		if addrs, err := mail.ParseAddressList(value); err == nil {
			for _, a := range addrs {
				candidates = append(candidates, a.Address)
			}
		} else {
			candidates = append(candidates, value)
		}
	}
	for _, cand := range candidates {
		addr := strings.ToLower(strings.TrimSpace(cand))
		if !strings.HasSuffix(addr, suffix) {
			continue
		}
		local := strings.TrimSuffix(addr, suffix)
		if !strings.HasPrefix(local, prefix) {
			continue
		}
		if tag := strings.TrimPrefix(local, prefix); tag != "" {
			return tag, nil
		}
	}
	return "", fmt.Errorf("no %s+<session>%s recipient found", s.cfg.VerifyLocalPart, suffix)
}

func senderAddress(msg *mail.Message) (string, error) {
	from := msg.Header.Get("From")
	if from == "" {
		return "", fmt.Errorf("message has no From header")
	}
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return "", fmt.Errorf("parse From: %w", err)
	}
	return addr.Address, nil
}

// verifyAlignedDKIM requires at least one passing DKIM signature whose d=
// domain matches (or is a parent of) the From domain — the same alignment
// rule DMARC uses in relaxed mode.
func verifyAlignedDKIM(raw []byte, fromAddr string) error {
	_, fromDomain, ok := strings.Cut(fromAddr, "@")
	if !ok {
		return fmt.Errorf("malformed From address")
	}
	fromDomain = strings.ToLower(fromDomain)

	verifications, err := dkim.Verify(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if len(verifications) == 0 {
		return fmt.Errorf("message carries no DKIM signature")
	}
	for _, v := range verifications {
		if v.Err != nil {
			continue
		}
		d := strings.ToLower(v.Domain)
		if d == fromDomain || strings.HasSuffix(fromDomain, "."+d) {
			return nil
		}
	}
	return fmt.Errorf("no valid DKIM signature aligned with %s", fromDomain)
}

func canonicalOrErr(addr string) (string, error) {
	canonical, err := mailbox.CanonicalEmail(addr)
	if err != nil {
		return "", fmt.Errorf("canonicalize sender: %w", err)
	}
	return canonical, nil
}

// handleWebhook accepts a raw RFC822 message body. It serves two ingress
// paths: the `issuerd deliver` MTA pipe and inbound-email providers that can
// forward raw MIME (Cloudflare Email Workers, Mailgun "store and notify",
// SendGrid inbound parse with raw checked).
func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WebhookSecret == "" && !s.cfg.Dev {
		writeErr(w, http.StatusForbidden, "webhook ingress is disabled: set ISSUERD_WEBHOOK_SECRET")
		return
	}
	if s.cfg.WebhookSecret != "" {
		got := r.Header.Get("X-Issuerd-Secret")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.WebhookSecret)) != 1 {
			writeErr(w, http.StatusForbidden, "bad webhook secret")
			return
		}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxMailBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if err := s.handleIncomingMail(raw); err != nil {
		s.log.Warn("webhook mail rejected", "err", err)
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
}
