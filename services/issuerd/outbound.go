package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// defaultSendCode delivers a verification code for the code direction. With
// a relay configured it sends real mail; in dev mode without a relay it
// prints the code so local demos need no mail infrastructure at all.
func (s *server) defaultSendCode(to, code string) error {
	if s.cfg.RelayAddr == "" {
		if s.cfg.Dev {
			s.log.Info("DEV verification code (no relay configured)", "to", to, "code", code)
			return nil
		}
		return fmt.Errorf("no outbound relay configured (set ISSUERD_RELAY)")
	}

	from := s.cfg.RelayFrom
	if from == "" {
		from = s.cfg.VerifyLocalPart + "@" + s.cfg.MailDomain
	}
	msg := strings.NewReader(
		"From: " + from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: Your verification code\r\n" +
			"\r\n" +
			"Your verification code is: " + code + "\r\n" +
			"\r\nIt expires in 10 minutes. If you did not request it, ignore this mail.\r\n")

	host, _, err := net.SplitHostPort(s.cfg.RelayAddr)
	if err != nil {
		return fmt.Errorf("relay address: %w", err)
	}
	var auth sasl.Client
	if s.cfg.RelayUser != "" {
		auth = sasl.NewPlainClient("", s.cfg.RelayUser, s.cfg.RelayPass)
	}

	client, err := smtp.DialStartTLS(s.cfg.RelayAddr, nil)
	if err != nil {
		return fmt.Errorf("relay dial %s: %w", host, err)
	}
	defer client.Close()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("relay auth: %w", err)
		}
	}
	if err := client.SendMail(from, []string{to}, msg); err != nil {
		return fmt.Errorf("relay send: %w", err)
	}
	return nil
}
