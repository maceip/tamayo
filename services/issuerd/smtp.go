package main

import (
	"io"
	"time"

	"github.com/emersion/go-smtp"
)

// serveSMTP runs the embedded SMTP ingress listener. It accepts mail for
// the verify address, hands the raw message to handleIncomingMail, and
// rejects everything else. This is for operators who can bind a port and
// publish an MX record; everyone else should use the webhook or pipe.
func (s *server) serveSMTP() error {
	backend := &smtpBackend{srv: s}
	server := smtp.NewServer(backend)
	server.Addr = s.cfg.SMTPAddr
	server.Domain = s.cfg.MailDomain
	server.ReadTimeout = 60 * time.Second
	server.WriteTimeout = 60 * time.Second
	server.MaxMessageBytes = maxMailBytes
	server.MaxRecipients = 4
	server.AllowInsecureAuth = false
	s.log.Info("smtp ingress listening", "addr", s.cfg.SMTPAddr, "domain", s.cfg.MailDomain)
	return server.ListenAndServe()
}

type smtpBackend struct {
	srv *server
}

func (b *smtpBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &smtpSession{srv: b.srv}, nil
}

type smtpSession struct {
	srv *server
}

func (s *smtpSession) Mail(_ string, _ *smtp.MailOptions) error { return nil }

func (s *smtpSession) Rcpt(_ string, _ *smtp.RcptOptions) error { return nil }

func (s *smtpSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxMailBytes))
	if err != nil {
		return err
	}
	if err := s.srv.handleIncomingMail(raw); err != nil {
		s.srv.log.Warn("smtp mail rejected", "err", err)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      err.Error(),
		}
	}
	return nil
}

func (s *smtpSession) Reset() {}

func (s *smtpSession) Logout() error { return nil }
