package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/maceip/tamayo/mailbox"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
	"github.com/maceip/tamayo/tokenservice"
)

const (
	issuerKeyVersion = 1
	maxSessions      = 4096
	maxBodyBytes     = 1 << 16
)

var b64 = base64.RawURLEncoding

// builtinDevPolicy gates private-identity mints on the email gate with a
// small per-mailbox budget. The bucket is caller-derived: this service
// computes it from the *verified* sender, never from client input.
const builtinDevPolicy = `{
  "version": 1,
  "mode": "development",
  "defaults": {
    "allow_software_witness": true,
    "max_batch": 4,
    "authorization_ttl_seconds": 120
  },
  "token_families": {
    "private_identity": {
      "enabled": true,
      "allowed_gates": ["email"],
      "budget_group": "mailproof"
    }
  },
  "gates": {
    "email": {
      "enabled": true,
      "bucket_source": "caller"
    }
  },
  "budgets": {
    "mailproof": {
      "limit": 8,
      "window_seconds": 3600
    }
  }
}`

type sessionStatus string

const (
	statusPending  sessionStatus = "pending"
	statusVerified sessionStatus = "verified"
)

type session struct {
	ID        string
	Mode      string // "send" or "code"
	Status    sessionStatus
	Bucket    string // hex mailbox bucket once verified; never the address
	CreatedAt time.Time
	ExpiresAt time.Time
	Minted    bool
}

type server struct {
	cfg    config
	log    *slog.Logger
	issuer *tokenprofile.Issuer
	svc    *tokenservice.Issuer
	policy *tokenauth.Policy

	budgets tokenauth.BudgetStore
	codes   *mailbox.ChallengeStore
	gateKey [32]byte

	sendCode func(to, code string) error

	mu       sync.Mutex
	sessions map[string]*session
}

func newServer(cfg config, log *slog.Logger) (*server, error) {
	seed, err := loadOrCreateSeed(cfg.SeedFile)
	if err != nil {
		return nil, fmt.Errorf("issuer seed: %w", err)
	}
	issuer, err := tokenprofile.NewIssuer(issuerKeyVersion, seed)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	svc, err := tokenservice.NewIssuer(issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("token service: %w", err)
	}

	policyJSON := []byte(builtinDevPolicy)
	if cfg.PolicyFile != "" {
		policyJSON, err = os.ReadFile(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
	}
	policy, err := tokenauth.CompileJSON(policyJSON)
	if err != nil {
		return nil, fmt.Errorf("policy compile: %w", err)
	}

	var gateKey [32]byte
	if _, err := rand.Read(gateKey[:]); err != nil {
		return nil, fmt.Errorf("gate key: %w", err)
	}

	s := &server{
		cfg:      cfg,
		log:      log,
		issuer:   issuer,
		svc:      svc,
		policy:   policy,
		budgets:  tokenauth.NewMemoryBudgetStore(),
		codes:    mailbox.NewChallengeStore(uint64((10 * time.Minute).Seconds())),
		gateKey:  gateKey,
		sessions: make(map[string]*session),
	}
	s.sendCode = s.defaultSendCode
	return s, nil
}

func loadOrCreateSeed(path string) ([]byte, error) {
	const seedLen = 24 // mayo.Mayo1.SKSeedBytes
	if path == "" {
		return nil, nil // ephemeral: NewIssuer draws fresh entropy
	}
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != seedLen {
			return nil, fmt.Errorf("%s is %d bytes, want %d", path, len(data), seedLen)
		}
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed := make([]byte, seedLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return nil, err
	}
	return seed, nil
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /v1/issuer", s.handleIssuerInfo)
	mux.HandleFunc("POST /v1/sessions", s.handleCreateSession)
	mux.HandleFunc("GET /v1/sessions/{id}", s.handleGetSession)
	mux.HandleFunc("POST /v1/sessions/{id}/send-code", s.handleSendCode)
	mux.HandleFunc("POST /v1/sessions/{id}/verify-code", s.handleVerifyCode)
	mux.HandleFunc("POST /v1/sessions/{id}/mint", s.handleMint)
	mux.HandleFunc("POST /v1/ingress/webhook", s.handleWebhook)
	return mux
}

func (s *server) handleIssuerInfo(w http.ResponseWriter, _ *http.Request) {
	id := s.issuer.TokenKeyID()
	writeJSON(w, http.StatusOK, map[string]any{
		"algorithm":              tokenprofile.Algorithm,
		"key_version":            s.issuer.KeyVersion(),
		"token_key_id_hex":       hex.EncodeToString(id[:]),
		"compact_public_key_b64": b64.EncodeToString(s.issuer.CompactPublicKey()),
		"verify_address":         s.cfg.VerifyLocalPart + "+<session_tag>@" + s.cfg.MailDomain,
		"public_base":            s.cfg.PublicBase,
	})
}

type createSessionRequest struct {
	Mode string `json:"mode"` // "send" (default) or "code"
}

func (s *server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = "send"
	}
	if mode != "send" && mode != "code" {
		writeErr(w, http.StatusBadRequest, `mode must be "send" or "code"`)
		return
	}

	tag, err := randomTag()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "entropy")
		return
	}
	now := time.Now()
	sess := &session{
		ID:        tag,
		Mode:      mode,
		Status:    statusPending,
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}

	s.mu.Lock()
	s.gcLocked(now)
	if len(s.sessions) >= maxSessions {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "session table full, retry later")
		return
	}
	s.sessions[sess.ID] = sess
	s.mu.Unlock()

	resp := map[string]any{
		"session_id": sess.ID,
		"mode":       mode,
		"status":     sess.Status,
		"expires_at": sess.ExpiresAt.Unix(),
	}
	if mode == "send" {
		resp["verify_address"] = s.verifyAddress(sess.ID)
		resp["email_subject"] = "verify " + sess.ID
		resp["instructions"] = "Send an email (any body) from the mailbox you want to prove to verify_address. " +
			"The sending address is hashed into a rate-limit bucket and immediately discarded."
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) verifyAddress(sessionID string) string {
	return s.cfg.VerifyLocalPart + "+" + sessionID + "@" + s.cfg.MailDomain
}

func (s *server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown or expired session")
		return
	}
	s.mu.Lock()
	status := sess.Status
	minted := sess.Minted
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sess.ID,
		"mode":       sess.Mode,
		"status":     status,
		"minted":     minted,
		"expires_at": sess.ExpiresAt.Unix(),
	})
}

type sendCodeRequest struct {
	Email string `json:"email"`
}

func (s *server) handleSendCode(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown or expired session")
		return
	}
	if sess.Mode != "code" {
		writeErr(w, http.StatusConflict, `session mode is not "code"`)
		return
	}
	var req sendCodeRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	code, err := s.codes.Create(req.Email, sessionBinding(sess.ID), uint64(time.Now().Unix()))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.sendCode(req.Email, code); err != nil {
		s.log.Error("code delivery failed", "err", err)
		writeErr(w, http.StatusBadGateway, "could not deliver the verification code")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

type verifyCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func (s *server) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown or expired session")
		return
	}
	var req verifyCodeRequest
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	canonical, err := s.codes.Verify(req.Email, req.Code, sessionBinding(sess.ID), uint64(time.Now().Unix()))
	if err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	s.markVerified(sess, canonical)
	writeJSON(w, http.StatusOK, map[string]any{"status": statusVerified})
}

// markVerified computes the keyed bucket for the canonical address and
// drops the plaintext — the session only ever stores the bucket.
func (s *server) markVerified(sess *session, canonical string) {
	bucket := mailbox.BucketID(s.gateKey, canonical)
	s.mu.Lock()
	sess.Status = statusVerified
	sess.Bucket = hex.EncodeToString(bucket[:])
	s.mu.Unlock()
	s.log.Info("session verified", "session", sess.ID, "mode", sess.Mode, "bucket", sess.Bucket[:12])
}

func (s *server) getSession(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil, false
	}
	return sess, true
}

func (s *server) gcLocked(now time.Time) {
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

func sessionBinding(sessionID string) [32]byte {
	return sha256.Sum256([]byte("issuerd/session-binding\x00" + sessionID))
}

func randomTag() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return strings.ToLower(base64.RawURLEncoding.EncodeToString(raw[:])), nil
}

func readJSON(r *http.Request, v any) error {
	body := http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	defer body.Close()
	if err := json.NewDecoder(body).Decode(v); err != nil {
		if errors.Is(err, io.EOF) { // an entirely-empty body decodes as the zero value
			return nil
		}
		return fmt.Errorf("json: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
