package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
	"github.com/maceip/tamayo/tokenservice"
)

// server is the reference issuer/verifier: real cryptography and policy,
// in-memory everything else. Spent burn nonces and seen presentation nonces
// die with the process — a product runtime must back both with durable,
// shared storage before this protects anything across restarts or replicas.
type server struct {
	issuer  *tokenprofile.Issuer
	svc     *tokenservice.Issuer
	policy  *tokenauth.Policy
	budgets *tokenauth.MemoryBudgetStore
	maxSkew time.Duration

	mu        sync.Mutex
	spentBurn map[[32]byte]bool // by burn nonce
	seenPvt   map[string]bool   // by origin \x00 presentation nonce
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	issuerPath := fs.String("issuer", "issuer.json", "issuer key-epoch file")
	policyPath := fs.String("policy", "", "tokenauth policy JSON (see 'tamayo example-policy')")
	addr := fs.String("addr", "127.0.0.1:8787", "listen address (loopback by default; this is a reference runtime)")
	maxSkew := fs.Duration("max-skew", 2*time.Minute, "allowed presentation timestamp skew")
	fs.Parse(args)
	if *policyPath == "" {
		return errors.New("serve: -policy is required (generate one with 'tamayo example-policy')")
	}

	issuer, err := loadIssuer(*issuerPath)
	if err != nil {
		return err
	}
	rawPolicy, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	policy, err := tokenauth.CompileJSON(rawPolicy)
	if err != nil {
		return fmt.Errorf("policy %s: %w", *policyPath, err)
	}
	svc, err := tokenservice.NewIssuer(issuer, nil)
	if err != nil {
		return err
	}

	s := &server{
		issuer:    issuer,
		svc:       svc,
		policy:    policy,
		budgets:   tokenauth.NewMemoryBudgetStore(),
		maxSkew:   *maxSkew,
		spentBurn: make(map[[32]byte]bool),
		seenPvt:   make(map[string]bool),
	}
	id := issuer.TokenKeyID()
	fmt.Printf("tamayo reference issuer/verifier\n  addr:         http://%s\n  key_version:  %d\n  token_key_id: %s\n  policy mode:  %s\n  state:        in-memory only (spent set + budgets are lost on exit)\n",
		*addr, issuer.KeyVersion(), hex.EncodeToString(id[:]), policy.Mode())
	return http.ListenAndServe(*addr, s.routes())
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /v1/issuer", s.handleIssuerInfo)
	mux.HandleFunc("POST /v1/blind-sign", s.handleBlindSign)
	mux.HandleFunc("POST /v1/verify/burn", s.handleVerifyBurn)
	mux.HandleFunc("POST /v1/verify/private-identity", s.handleVerifyPvt)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return false
	}
	return true
}

func (s *server) handleIssuerInfo(w http.ResponseWriter, _ *http.Request) {
	id := s.issuer.TokenKeyID()
	writeJSON(w, http.StatusOK, map[string]any{
		"algorithm":               tokenprofile.Algorithm,
		"key_version":             s.issuer.KeyVersion(),
		"token_key_id_hex":        hex.EncodeToString(id[:]),
		"expanded_public_key_b64": base64.RawURLEncoding.EncodeToString(s.issuer.ExpandedPublicKey()),
		"compact_public_key_b64":  base64.RawURLEncoding.EncodeToString(s.issuer.CompactPublicKey()),
	})
}

// blindSignRequest carries what a real deployment's attester/product layer
// would assemble: the caller's evidence-derived subject and eligibility,
// plus the blinded targets. The binding is computed here from the presented
// batch, exactly as the eat-pass issuer does.
type blindSignRequest struct {
	TokenFamily string                  `json:"token_family"`
	BlindedB64  []string                `json:"blinded_b64"`
	Subject     tokenauth.Subject       `json:"subject"`
	Eligibility []tokenauth.Eligibility `json:"eligibility"`
	Origin      string                  `json:"origin,omitempty"`
	Address     string                  `json:"address,omitempty"`
}

func (s *server) handleBlindSign(w http.ResponseWriter, r *http.Request) {
	var req blindSignRequest
	if !readJSON(w, r, &req) {
		return
	}
	blinded := make([][]byte, len(req.BlindedB64))
	for i, b := range req.BlindedB64 {
		var err error
		if blinded[i], err = base64.RawURLEncoding.DecodeString(b); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("blinded_b64[%d]: %v", i, err)})
			return
		}
	}
	binding := tokenprofile.BindingOf(blinded)
	now := time.Now()
	decision := s.policy.AuthorizeMint(tokenauth.MintRequest{
		Subject:     req.Subject,
		Eligibility: req.Eligibility,
		TokenFamily: tokenauth.TokenFamily(req.TokenFamily),
		Count:       len(blinded),
		KeyVersion:  s.issuer.KeyVersion(),
		Origin:      req.Origin,
		Address:     req.Address,
		Binding:     binding[:],
	}, s.budgets, now)
	if !decision.Allow {
		writeJSON(w, http.StatusForbidden, map[string]any{"decision": decision})
		return
	}
	sigs, err := s.svc.SignAuthorizedBlind(tokenservice.BlindMintRequest{
		Decision: decision,
		Family:   tokenauth.TokenFamily(req.TokenFamily),
		Blinded:  blinded,
		Now:      now,
	})
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": err.Error(), "decision": decision})
		return
	}
	out := make([]string, len(sigs))
	for i, sig := range sigs {
		out[i] = base64.RawURLEncoding.EncodeToString(sig)
	}
	writeJSON(w, http.StatusOK, map[string]any{"blind_signatures_b64": out, "decision": decision})
}

type verifyBurnRequest struct {
	TokenB64     string `json:"token_b64"`
	ChallengeB64 string `json:"challenge_b64"` // the raw origin challenge; digested here
}

func (s *server) handleVerifyBurn(w http.ResponseWriter, r *http.Request) {
	var req verifyBurnRequest
	if !readJSON(w, r, &req) {
		return
	}
	tokenBytes, err := base64.RawURLEncoding.DecodeString(req.TokenB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token_b64: " + err.Error()})
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(req.ChallengeB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_b64: " + err.Error()})
		return
	}
	token, err := tokenprofile.ParseBurnToken(tokenBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.issuer.VerifyBurnToken(token, sha256.Sum256(challenge)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	spent := s.spentBurn[token.Nonce]
	if !spent {
		s.spentBurn[token.Nonce] = true
	}
	s.mu.Unlock()
	if spent {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "token already spent"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type verifyPvtRequest struct {
	TokenB64     string `json:"token_b64"`
	Origin       string `json:"origin"`
	NonceB64     string `json:"nonce_b64"` // 32-byte server nonce issued to the holder
	IssuedAt     int64  `json:"issued_at"`
	SignatureB64 string `json:"signature_b64"`
}

func (s *server) handleVerifyPvt(w http.ResponseWriter, r *http.Request) {
	var req verifyPvtRequest
	if !readJSON(w, r, &req) {
		return
	}
	tokenBytes, err := base64.RawURLEncoding.DecodeString(req.TokenB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token_b64: " + err.Error()})
		return
	}
	token, err := tokenprofile.ParsePrivateIdentityToken(tokenBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(req.NonceB64)
	if err != nil || len(nonceBytes) != 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce_b64 must be 32 base64url bytes"})
		return
	}
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	signature, err := base64.RawURLEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signature_b64: " + err.Error()})
		return
	}

	replayKey := req.Origin + "\x00" + string(nonce[:])
	s.mu.Lock()
	seen := s.seenPvt[replayKey]
	if !seen {
		s.seenPvt[replayKey] = true
	}
	s.mu.Unlock()
	if seen {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "presentation nonce already used for this origin"})
		return
	}

	pseudonym, err := s.issuer.VerifyPrivateIdentityPresentation(tokenprofile.PrivateIdentityPresentation{
		Token:     token,
		Origin:    req.Origin,
		Nonce:     nonce,
		IssuedAt:  req.IssuedAt,
		Signature: signature,
	}, time.Now(), s.maxSkew)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pseudonym_hex": hex.EncodeToString(pseudonym[:])})
}
