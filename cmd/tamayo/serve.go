package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/maceip/tamayo/emailtoken"
	"github.com/maceip/tamayo/mailbox"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
	"github.com/maceip/tamayo/tokenservice"
	"github.com/maceip/tamayo/transparency"
)

// server is the reference issuer/verifier: real cryptography and policy,
// in-memory everything else. Spent burn nonces and seen presentation nonces
// die with the process — a product runtime must back both with durable,
// shared storage before this protects anything across restarts or replicas.
type server struct {
	issuer  *tokenprofile.Issuer
	svc     *tokenservice.Issuer
	policy  *tokenauth.Policy
	budgets tokenauth.BudgetStore
	maxSkew time.Duration
	journal *journal // nil = in-memory only
	evp     *evpRail // nil when the EVP rail is not mounted

	spent *tokenservice.MemorySpentStore
	kt    *ktState

	mu      sync.Mutex
	seenPvt map[string]bool // by origin \x00 presentation nonce
}

// ktState is the served key-transparency log: this runtime's single key
// epoch, signed at startup. Rotation (multiple records, durable log
// storage) is product work; serving the log is not.
type ktState struct {
	logPub  [32]byte
	records []transparency.KeyRecord
	sth     transparency.SignedHead
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	issuerPath := fs.String("issuer", "issuer.json", "issuer key-epoch file")
	policyPath := fs.String("policy", "", "tokenauth policy JSON (see 'tamayo example-policy')")
	addr := fs.String("addr", "127.0.0.1:8787", "listen address (loopback by default; this is a reference runtime)")
	maxSkew := fs.Duration("max-skew", 2*time.Minute, "allowed presentation timestamp skew")
	tlsCert := fs.String("tls-cert", "", "TLS certificate chain (PEM); with -tls-key, serve HTTPS")
	tlsKey := fs.String("tls-key", "", "TLS private key (PEM)")
	evpIssuer := fs.String("evp-issuer", "", "mount the EVP rail (/.well-known/email-verification) under this issuer id")
	publicBase := fs.String("public-base", "", "public base URL for EVP metadata (default: scheme://addr)")
	sendmail := fs.String("sendmail", "", "command to deliver mailbox codes: run as `cmd <address>` with the code on stdin (default: print to stderr, dev only)")
	codeTTL := fs.Duration("code-ttl", 10*time.Minute, "mailbox challenge code lifetime")
	policyPub := fs.String("policy-pub", "", "comma-separated trusted operator keys (hex); requires a verifying <policy>.sig sidecar")
	stateDir := fs.String("state-dir", "", "journal state (spends, nonces, budgets) here and replay on start (default: in-memory only)")
	fs.Parse(args)
	if *policyPath == "" {
		return errors.New("serve: -policy is required (generate one with 'tamayo example-policy')")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("serve: -tls-cert and -tls-key must be set together")
	}

	issuer, err := loadIssuer(*issuerPath)
	if err != nil {
		return err
	}
	rawPolicy, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	if *policyPub != "" {
		var trusted [][32]byte
		for _, h := range strings.Split(*policyPub, ",") {
			v, err := hex.DecodeString(strings.TrimSpace(h))
			if err != nil || len(v) != 32 {
				return fmt.Errorf("-policy-pub: keys must be 32 hex bytes")
			}
			var k [32]byte
			copy(k[:], v)
			trusted = append(trusted, k)
		}
		sidecar, err := os.ReadFile(*policyPath + ".sig")
		if err != nil {
			return fmt.Errorf("-policy-pub set but sidecar unreadable: %w (sign with 'tamayo sign-policy')", err)
		}
		if err := tokenauth.VerifyPolicySidecar(rawPolicy, string(sidecar), trusted); err != nil {
			return fmt.Errorf("policy %s: %w", *policyPath, err)
		}
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
		issuer:  issuer,
		svc:     svc,
		policy:  policy,
		budgets: tokenauth.NewMemoryBudgetStore(),
		maxSkew: *maxSkew,
		spent:   tokenservice.NewMemorySpentStore(),
		seenPvt: make(map[string]bool),
	}
	if err := s.initKT(); err != nil {
		return err
	}
	if *stateDir != "" {
		mem := s.spent
		seen := s.seenPvt
		j, err := openJournal(*stateDir, mem, seen, s.budgets)
		if err != nil {
			return fmt.Errorf("state-dir %s: %w", *stateDir, err)
		}
		s.journal = j
		s.budgets = &journaledBudgets{inner: s.budgets, j: j}
	}

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	if *evpIssuer != "" {
		base := *publicBase
		if base == "" {
			base = scheme + "://" + *addr
		}
		evtSigner, err := emailtoken.NewSigner(*evpIssuer, nil)
		if err != nil {
			return err
		}
		var gateKey [32]byte
		if _, err := rand.Read(gateKey[:]); err != nil {
			return err
		}
		deliver := func(address, code string) error {
			fmt.Fprintf(os.Stderr, "MAILBOX CODE (dev delivery) %s: %s\n", address, code)
			return nil
		}
		if *sendmail != "" {
			cmd := *sendmail
			deliver = func(address, code string) error {
				c := exec.Command(cmd, address)
				c.Stdin = strings.NewReader(code + "\n")
				return c.Run()
			}
		}
		s.evp = &evpRail{
			signer:       evtSigner,
			issuerID:     *evpIssuer,
			publicBase:   strings.TrimRight(base, "/"),
			store:        mailbox.NewChallengeStore(uint64(codeTTL.Seconds())),
			gateKey:      gateKey,
			budgetLimit:  16,
			budgetWindow: time.Hour,
			deliver:      deliver,
		}
	}

	id := issuer.TokenKeyID()
	fmt.Printf("tamayo reference issuer/verifier\n  addr:         %s://%s\n  key_version:  %d\n  token_key_id: %s\n  policy mode:  %s\n  state:        in-memory only (spent set + budgets are lost on exit)\n",
		scheme, *addr, issuer.KeyVersion(), hex.EncodeToString(id[:]), policy.Mode())
	if s.evp != nil {
		fmt.Printf("  evp issuer:   %s (EVT kid %s, discovery %s/.well-known/email-verification)\n",
			s.evp.issuerID, s.evp.signer.KID(), s.evp.publicBase)
	}
	if *tlsCert != "" {
		return http.ListenAndServeTLS(*addr, *tlsCert, *tlsKey, s.routes())
	}
	return http.ListenAndServe(*addr, s.routes())
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /v1/issuer", s.handleIssuerInfo)
	mux.HandleFunc("POST /v1/blind-sign", s.handleBlindSign)
	mux.HandleFunc("POST /v1/verify/burn", s.handleVerifyBurn)
	mux.HandleFunc("POST /v1/verify/private-identity", s.handleVerifyPvt)
	mux.HandleFunc("GET /v1/kt", s.handleKT)
	s.evpRoutes(mux)
	return mux
}

// initKT signs this runtime's key epoch into a fresh transparency log so
// clients can pin the log key and check inclusion/consistency.
func (s *server) initKT() error {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	signer, err := transparency.NewLogSigner(seed)
	if err != nil {
		return err
	}
	log := transparency.NewKeyLog()
	log.Append(s.issuer.KeyVersion(), s.issuer.TokenKeyID(), uint64(time.Now().Unix()))
	s.kt = &ktState{
		logPub:  signer.Public(),
		records: log.Records(),
		sth:     signer.Sign(log, nil),
	}
	return nil
}

func (s *server) handleKT(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"log_public_key_hex": hex.EncodeToString(s.kt.logPub[:]),
		"records":            s.kt.records,
		"signed_head":        s.kt.sth,
	})
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
	if err := s.spent.CheckAndMark(s.issuer.KeyVersion(), token.Nonce); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if err := s.journal.spend(s.issuer.KeyVersion(), token.Nonce); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "state journal: " + err.Error()})
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
	if err := s.journal.pvt(replayKey); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "state journal: " + err.Error()})
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
