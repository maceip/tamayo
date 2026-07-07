package main

// The EVP rail (draft-hardt email verification): the browser-facing issuer
// surface a feature-flagged Chrome discovers and calls. Ported from the
// reference implementation and wire-compatible with it: issuer metadata at
// /.well-known/email-verification, an EdDSA JWKS, and an issuance endpoint
// whose requests carry an RFC 9421 HTTP Message Signature under the
// browser's Ed25519 key (the `hwk` scheme with a fixed covered-component
// set). Mailbox control is proven with a mailed code bound to the browser
// key, so a phished code cannot be redeemed under a different holder key;
// each issued EVT charges the mailbox's per-window issuance budget.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/maceip/tamayo/emailtoken"
	"github.com/maceip/tamayo/mailbox"
)

const (
	// evpSigMaxAgeSecs bounds the RFC 9421 `created` skew.
	evpSigMaxAgeSecs = 60
	// evpCodeBindingDomain matches the reference: the mailed code is bound
	// to SHA-256(domain || browser_pub).
	evpCodeBindingDomain = "eat-pass/evp-code-binding\x00"
	// evpCovered is the fixed RFC 9421 covered-component set the issuance
	// endpoint requires (no cookies are ever set by this issuer).
	evpCovered = `("@method" "@authority" "@path" "signature-key")`
	// evpBudgetGroup names the EVT row's budget bucket group.
	evpBudgetGroup = "evt"
)

// evpRail is the state behind the three EVP endpoints.
type evpRail struct {
	signer       *emailtoken.Signer
	issuerID     string
	publicBase   string
	store        *mailbox.ChallengeStore
	gateKey      [32]byte
	budgetLimit  int
	budgetWindow time.Duration
	deliver      func(address, code string) error
}

func (s *server) evpRoutes(mux *http.ServeMux) {
	if s.evp == nil {
		return
	}
	mux.HandleFunc("GET /.well-known/email-verification", s.handleEVPMetadata)
	mux.HandleFunc("GET /email-verification/jwks", s.handleEVPJWKS)
	mux.HandleFunc("POST /email-verification/issuance", s.handleEVPIssuance)
}

func (s *server) handleEVPMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                       s.evp.issuerID,
		"issuance_endpoint":            s.evp.publicBase + "/email-verification/issuance",
		"jwks_uri":                     s.evp.publicBase + "/email-verification/jwks",
		"signing_alg_values_supported": []string{emailtoken.AlgEdDSA},
		"webauthn_supported":           false,
	})
}

func (s *server) handleEVPJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, emailtoken.JWKS{Keys: []emailtoken.JWK{s.evp.signer.JWK()}})
}

// evpCodeBinding ties a mailed code to the browser key that will end up in
// the EVT's cnf.
func evpCodeBinding(browserPub [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(evpCodeBindingDomain))
	h.Write(browserPub[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type evpIssuanceBody struct {
	Email string `json:"email"`
	// Code is the mailed verification code — the reference runtime's
	// stand-in for the draft's provider login / WebAuthn, since we are not
	// the user's mail UI.
	Code string `json:"code,omitempty"`
}

func (s *server) handleEVPIssuance(w http.ResponseWriter, r *http.Request) {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "email-verification" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Sec-Fetch-Dest must be email-verification"})
		return
	}
	now := uint64(time.Now().Unix())
	browserPub, err := verifyEVPMessageSignature(r.Header, "POST", r.Host, "/email-verification/issuance", now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "http message signature: " + err.Error()})
		return
	}
	var body evpIssuanceBody
	if !readJSON(w, r, &body) {
		return
	}
	canonical, err := mailbox.CanonicalEmail(body.Email)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	binding := evpCodeBinding(browserPub)

	if body.Code == "" {
		// No proof of mailbox control yet — mail a code bound to this
		// browser key, mirroring the draft's re-request shape.
		code, err := s.evp.store.Create(canonical, binding, now)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.evp.deliver(canonical, code); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "code delivery: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "verification_code_sent"})
		return
	}

	canonical, err = s.evp.store.Verify(canonical, body.Code, binding, now)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}

	// An EVT costs one permit out of this mailbox's per-window budget —
	// the same bucket identity the blind rail charges.
	bucket := mailbox.BucketID(s.evp.gateKey, canonical)
	budgetKey := mailbox.Platform + ":" + base64.RawURLEncoding.EncodeToString(bucket[:]) + ":" + evpBudgetGroup
	if err := s.budgets.Reserve(budgetKey, 1, s.evp.budgetLimit, s.evp.budgetWindow, time.Unix(int64(now), 0)); err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "issuance quota exceeded"})
		return
	}

	holderJWK, err := emailtoken.PublicJWK(ed25519.PublicKey(browserPub[:]), "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	evt, err := s.evp.signer.IssueEVT(emailtoken.IssueOptions{
		Email:     canonical,
		HolderJWK: holderJWK,
		IssuedAt:  time.Unix(int64(now), 0),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"issuance_token": evt})
}

// --- RFC 9421 (fixed-profile subset) ---

// evpSignatureKeyValue is the Signature-Key header for a browser Ed25519
// key under the hwk scheme.
func evpSignatureKeyValue(browserPub [32]byte) string {
	return fmt.Sprintf("sig=hwk; kty=%q; crv=%q; x=%q",
		"OKP", "Ed25519", base64.RawURLEncoding.EncodeToString(browserPub[:]))
}

// evpSignatureBase is the RFC 9421 §2.5 signature base for the fixed
// covered-component set.
func evpSignatureBase(method, authority, path, signatureKey string, created uint64) string {
	return fmt.Sprintf("\"@method\": %s\n\"@authority\": %s\n\"@path\": %s\n\"signature-key\": %s\n\"@signature-params\": %s;created=%d",
		method, authority, path, signatureKey, evpCovered, created)
}

// signEVPRequest is the client half (a stand-in browser): it returns the
// Signature-Input, Signature, and Signature-Key header values for a POST to
// path at authority. Used by tests and by any Go client driving the rail.
func signEVPRequest(priv ed25519.PrivateKey, authority, path string, created uint64) (sigInput, sig, sigKey string) {
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	sigKey = evpSignatureKeyValue(pub)
	base := evpSignatureBase("POST", authority, path, sigKey, created)
	raw := ed25519.Sign(priv, []byte(base))
	sigInput = fmt.Sprintf("sig=%s;created=%d", evpCovered, created)
	sig = "sig=:" + base64.StdEncoding.EncodeToString(raw) + ":"
	return
}

func evpHeader(h http.Header, name string) (string, error) {
	v := h.Get(name)
	if v == "" {
		return "", fmt.Errorf("missing %s header", name)
	}
	return v, nil
}

// verifyEVPMessageSignature checks the covered-component set, the created
// window, and the Ed25519 signature under the hwk key from Signature-Key,
// returning the browser public key that must be bound into the EVT's cnf.
func verifyEVPMessageSignature(h http.Header, method, authority, path string, now uint64) ([32]byte, error) {
	var browserPub [32]byte
	sigKey, err := evpHeader(h, "Signature-Key")
	if err != nil {
		return browserPub, err
	}
	sigInput, err := evpHeader(h, "Signature-Input")
	if err != nil {
		return browserPub, err
	}
	sigHeader, err := evpHeader(h, "Signature")
	if err != nil {
		return browserPub, err
	}
	if authority == "" {
		return browserPub, errors.New("missing authority")
	}

	// Signature-Key: sig=hwk; kty="OKP"; crv="Ed25519"; x="..."
	params := strings.Split(sigKey, ";")
	if strings.TrimSpace(params[0]) != "sig=hwk" {
		return browserPub, errors.New("Signature-Key must use the hwk scheme")
	}
	var kty, crv, x string
	for _, p := range params[1:] {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.TrimSpace(k) {
		case "kty":
			kty = v
		case "crv":
			crv = v
		case "x":
			x = v
		}
	}
	if kty != "OKP" || crv != "Ed25519" {
		return browserPub, errors.New("only OKP/Ed25519 browser keys are supported")
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(pubBytes) != 32 {
		return browserPub, errors.New("browser key must be 32 base64url bytes")
	}
	copy(browserPub[:], pubBytes)

	// Signature-Input: sig=(<covered>);created=<ts> — exactly the fixed set.
	rest, ok := strings.CutPrefix(strings.TrimSpace(sigInput), "sig=")
	if !ok {
		return browserPub, errors.New("Signature-Input must carry label 'sig'")
	}
	components, sigParams, ok := strings.Cut(rest, ";")
	if !ok {
		return browserPub, errors.New("Signature-Input missing parameters")
	}
	if strings.TrimSpace(components) != evpCovered {
		return browserPub, fmt.Errorf("covered components must be %s", evpCovered)
	}
	var created uint64
	found := false
	for _, p := range strings.Split(sigParams, ";") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(p), "created="); ok {
			if _, err := fmt.Sscanf(v, "%d", &created); err != nil {
				return browserPub, fmt.Errorf("created: %v", err)
			}
			found = true
			break
		}
	}
	if !found {
		return browserPub, errors.New("Signature-Input missing created")
	}
	diff := now - created
	if created > now {
		diff = created - now
	}
	if diff > evpSigMaxAgeSecs {
		return browserPub, errors.New("signature created timestamp outside accepted window")
	}

	// Signature: sig=:base64:
	sigB64, ok := strings.CutPrefix(strings.TrimSpace(sigHeader), "sig=:")
	if !ok || !strings.HasSuffix(sigB64, ":") {
		return browserPub, errors.New("Signature must be sig=:base64:")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(sigB64, ":"))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return browserPub, errors.New("signature must be 64 base64 bytes")
	}

	base := evpSignatureBase(method, authority, path, sigKey, created)
	if !ed25519.Verify(ed25519.PublicKey(browserPub[:]), []byte(base), sigBytes) {
		return browserPub, errors.New("request signature rejected")
	}
	return browserPub, nil
}
