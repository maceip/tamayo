package emailtoken

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/maceip/tamayo/mldsa"
)

// TestPQPolicyEmailRoundTripAndPresentation exercises the fully post-quantum
// chain: ML-DSA-44 issuer signature plus an ML-DSA-44 holder key for the
// KB-JWT presentation.
func TestPQPolicyEmailRoundTripAndPresentation(t *testing.T) {
	issuer, err := NewPQSigner("issuer.test", bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatalf("NewPQSigner: %v", err)
	}
	holderPub, holderPriv, err := mldsa.MLDSA44.KeyGen(bytes.Repeat([]byte{0x88}, 32))
	if err != nil {
		t.Fatalf("MLDSA44.KeyGen: %v", err)
	}
	holderJWK, err := PublicJWKMLDSA44(holderPub, "")
	if err != nil {
		t.Fatalf("PublicJWKMLDSA44: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	opts := PolicyEmailIssueOptions{
		Email:     "carol@example.com",
		HolderJWK: holderJWK,
		Policy: PolicyBinding{
			TokenFamily:            "policy_email",
			BindingB64:             "binding",
			BudgetKey:              "email:carol@example.com:shared",
			Origin:                 "rp.example",
			AuthorizationExpiresAt: now.Add(time.Minute).Unix(),
		},
		IssuedAt: now,
		TTL:      time.Hour,
	}
	token, err := issuer.IssuePolicyEmail(opts)
	if err != nil {
		t.Fatalf("IssuePolicyEmail: %v", err)
	}

	claims, err := issuer.Verifier().VerifyPolicyEmail(token, VerifyOptions{Now: now, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("VerifyPolicyEmail: %v", err)
	}
	if claims.Policy.BudgetKey != "email:carol@example.com:shared" {
		t.Fatalf("policy binding = %+v", claims.Policy)
	}

	// Deterministic vs hedged signing must both verify, and differ.
	hedged := PolicyEmailIssueOptions(opts)
	hedged.Rnd = bytes.Repeat([]byte{0xAB}, 32)
	hedgedToken, err := issuer.IssuePolicyEmail(hedged)
	if err != nil {
		t.Fatalf("IssuePolicyEmail hedged: %v", err)
	}
	if hedgedToken == token {
		t.Fatal("hedged signature must differ from deterministic")
	}
	if _, err := issuer.Verifier().VerifyPolicyEmail(hedgedToken, VerifyOptions{Now: now, MaxAge: time.Hour}); err != nil {
		t.Fatalf("VerifyPolicyEmail hedged: %v", err)
	}

	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x99}, 32))
	kb, err := SignKBJWTMLDSA44(holderPriv, token, PresentationOptions{
		Audience: "rp.example",
		Nonce:    nonce,
		IssuedAt: now,
	}, nil)
	if err != nil {
		t.Fatalf("SignKBJWTMLDSA44: %v", err)
	}
	presentation, err := JoinPresentation(token, kb)
	if err != nil {
		t.Fatalf("JoinPresentation: %v", err)
	}
	verified, err := issuer.Verifier().VerifyPolicyEmailPresentation(presentation, PresentationVerifyOptions{
		Audience:  "rp.example",
		Nonce:     nonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	})
	if err != nil {
		t.Fatalf("VerifyPolicyEmailPresentation: %v", err)
	}
	if verified.Email != "carol@example.com" || verified.Token.Policy.TokenFamily != "policy_email" {
		t.Fatalf("verified = %+v", verified)
	}

	// Tampered issuer signature must be rejected.
	bad := []byte(strings.TrimSuffix(token, "~"))
	bad[len(bad)-3] ^= 1
	if _, err := issuer.Verifier().VerifyPolicyEmail(string(bad)+"~", VerifyOptions{Now: now, MaxAge: time.Hour}); err == nil {
		t.Fatal("tampered PQ token accepted")
	}
}

// TestPQPolicyEmailEd25519Holder covers the hybrid shape: PQ issuer
// signature over a classical Ed25519 holder key.
func TestPQPolicyEmailEd25519Holder(t *testing.T) {
	issuer, err := NewPQSigner("issuer.test", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatalf("NewPQSigner: %v", err)
	}
	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	holderJWK, err := PublicJWK(holderPriv.Public().(ed25519.PublicKey), "")
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	token, err := issuer.IssuePolicyEmail(PolicyEmailIssueOptions{
		Email:     "dave@example.com",
		HolderJWK: holderJWK,
		Policy: PolicyBinding{
			TokenFamily:            "policy_email",
			BindingB64:             "binding",
			BudgetKey:              "email:dave@example.com:shared",
			AuthorizationExpiresAt: now.Add(time.Minute).Unix(),
		},
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("IssuePolicyEmail: %v", err)
	}
	var nonce [32]byte
	kb, err := SignKBJWT(holderPriv, token, PresentationOptions{
		Audience: "rp.example",
		Nonce:    nonce,
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("SignKBJWT: %v", err)
	}
	presentation, err := JoinPresentation(token, kb)
	if err != nil {
		t.Fatalf("JoinPresentation: %v", err)
	}
	if _, err := issuer.Verifier().VerifyPolicyEmailPresentation(presentation, PresentationVerifyOptions{
		Audience:  "rp.example",
		Nonce:     nonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	}); err != nil {
		t.Fatalf("VerifyPolicyEmailPresentation: %v", err)
	}
}

// TestClassicalPathRejectsAKPHolder pins the boundary: the Ed25519 policy
// email profile must not accept AKP holder keys (those belong to the PQ
// profile).
func TestClassicalPathRejectsAKPHolder(t *testing.T) {
	issuer, err := NewSigner("issuer.test", bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	holderPub, _, err := mldsa.MLDSA44.KeyGen(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatalf("MLDSA44.KeyGen: %v", err)
	}
	holderJWK, err := PublicJWKMLDSA44(holderPub, "")
	if err != nil {
		t.Fatalf("PublicJWKMLDSA44: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	_, err = issuer.IssuePolicyEmail(PolicyEmailIssueOptions{
		Email:     "erin@example.com",
		HolderJWK: holderJWK,
		Policy: PolicyBinding{
			TokenFamily:            "policy_email",
			BindingB64:             "binding",
			BudgetKey:              "email:erin@example.com:shared",
			AuthorizationExpiresAt: now.Add(time.Minute).Unix(),
		},
		IssuedAt: now,
	})
	if err == nil {
		t.Fatal("classical issuer accepted an AKP holder key")
	}
}
