package emailtoken

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestGoogleEVTRoundTripAndPresentation(t *testing.T) {
	issuer, err := NewSigner("issuer.test", bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	holderJWK, err := PublicJWK(holderPriv.Public().(ed25519.PublicKey), "")
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	evt, err := issuer.IssueEVT(IssueOptions{
		Email:     "alice@example.com",
		HolderJWK: holderJWK,
		IssuedAt:  now,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueEVT: %v", err)
	}
	if !strings.HasSuffix(evt, "~") {
		t.Fatalf("EVT must keep trailing tilde: %q", evt)
	}
	claims, err := issuer.Verifier().VerifyEVT(evt, VerifyOptions{Now: now, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("VerifyEVT: %v", err)
	}
	if claims.Email != "alice@example.com" || !claims.EmailVerified {
		t.Fatalf("claims = %+v", claims)
	}
	if got := issuer.JWKS().Keys[0].Kid; got != issuer.KID() {
		t.Fatalf("jwks kid = %q want %q", got, issuer.KID())
	}

	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x33}, 32))
	kb, err := SignKBJWT(holderPriv, evt, PresentationOptions{
		Audience: "rp.example",
		Nonce:    nonce,
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("SignKBJWT: %v", err)
	}
	presentation, err := JoinPresentation(evt, kb)
	if err != nil {
		t.Fatalf("JoinPresentation: %v", err)
	}
	verified, err := issuer.Verifier().VerifyPresentation(presentation, PresentationVerifyOptions{
		Audience:  "rp.example",
		Nonce:     nonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	})
	if err != nil {
		t.Fatalf("VerifyPresentation: %v", err)
	}
	if verified.Email != "alice@example.com" {
		t.Fatalf("verified email = %q", verified.Email)
	}
}

func TestGoogleEVTPresentationRejectsWrongNonceAndAudience(t *testing.T) {
	issuer, err := NewSigner("issuer.test", bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	holderJWK, err := PublicJWK(holderPriv.Public().(ed25519.PublicKey), "")
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	evt, err := issuer.IssueEVT(IssueOptions{
		Email:     "bob@example.com",
		HolderJWK: holderJWK,
		IssuedAt:  now,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueEVT: %v", err)
	}
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x66}, 32))
	kb, err := SignKBJWT(holderPriv, evt, PresentationOptions{
		Audience: "rp.example",
		Nonce:    nonce,
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("SignKBJWT: %v", err)
	}
	presentation, err := JoinPresentation(evt, kb)
	if err != nil {
		t.Fatalf("JoinPresentation: %v", err)
	}

	wrongNonce := nonce
	wrongNonce[0] ^= 0xff
	_, err = issuer.Verifier().VerifyPresentation(presentation, PresentationVerifyOptions{
		Audience:  "rp.example",
		Nonce:     wrongNonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	})
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("wrong nonce error = %v", err)
	}

	_, err = issuer.Verifier().VerifyPresentation(presentation, PresentationVerifyOptions{
		Audience:  "other.example",
		Nonce:     nonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	})
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("wrong audience error = %v", err)
	}
}

func TestPolicyEmailRoundTripAndPresentation(t *testing.T) {
	issuer, err := NewSigner("issuer.test", bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x88}, ed25519.SeedSize))
	holderJWK, err := PublicJWK(holderPriv.Public().(ed25519.PublicKey), "")
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	token, err := issuer.IssuePolicyEmail(PolicyEmailIssueOptions{
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
	})
	if err != nil {
		t.Fatalf("IssuePolicyEmail: %v", err)
	}
	if _, err := issuer.Verifier().VerifyEVT(token, VerifyOptions{Now: now, MaxAge: time.Hour}); err == nil {
		t.Fatal("policy email token must not verify as Google EVT")
	}
	claims, err := issuer.Verifier().VerifyPolicyEmail(token, VerifyOptions{Now: now, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("VerifyPolicyEmail: %v", err)
	}
	if claims.Policy.BudgetKey != "email:carol@example.com:shared" {
		t.Fatalf("policy binding = %+v", claims.Policy)
	}

	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x99}, 32))
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
}
