package tokenservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/maceip/tamayo/emailtoken"
	"github.com/maceip/tamayo/mayo"
	"github.com/maceip/tamayo/mldsa"
	"github.com/maceip/tamayo/tokenauth"
	"github.com/maceip/tamayo/tokenprofile"
)

func TestServiceIssuesAndVerifiesBlindRows(t *testing.T) {
	blind, err := tokenprofile.NewIssuer(7, make([]byte, mayo.Mayo1.SKSeedBytes))
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	issuer, err := NewIssuer(blind, nil)
	if err != nil {
		t.Fatalf("NewIssuer service: %v", err)
	}
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x11}, 32))
	challenge := sha256.Sum256([]byte("origin challenge"))
	input := tokenprofile.BurnInput(nonce, challenge, blind.TokenKeyID())
	var additionalR [32]byte
	copy(additionalR[:], bytes.Repeat([]byte{0x22}, 32))
	target, state := tokenprofile.PrepareBlind(input, additionalR)
	if _, err := issuer.SignAuthorizedBlind(BlindMintRequest{
		Decision: allowedDecision(tokenauth.TokenBurn, 1, blind.KeyVersion(), "wrong-binding"),
		Family:   tokenauth.TokenBurn,
		Blinded:  [][]byte{target},
		Now:      time.Unix(1_800_000_000, 0),
	}); err == nil {
		t.Fatal("decision bound to different blinded targets must be rejected")
	}
	sigs, err := issuer.SignAuthorizedBlind(BlindMintRequest{
		Decision: allowedDecision(tokenauth.TokenBurn, 1, blind.KeyVersion(), bindingB64(target)),
		Family:   tokenauth.TokenBurn,
		Blinded:  [][]byte{target},
		Now:      time.Unix(1_800_000_000, 0),
	})
	if err != nil {
		t.Fatalf("SignAuthorizedBlind: %v", err)
	}
	authenticator, err := tokenprofile.FinalizeBlind(blind.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		t.Fatalf("FinalizeBlind: %v", err)
	}
	token := tokenprofile.BurnToken{
		TokenType:       tokenprofile.BurnTokenType,
		Nonce:           nonce,
		ChallengeDigest: challenge,
		TokenKeyID:      blind.TokenKeyID(),
		Authenticator:   authenticator,
	}
	if _, err := issuer.Verifier().VerifyBurnTokenBytes(token.Bytes(), challenge); err != nil {
		t.Fatalf("VerifyBurnTokenBytes: %v", err)
	}

	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	holderPub := holderPriv.Public().(ed25519.PublicKey)
	pvtInput := tokenprofile.NewPrivateIdentityInput(blind.KeyVersion(), blind.TokenKeyID(), tokenprofile.HolderAlgEd25519, holderPub)
	target, state = tokenprofile.PrepareBlind(pvtInput.Bytes(), additionalR)
	sigs, err = issuer.SignAuthorizedBlind(BlindMintRequest{
		Decision: allowedDecision(tokenauth.TokenPrivateIdentity, 1, blind.KeyVersion(), bindingB64(target)),
		Family:   tokenauth.TokenPrivateIdentity,
		Blinded:  [][]byte{target},
		Now:      time.Unix(1_800_000_000, 0),
	})
	if err != nil {
		t.Fatalf("SignAuthorizedBlind private identity: %v", err)
	}
	authenticator, err = tokenprofile.FinalizeBlind(blind.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		t.Fatalf("FinalizeBlind private identity: %v", err)
	}
	pvt := tokenprofile.PrivateIdentityToken{
		Input:         pvtInput,
		Authenticator: authenticator,
	}
	var pvtNonce [32]byte
	copy(pvtNonce[:], bytes.Repeat([]byte{0x77}, 32))
	now := time.Unix(1_800_000_000, 0)
	msg := tokenprofile.PrivateIdentityPresentationMessage("rp.example", pvtNonce, pvt.Digest(), now.Unix())
	pres := tokenprofile.PrivateIdentityPresentation{
		Token:     pvt,
		Origin:    "rp.example",
		Nonce:     pvtNonce,
		IssuedAt:  now.Unix(),
		Signature: ed25519.Sign(holderPriv, msg),
	}
	pseudonym, err := issuer.Verifier().VerifyPrivateIdentityPresentation(pres, now, time.Minute)
	if err != nil {
		t.Fatalf("VerifyPrivateIdentityPresentation: %v", err)
	}
	if pseudonym != pvt.PseudonymForOrigin("rp.example") {
		t.Fatal("service private identity pseudonym mismatch")
	}
}

func TestServiceIssuesAndVerifiesEmailRows(t *testing.T) {
	emailSigner, err := emailtoken.NewSigner("issuer.test", bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	issuer, err := NewIssuer(nil, emailSigner)
	if err != nil {
		t.Fatalf("NewIssuer service: %v", err)
	}
	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	holderJWK, err := emailtoken.PublicJWK(holderPriv.Public().(ed25519.PublicKey), "")
	if err != nil {
		t.Fatalf("PublicJWK: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)

	googleEVT, err := issuer.IssueGoogleEVT(emailtoken.IssueOptions{
		Email:     "alice@example.com",
		HolderJWK: holderJWK,
		IssuedAt:  now,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueGoogleEVT: %v", err)
	}
	policyEmail, err := issuer.IssuePolicyEmail(PolicyEmailIssueRequest{
		Decision:  allowedDecision(tokenauth.TokenPolicyEmail, 1, 3, "policy-binding"),
		Email:     "alice@example.com",
		HolderJWK: holderJWK,
		IssuedAt:  now,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("IssuePolicyEmail: %v", err)
	}

	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x55}, 32))
	googleKB, err := emailtoken.SignKBJWT(holderPriv, googleEVT, emailtoken.PresentationOptions{
		Audience: "rp.example",
		Nonce:    nonce,
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("SignKBJWT Google EVT: %v", err)
	}
	googlePresentation, err := emailtoken.JoinPresentation(googleEVT, googleKB)
	if err != nil {
		t.Fatalf("JoinPresentation Google EVT: %v", err)
	}
	verifiedGoogle, err := issuer.Verifier().VerifyGoogleEVTPresentation(googlePresentation, emailtoken.PresentationVerifyOptions{
		Audience:  "rp.example",
		Nonce:     nonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	})
	if err != nil {
		t.Fatalf("VerifyGoogleEVTPresentation: %v", err)
	}
	if verifiedGoogle.Email != "alice@example.com" {
		t.Fatalf("verified Google EVT email = %q", verifiedGoogle.Email)
	}

	policyKB, err := emailtoken.SignKBJWT(holderPriv, policyEmail, emailtoken.PresentationOptions{
		Audience: "rp.example",
		Nonce:    nonce,
		IssuedAt: now,
	})
	if err != nil {
		t.Fatalf("SignKBJWT policy email: %v", err)
	}
	policyPresentation, err := emailtoken.JoinPresentation(policyEmail, policyKB)
	if err != nil {
		t.Fatalf("JoinPresentation policy email: %v", err)
	}
	verifiedPolicy, err := issuer.Verifier().VerifyPolicyEmailPresentation(policyPresentation, emailtoken.PresentationVerifyOptions{
		Audience:  "rp.example",
		Nonce:     nonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	})
	if err != nil {
		t.Fatalf("VerifyPolicyEmailPresentation: %v", err)
	}
	if verifiedPolicy.Token.Policy.TokenFamily != string(tokenauth.TokenPolicyEmail) {
		t.Fatalf("policy binding = %+v", verifiedPolicy.Token.Policy)
	}
}

func TestServiceIssuesAndVerifiesPQEmailRow(t *testing.T) {
	pqSigner, err := emailtoken.NewPQSigner("issuer.test", bytes.Repeat([]byte{0x88}, 32))
	if err != nil {
		t.Fatalf("NewPQSigner: %v", err)
	}
	issuer, err := NewIssuerWithPQEmail(nil, nil, pqSigner)
	if err != nil {
		t.Fatalf("NewIssuerWithPQEmail: %v", err)
	}
	holderPub, holderPriv, err := mldsa.MLDSA44.KeyGen(bytes.Repeat([]byte{0x99}, 32))
	if err != nil {
		t.Fatalf("MLDSA44.KeyGen: %v", err)
	}
	holderJWK, err := emailtoken.PublicJWKMLDSA44(holderPub, "")
	if err != nil {
		t.Fatalf("PublicJWKMLDSA44: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)

	token, err := issuer.IssuePolicyEmailPQ(PolicyEmailIssueRequest{
		Decision:  allowedDecision(tokenauth.TokenPolicyEmail, 1, 3, "policy-binding"),
		Email:     "alice@example.com",
		HolderJWK: holderJWK,
		IssuedAt:  now,
		TTL:       time.Hour,
	})
	if err != nil {
		t.Fatalf("IssuePolicyEmailPQ: %v", err)
	}
	if _, err := issuer.IssuePolicyEmail(PolicyEmailIssueRequest{}); err == nil {
		t.Fatal("classical rail must not be configured")
	}

	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0xAA}, 32))
	kb, err := emailtoken.SignKBJWTMLDSA44(holderPriv, token, emailtoken.PresentationOptions{
		Audience: "rp.example",
		Nonce:    nonce,
		IssuedAt: now,
	}, nil)
	if err != nil {
		t.Fatalf("SignKBJWTMLDSA44: %v", err)
	}
	presentation, err := emailtoken.JoinPresentation(token, kb)
	if err != nil {
		t.Fatalf("JoinPresentation: %v", err)
	}
	verified, err := issuer.Verifier().VerifyPolicyEmailPresentationPQ(presentation, emailtoken.PresentationVerifyOptions{
		Audience:  "rp.example",
		Nonce:     nonce,
		Now:       now,
		EVTMaxAge: time.Hour,
		KBMaxAge:  time.Minute,
	})
	if err != nil {
		t.Fatalf("VerifyPolicyEmailPresentationPQ: %v", err)
	}
	if verified.Email != "alice@example.com" || verified.Token.Policy.TokenFamily != string(tokenauth.TokenPolicyEmail) {
		t.Fatalf("verified = %+v", verified)
	}
}

// bindingB64 encodes the channel binding for a single-target batch the way
// tokenauth constraints carry it.
func bindingB64(target []byte) string {
	binding := tokenprofile.BindingOf([][]byte{target})
	return base64.RawURLEncoding.EncodeToString(binding[:])
}

func allowedDecision(family tokenauth.TokenFamily, count int, keyVersion uint32, binding string) tokenauth.MintDecision {
	return tokenauth.MintDecision{
		Allow:  true,
		Reason: "authorized",
		Constraints: tokenauth.MintConstraints{
			TokenFamily: family,
			Count:       count,
			KeyVersion:  keyVersion,
			BindingB64:  binding,
			BudgetKey:   "test-budget",
			Address:     "alice@example.com",
			ExpiresAt:   time.Unix(1_800_000_000, 0).Add(time.Minute).Unix(),
		},
	}
}
