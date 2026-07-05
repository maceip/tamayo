package tokenprofile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/maceip/tamayo/faest"
	"github.com/maceip/tamayo/mayo"
)

func TestBurnTokenRoundTrip(t *testing.T) {
	issuer := testIssuer(t)
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x11}, 32))
	challenge := sha256.Sum256([]byte("origin challenge"))

	authenticator := mintAuthenticator(t, issuer, BurnInput(nonce, challenge, issuer.TokenKeyID()))
	token := BurnToken{
		TokenType:       BurnTokenType,
		Nonce:           nonce,
		ChallengeDigest: challenge,
		TokenKeyID:      issuer.TokenKeyID(),
		Authenticator:   authenticator,
	}
	if err := issuer.VerifyBurnToken(token, challenge); err != nil {
		t.Fatalf("VerifyBurnToken: %v", err)
	}
	parsed, err := ParseBurnToken(token.Bytes())
	if err != nil {
		t.Fatalf("ParseBurnToken: %v", err)
	}
	if err := issuer.VerifyBurnToken(parsed, challenge); err != nil {
		t.Fatalf("VerifyBurnToken parsed: %v", err)
	}
	wrongChallenge := sha256.Sum256([]byte("wrong"))
	if err := issuer.VerifyBurnToken(token, wrongChallenge); err == nil || !strings.Contains(err.Error(), "challenge") {
		t.Fatalf("wrong challenge error = %v", err)
	}
}

func TestPrivateIdentityPresentation(t *testing.T) {
	issuer := testIssuer(t)
	holderPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	holderPub := holderPriv.Public().(ed25519.PublicKey)

	input := NewPrivateIdentityInput(issuer.KeyVersion(), issuer.TokenKeyID(), HolderAlgEd25519, holderPub)
	token := PrivateIdentityToken{
		Input:         input,
		Authenticator: mintAuthenticator(t, issuer, input.Bytes()),
	}
	if err := issuer.VerifyPrivateIdentityToken(token); err != nil {
		t.Fatalf("VerifyPrivateIdentityToken: %v", err)
	}
	parsed, err := ParsePrivateIdentityToken(token.Bytes())
	if err != nil {
		t.Fatalf("ParsePrivateIdentityToken: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x22}, 32))
	msg := PrivateIdentityPresentationMessage("rp.example", nonce, parsed.Digest(), now.Unix())
	pres := PrivateIdentityPresentation{
		Token:     parsed,
		Origin:    "rp.example",
		Nonce:     nonce,
		IssuedAt:  now.Unix(),
		Signature: ed25519.Sign(holderPriv, msg),
	}
	pseudonym, err := issuer.VerifyPrivateIdentityPresentation(pres, now, time.Minute)
	if err != nil {
		t.Fatalf("VerifyPrivateIdentityPresentation: %v", err)
	}
	if pseudonym != token.PseudonymForOrigin("rp.example") {
		t.Fatal("pseudonym mismatch")
	}
	if pseudonym == token.PseudonymForOrigin("other.example") {
		t.Fatal("pseudonym must be origin-bound")
	}
	pres.Origin = "other.example"
	if _, err := issuer.VerifyPrivateIdentityPresentation(pres, now, time.Minute); err == nil || !strings.Contains(err.Error(), "proof-of-possession") {
		t.Fatalf("wrong origin error = %v", err)
	}
}

func TestPrivateIdentityPresentationFAEST128s(t *testing.T) {
	issuer := testIssuer(t)
	holderSK, holderPK, err := faest.FAEST128s.KeyGen(bytes.NewReader(bytes.Repeat([]byte{0x10}, 128)))
	if err != nil {
		t.Fatalf("FAEST128s.KeyGen: %v", err)
	}
	holderPub := FAEST128sPublicKeyBytes(holderPK)

	input := NewPrivateIdentityInput(issuer.KeyVersion(), issuer.TokenKeyID(), HolderAlgFAEST128s, holderPub)
	token := PrivateIdentityToken{
		Input:         input,
		Authenticator: mintAuthenticator(t, issuer, input.Bytes()),
	}
	now := time.Unix(1_800_000_000, 0)
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x44}, 32))
	msg := PrivateIdentityPresentationMessage("rp.example", nonce, token.Digest(), now.Unix())
	rho := bytes.Repeat([]byte{0x55}, faest.FAEST128s.OWF.LambdaBytes)
	pres := PrivateIdentityPresentation{
		Token:     token,
		Origin:    "rp.example",
		Nonce:     nonce,
		IssuedAt:  now.Unix(),
		Signature: faest.FAEST128s.Sign(msg, holderSK, rho),
	}
	pseudonym, err := issuer.VerifyPrivateIdentityPresentation(pres, now, time.Minute)
	if err != nil {
		t.Fatalf("VerifyPrivateIdentityPresentation FAEST: %v", err)
	}
	if pseudonym != token.PseudonymForOrigin("rp.example") {
		t.Fatal("pseudonym mismatch")
	}
	pres.Signature[0] ^= 0x80
	if _, err := issuer.VerifyPrivateIdentityPresentation(pres, now, time.Minute); err == nil || !strings.Contains(err.Error(), "faest") {
		t.Fatalf("tampered FAEST proof error = %v", err)
	}
}

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	issuer, err := NewIssuer(7, make([]byte, mayo.Mayo1.SKSeedBytes))
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer
}

func mintAuthenticator(t *testing.T, issuer *Issuer, message []byte) []byte {
	t.Helper()
	var additionalR [32]byte
	copy(additionalR[:], bytes.Repeat([]byte{0x33}, 32))
	target, state := PrepareBlind(message, additionalR)
	sigs, err := issuer.BlindSign([][]byte{target})
	if err != nil {
		t.Fatalf("BlindSign: %v", err)
	}
	authenticator, err := FinalizeBlind(issuer.ExpandedPublicKey(), sigs[0], state)
	if err != nil {
		t.Fatalf("FinalizeBlind: %v", err)
	}
	return authenticator
}
