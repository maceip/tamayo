package emailtoken

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const Scheme = "EVT"

type KBClaims struct {
	Aud    string `json:"aud"`
	Nonce  string `json:"nonce"`
	Iat    int64  `json:"iat"`
	SDHash string `json:"sd_hash"`
}

type PresentationOptions struct {
	Audience string
	Nonce    [32]byte
	IssuedAt time.Time
}

type PresentationVerifyOptions struct {
	Audience  string
	Nonce     [32]byte
	Now       time.Time
	EVTMaxAge time.Duration
	KBMaxAge  time.Duration
}

type VerifiedPresentation struct {
	Email         string
	EmailVerified bool
	EVT           EVTClaims
	KB            KBClaims
}

func SDHash(evtWithTilde string) string {
	sum := sha256.Sum256([]byte(evtWithTilde))
	return encode(sum[:])
}

func SignKBJWT(holder ed25519.PrivateKey, evtWithTilde string, opts PresentationOptions) (string, error) {
	if opts.Audience == "" {
		return "", errors.New("audience required")
	}
	if opts.IssuedAt.IsZero() {
		return "", errors.New("issued_at required")
	}
	if !strings.HasSuffix(evtWithTilde, "~") {
		return "", errors.New("evt must include trailing tilde")
	}
	claims := KBClaims{
		Aud:    opts.Audience,
		Nonce:  encode(opts.Nonce[:]),
		Iat:    opts.IssuedAt.Unix(),
		SDHash: SDHash(evtWithTilde),
	}
	return signJWS(Header{Typ: TypKBJWT}, claims, holder)
}

func JoinPresentation(evtWithTilde, kbJWT string) (string, error) {
	if !strings.HasSuffix(evtWithTilde, "~") {
		return "", errors.New("evt must include trailing tilde")
	}
	if strings.TrimSpace(kbJWT) == "" {
		return "", errors.New("kb-jwt required")
	}
	return evtWithTilde + kbJWT, nil
}

func (v *Verifier) VerifyPresentation(presentation string, opts PresentationVerifyOptions) (VerifiedPresentation, error) {
	evt, kb, err := splitPresentation(presentation)
	if err != nil {
		return VerifiedPresentation{}, err
	}
	evtClaims, err := v.VerifyEVT(evt, VerifyOptions{Now: opts.Now, MaxAge: opts.EVTMaxAge})
	if err != nil {
		return VerifiedPresentation{}, fmt.Errorf("evt: %w", err)
	}
	holderPub, err := evtClaims.CNF.JWK.Ed25519PublicKey()
	if err != nil {
		return VerifiedPresentation{}, fmt.Errorf("evt cnf.jwk: %w", err)
	}
	kbClaims, err := verifyKBJWT(kb, evt, holderPub, opts)
	if err != nil {
		return VerifiedPresentation{}, err
	}
	return VerifiedPresentation{
		Email:         evtClaims.Email,
		EmailVerified: evtClaims.EmailVerified,
		EVT:           evtClaims,
		KB:            kbClaims,
	}, nil
}

func verifyKBJWT(kbJWT, tokenWithTilde string, holderPub ed25519.PublicKey, opts PresentationVerifyOptions) (KBClaims, error) {
	header, payload, err := verifyJWS(kbJWT, holderPub)
	if err != nil {
		return KBClaims{}, fmt.Errorf("kb-jwt: %w", err)
	}
	return checkKBClaims(header, payload, tokenWithTilde, opts)
}

// checkKBClaims validates a verified KB-JWT payload against the presented
// token and options (shared by the Ed25519 and ML-DSA-44 holder paths).
func checkKBClaims(header Header, payload []byte, tokenWithTilde string, opts PresentationVerifyOptions) (KBClaims, error) {
	if header.Typ != TypKBJWT {
		return KBClaims{}, fmt.Errorf("kb-jwt typ %q unsupported", header.Typ)
	}
	var kbClaims KBClaims
	if err := json.Unmarshal(payload, &kbClaims); err != nil {
		return KBClaims{}, err
	}
	if kbClaims.Aud != opts.Audience {
		return KBClaims{}, errors.New("kb-jwt audience mismatch")
	}
	if kbClaims.SDHash != SDHash(tokenWithTilde) {
		return KBClaims{}, errors.New("kb-jwt sd_hash mismatch")
	}
	nonce, err := decode(kbClaims.Nonce)
	if err != nil {
		return KBClaims{}, fmt.Errorf("kb-jwt nonce: %w", err)
	}
	if len(nonce) != len(opts.Nonce) {
		return KBClaims{}, fmt.Errorf("kb-jwt nonce is %d bytes, want %d", len(nonce), len(opts.Nonce))
	}
	if !bytes.Equal(nonce, opts.Nonce[:]) {
		return KBClaims{}, errors.New("kb-jwt nonce mismatch")
	}
	if err := checkTime("kb-jwt", kbClaims.Iat, 0, opts.Now, opts.KBMaxAge); err != nil {
		return KBClaims{}, err
	}
	return kbClaims, nil
}

func splitPresentation(presentation string) (evtWithTilde string, kbJWT string, err error) {
	presentation = strings.TrimSpace(presentation)
	idx := strings.LastIndex(presentation, "~")
	if idx < 0 {
		return "", "", errors.New("presentation must be <EVT>~<KB-JWT>")
	}
	evtWithTilde = presentation[:idx+1]
	kbJWT = presentation[idx+1:]
	if strings.Count(strings.TrimSuffix(evtWithTilde, "~"), ".") != 2 {
		return "", "", errors.New("evt must be compact jws plus trailing tilde")
	}
	if strings.Count(kbJWT, ".") != 2 {
		return "", "", errors.New("kb-jwt must be compact jws")
	}
	return evtWithTilde, kbJWT, nil
}
