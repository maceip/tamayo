package emailtoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type Signer struct {
	issuer string
	kid    string
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
}

type Verifier struct {
	issuer string
	kid    string
	pub    ed25519.PublicKey
}

type Confirmation struct {
	JWK JWK `json:"jwk"`
}

type EVTClaims struct {
	Iss           string       `json:"iss"`
	Iat           int64        `json:"iat"`
	Exp           int64        `json:"exp,omitempty"`
	CNF           Confirmation `json:"cnf"`
	Email         string       `json:"email"`
	EmailVerified bool         `json:"email_verified"`
}

type IssueOptions struct {
	Email     string
	HolderJWK JWK
	IssuedAt  time.Time
	TTL       time.Duration
}

type VerifyOptions struct {
	Now    time.Time
	MaxAge time.Duration
}

func NewSigner(issuer string, seed []byte) (*Signer, error) {
	if issuer == "" {
		return nil, errors.New("issuer required")
	}
	var priv ed25519.PrivateKey
	if len(seed) == 0 {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = generated
	} else {
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("ed25519 seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	}
	return NewSignerFromPrivateKey(issuer, priv)
}

func NewSignerFromPrivateKey(issuer string, priv ed25519.PrivateKey) (*Signer, error) {
	if issuer == "" {
		return nil, errors.New("issuer required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &Signer{
		issuer: issuer,
		kid:    "ed25519-" + hex.EncodeToString(sum[:8]),
		pub:    append(ed25519.PublicKey(nil), pub...),
		priv:   append(ed25519.PrivateKey(nil), priv...),
	}, nil
}

func (s *Signer) Verifier() *Verifier {
	return &Verifier{
		issuer: s.issuer,
		kid:    s.kid,
		pub:    append(ed25519.PublicKey(nil), s.pub...),
	}
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.pub...)
}

func (s *Signer) KID() string {
	return s.kid
}

func (s *Signer) JWK() JWK {
	jwk, _ := PublicJWK(s.pub, s.kid)
	return jwk
}

func (s *Signer) JWKS() JWKS {
	return JWKS{Keys: []JWK{s.JWK()}}
}

func (s *Signer) IssueEVT(opts IssueOptions) (string, error) {
	if opts.Email == "" {
		return "", errors.New("email required")
	}
	if opts.IssuedAt.IsZero() {
		return "", errors.New("issued_at required")
	}
	if _, err := opts.HolderJWK.Ed25519PublicKey(); err != nil {
		return "", fmt.Errorf("holder jwk: %w", err)
	}
	claims := EVTClaims{
		Iss:           s.issuer,
		Iat:           opts.IssuedAt.Unix(),
		CNF:           Confirmation{JWK: opts.HolderJWK},
		Email:         opts.Email,
		EmailVerified: true,
	}
	if opts.TTL > 0 {
		claims.Exp = opts.IssuedAt.Add(opts.TTL).Unix()
	}
	jws, err := signJWS(Header{Typ: TypEVT, Kid: s.kid}, claims, s.priv)
	if err != nil {
		return "", err
	}
	return jws + "~", nil
}

func (v *Verifier) VerifyEVT(evt string, opts VerifyOptions) (EVTClaims, error) {
	evt = strings.TrimSpace(evt)
	if !strings.HasSuffix(evt, "~") {
		return EVTClaims{}, errors.New("evt must include trailing tilde")
	}
	compact := strings.TrimSuffix(evt, "~")
	header, payload, err := verifyJWS(compact, v.pub)
	if err != nil {
		return EVTClaims{}, err
	}
	if header.Typ != TypEVT {
		return EVTClaims{}, fmt.Errorf("evt typ %q unsupported", header.Typ)
	}
	if v.kid != "" && header.Kid != v.kid {
		return EVTClaims{}, errors.New("evt kid mismatch")
	}
	var claims EVTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return EVTClaims{}, err
	}
	if claims.Iss != v.issuer {
		return EVTClaims{}, errors.New("evt issuer mismatch")
	}
	if !claims.EmailVerified {
		return EVTClaims{}, errors.New("evt email_verified must be true")
	}
	if claims.Email == "" {
		return EVTClaims{}, errors.New("evt email required")
	}
	if _, err := claims.CNF.JWK.Ed25519PublicKey(); err != nil {
		return EVTClaims{}, fmt.Errorf("evt cnf.jwk: %w", err)
	}
	if err := checkTime("evt", claims.Iat, claims.Exp, opts.Now, opts.MaxAge); err != nil {
		return EVTClaims{}, err
	}
	return claims, nil
}

func RandomNonce() ([32]byte, error) {
	var nonce [32]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return nonce, err
}

func checkTime(name string, iat, exp int64, now time.Time, maxAge time.Duration) error {
	if now.IsZero() {
		return nil
	}
	nowUnix := now.Unix()
	if exp > 0 && nowUnix > exp {
		return fmt.Errorf("%s expired", name)
	}
	if maxAge > 0 {
		age := now.Sub(time.Unix(iat, 0))
		if age < 0 {
			age = -age
		}
		if age > maxAge {
			return fmt.Errorf("%s iat outside accepted window", name)
		}
	}
	return nil
}
