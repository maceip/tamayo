package emailtoken

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func PublicJWK(pub ed25519.PublicKey, kid string) (JWK, error) {
	if len(pub) != ed25519.PublicKeySize {
		return JWK{}, fmt.Errorf("ed25519 public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   encode(pub),
		Kid: kid,
		Alg: AlgEdDSA,
		Use: "sig",
	}, nil
}

func (j JWK) Ed25519PublicKey() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, errors.New("jwk must be OKP/Ed25519")
	}
	x, err := decode(j.X)
	if err != nil {
		return nil, fmt.Errorf("jwk x: %w", err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwk x is %d bytes, want %d", len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), x...)), nil
}
