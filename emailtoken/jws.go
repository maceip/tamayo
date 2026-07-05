package emailtoken

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	AlgEdDSA = "EdDSA"
	TypEVT   = "evt+jwt"
	TypKBJWT = "kb+jwt"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func signJWS(header Header, claims any, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("ed25519 private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	header.Alg = AlgEdDSA
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := encode(h) + "." + encode(p)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + encode(sig), nil
}

func verifyJWS(compact string, pub ed25519.PublicKey) (Header, []byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Header{}, nil, fmt.Errorf("ed25519 public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return Header{}, nil, errors.New("jws must have three segments")
	}
	headerBytes, err := decode(parts[0])
	if err != nil {
		return Header{}, nil, fmt.Errorf("jws header: %w", err)
	}
	var header Header
	dec := json.NewDecoder(bytes.NewReader(headerBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&header); err != nil {
		return Header{}, nil, err
	}
	if header.Alg != AlgEdDSA {
		return Header{}, nil, fmt.Errorf("jws alg %q unsupported", header.Alg)
	}
	sig, err := decode(parts[2])
	if err != nil {
		return Header{}, nil, fmt.Errorf("jws signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return Header{}, nil, fmt.Errorf("jws signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return Header{}, nil, errors.New("jws signature rejected")
	}
	payload, err := decode(parts[1])
	if err != nil {
		return Header{}, nil, fmt.Errorf("jws payload: %w", err)
	}
	return header, payload, nil
}
