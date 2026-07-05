package tokenprofile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	PrivateIdentityTokenType = uint16(0x5056)
	HolderAlgEd25519         = byte(0x01)
	HolderAlgMLDSA44         = byte(0x02)
	privateIdentityInputHead = 2 + 4 + 32 + 1
	popDomain                = "eat-pass/pvt-pop\x00"
)

// PrivateIdentityInput is the blind-signed input for a reusable private
// identity token. The holder key becomes the verifier-visible pseudonym source.
type PrivateIdentityInput struct {
	TokenType  uint16
	KeyVersion uint32
	TokenKeyID [32]byte
	HolderAlg  byte
	HolderPub  []byte
}

func NewPrivateIdentityInput(keyVersion uint32, tokenKeyID [32]byte, holderAlg byte, holderPub []byte) PrivateIdentityInput {
	return PrivateIdentityInput{
		TokenType:  PrivateIdentityTokenType,
		KeyVersion: keyVersion,
		TokenKeyID: tokenKeyID,
		HolderAlg:  holderAlg,
		HolderPub:  append([]byte(nil), holderPub...),
	}
}

func (p PrivateIdentityInput) Bytes() []byte {
	out := make([]byte, 0, privateIdentityInputHead+len(p.HolderPub))
	out = binary.BigEndian.AppendUint16(out, p.TokenType)
	out = binary.BigEndian.AppendUint32(out, p.KeyVersion)
	out = append(out, p.TokenKeyID[:]...)
	out = append(out, p.HolderAlg)
	out = append(out, p.HolderPub...)
	return out
}

func parsePrivateIdentityInputPrefix(b []byte) (PrivateIdentityInput, int, error) {
	if len(b) < privateIdentityInputHead {
		return PrivateIdentityInput{}, 0, fmt.Errorf("private identity input is %d bytes, too short", len(b))
	}
	tokenType := binary.BigEndian.Uint16(b[:2])
	if tokenType != PrivateIdentityTokenType {
		return PrivateIdentityInput{}, 0, fmt.Errorf("token type 0x%04x unsupported", tokenType)
	}
	holderAlg := b[38]
	holderLen, err := holderPubLen(holderAlg)
	if err != nil {
		return PrivateIdentityInput{}, 0, err
	}
	end := privateIdentityInputHead + holderLen
	if len(b) < end {
		return PrivateIdentityInput{}, 0, fmt.Errorf("private identity holder public key truncated")
	}
	var tokenKeyID [32]byte
	copy(tokenKeyID[:], b[6:38])
	return PrivateIdentityInput{
		TokenType:  tokenType,
		KeyVersion: binary.BigEndian.Uint32(b[2:6]),
		TokenKeyID: tokenKeyID,
		HolderAlg:  holderAlg,
		HolderPub:  append([]byte(nil), b[privateIdentityInputHead:end]...),
	}, end, nil
}

func holderPubLen(alg byte) (int, error) {
	switch alg {
	case HolderAlgEd25519:
		return ed25519.PublicKeySize, nil
	case HolderAlgMLDSA44:
		return 1312, nil
	default:
		return 0, fmt.Errorf("unsupported holder_alg 0x%02x", alg)
	}
}

// PrivateIdentityToken is reusable at a verifier. Product services issue and
// consume presentation nonces; this package verifies the token and holder proof.
type PrivateIdentityToken struct {
	Input         PrivateIdentityInput
	Authenticator []byte
}

func (p PrivateIdentityToken) Bytes() []byte {
	out := p.Input.Bytes()
	out = append(out, p.Authenticator...)
	return out
}

func ParsePrivateIdentityToken(b []byte) (PrivateIdentityToken, error) {
	input, consumed, err := parsePrivateIdentityInputPrefix(b)
	if err != nil {
		return PrivateIdentityToken{}, err
	}
	authenticator := append([]byte(nil), b[consumed:]...)
	if len(authenticator) <= authenticatorRandomLength {
		return PrivateIdentityToken{}, fmt.Errorf("private identity authenticator too short")
	}
	return PrivateIdentityToken{Input: input, Authenticator: authenticator}, nil
}

func (p PrivateIdentityToken) Digest() [32]byte {
	return digest(p.Bytes())
}

func (p PrivateIdentityToken) Pseudonym() [32]byte {
	return digest(p.Input.HolderPub)
}

// PrivateIdentityPresentation is one verifier-bound presentation of a reusable
// private identity token.
type PrivateIdentityPresentation struct {
	Token     PrivateIdentityToken
	Origin    string
	Nonce     [32]byte
	IssuedAt  int64
	Signature []byte
}

func PrivateIdentityPresentationMessage(origin string, nonce, tokenDigest [32]byte, issuedAt int64) []byte {
	var buf bytes.Buffer
	buf.WriteString(popDomain)
	binary.Write(&buf, binary.BigEndian, uint16(len(origin)))
	buf.WriteString(origin)
	buf.Write(nonce[:])
	buf.Write(tokenDigest[:])
	binary.Write(&buf, binary.BigEndian, uint64(issuedAt))
	return buf.Bytes()
}

func (i *Issuer) VerifyPrivateIdentityToken(token PrivateIdentityToken) error {
	if token.Input.TokenType != PrivateIdentityTokenType {
		return fmt.Errorf("token type 0x%04x unsupported", token.Input.TokenType)
	}
	if token.Input.KeyVersion != i.keyVersion {
		return fmt.Errorf("key version %d unsupported", token.Input.KeyVersion)
	}
	if token.Input.TokenKeyID != i.tokenKeyID {
		return errors.New("token_key_id mismatch")
	}
	return i.VerifyMessage(token.Input.Bytes(), token.Authenticator)
}

func (i *Issuer) VerifyPrivateIdentityPresentation(p PrivateIdentityPresentation, now time.Time, maxSkew time.Duration) ([32]byte, error) {
	if err := i.VerifyPrivateIdentityToken(p.Token); err != nil {
		return [32]byte{}, err
	}
	if p.Origin == "" {
		return [32]byte{}, errors.New("origin required")
	}
	ts := time.Unix(p.IssuedAt, 0)
	if ts.After(now.Add(maxSkew)) || ts.Before(now.Add(-maxSkew)) {
		return [32]byte{}, errors.New("presentation timestamp outside allowed window")
	}
	msg := PrivateIdentityPresentationMessage(p.Origin, p.Nonce, p.Token.Digest(), p.IssuedAt)
	switch p.Token.Input.HolderAlg {
	case HolderAlgEd25519:
		if !ed25519.Verify(ed25519.PublicKey(p.Token.Input.HolderPub), msg, p.Signature) {
			return [32]byte{}, errors.New("ed25519 proof-of-possession rejected")
		}
	case HolderAlgMLDSA44:
		return [32]byte{}, errors.New("ml-dsa-44 proof-of-possession is not implemented")
	default:
		return [32]byte{}, fmt.Errorf("unsupported holder_alg 0x%02x", p.Token.Input.HolderAlg)
	}
	return p.Token.Pseudonym(), nil
}
