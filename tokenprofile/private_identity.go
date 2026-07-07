package tokenprofile

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/maceip/tamayo/faest"
	"github.com/maceip/tamayo/mldsa"
)

const (
	PrivateIdentityTokenType = uint16(0x5056)
	HolderAlgEd25519         = byte(0x01)
	HolderAlgMLDSA44         = byte(0x02)
	HolderAlgFAEST128s       = byte(0x03)
	privateIdentityInputHead = 2 + 4 + 32 + 1
	popDomain                = "eat-pass/pvt-pop\x00"
	pseudonymDomain          = "tamayo/private-identity-pseudonym\x00"
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
		return mldsa.MLDSA44.PublicKeySize, nil
	case HolderAlgFAEST128s:
		return faestPublicKeyLen(faest.FAEST128s), nil
	default:
		return 0, fmt.Errorf("unsupported holder_alg 0x%02x", alg)
	}
}

func FAEST128sPublicKeyBytes(pk *faest.PublicKey) []byte {
	if pk == nil {
		return nil
	}
	out := make([]byte, 0, faestPublicKeyLen(faest.FAEST128s))
	out = append(out, pk.OwfInput...)
	out = append(out, pk.OwfOutput...)
	return out
}

func parseFAEST128sPublicKey(b []byte) (*faest.PublicKey, error) {
	want := faestPublicKeyLen(faest.FAEST128s)
	if len(b) != want {
		return nil, fmt.Errorf("faest-128s public key is %d bytes, want %d", len(b), want)
	}
	inputLen := faest.FAEST128s.OWF.InputSize
	return &faest.PublicKey{
		OwfInput:  append([]byte(nil), b[:inputLen]...),
		OwfOutput: append([]byte(nil), b[inputLen:]...),
	}, nil
}

func faestPublicKeyLen(params faest.FaestParams) int {
	return params.OWF.InputSize + params.OWF.Beta*16
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

func (p PrivateIdentityToken) PseudonymForOrigin(origin string) [32]byte {
	buf := make([]byte, 0, len(pseudonymDomain)+4+len(origin)+len(p.Input.HolderPub))
	buf = append(buf, pseudonymDomain...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(origin)))
	buf = append(buf, origin...)
	buf = append(buf, p.Input.HolderPub...)
	return digest(buf)
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
	out := make([]byte, 0, len(popDomain)+4+len(origin)+32+32+8)
	out = append(out, popDomain...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(origin)))
	out = append(out, origin...)
	out = append(out, nonce[:]...)
	out = append(out, tokenDigest[:]...)
	out = binary.BigEndian.AppendUint64(out, uint64(issuedAt))
	return out
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
		// Pure ML-DSA-44 with an empty context, matching the eat-pass PVT
		// cnf-key convention (the Rust ml-dsa crate's default).
		if !mldsa.MLDSA44.Verify(p.Token.Input.HolderPub, msg, p.Signature, nil) {
			return [32]byte{}, errors.New("ml-dsa-44 proof-of-possession rejected")
		}
	case HolderAlgFAEST128s:
		pk, err := parseFAEST128sPublicKey(p.Token.Input.HolderPub)
		if err != nil {
			return [32]byte{}, err
		}
		if !faest.FAEST128s.Verify(msg, pk, p.Signature) {
			return [32]byte{}, errors.New("faest-128s proof-of-possession rejected")
		}
	default:
		return [32]byte{}, fmt.Errorf("unsupported holder_alg 0x%02x", p.Token.Input.HolderAlg)
	}
	return p.Token.PseudonymForOrigin(p.Origin), nil
}
