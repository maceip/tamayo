package tokenprofile

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	BurnTokenType = uint16(0x4550)
	burnInputLen  = 2 + 32 + 32 + 32
)

// BurnToken is the one-request privacy token. Product services decide how to
// record spent nonces; this package verifies only the token cryptography and
// challenge binding.
type BurnToken struct {
	TokenType       uint16
	Nonce           [32]byte
	ChallengeDigest [32]byte
	TokenKeyID      [32]byte
	Authenticator   []byte
}

// BurnInput returns the blind-signed input for a burn token.
func BurnInput(nonce, challengeDigest, tokenKeyID [32]byte) []byte {
	out := make([]byte, 0, burnInputLen)
	out = binary.BigEndian.AppendUint16(out, BurnTokenType)
	out = append(out, nonce[:]...)
	out = append(out, challengeDigest[:]...)
	out = append(out, tokenKeyID[:]...)
	return out
}

func (t BurnToken) Input() []byte {
	return BurnInput(t.Nonce, t.ChallengeDigest, t.TokenKeyID)
}

func (t BurnToken) Bytes() []byte {
	out := make([]byte, 0, burnInputLen+len(t.Authenticator))
	out = binary.BigEndian.AppendUint16(out, t.TokenType)
	out = append(out, t.Nonce[:]...)
	out = append(out, t.ChallengeDigest[:]...)
	out = append(out, t.TokenKeyID[:]...)
	out = append(out, t.Authenticator...)
	return out
}

func ParseBurnToken(b []byte) (BurnToken, error) {
	if len(b) <= burnInputLen+authenticatorRandomLength {
		return BurnToken{}, fmt.Errorf("burn token is %d bytes, too short", len(b))
	}
	tokenType := binary.BigEndian.Uint16(b[:2])
	if tokenType != BurnTokenType {
		return BurnToken{}, fmt.Errorf("token type 0x%04x unsupported", tokenType)
	}
	var t BurnToken
	t.TokenType = tokenType
	copy(t.Nonce[:], b[2:34])
	copy(t.ChallengeDigest[:], b[34:66])
	copy(t.TokenKeyID[:], b[66:98])
	t.Authenticator = append([]byte(nil), b[98:]...)
	return t, nil
}

func (i *Issuer) VerifyBurnToken(token BurnToken, challengeDigest [32]byte) error {
	if token.TokenType != BurnTokenType {
		return fmt.Errorf("token type 0x%04x unsupported", token.TokenType)
	}
	if token.ChallengeDigest != challengeDigest {
		return errors.New("challenge digest mismatch")
	}
	if token.TokenKeyID != i.tokenKeyID {
		return errors.New("token_key_id mismatch")
	}
	return i.VerifyMessage(token.Input(), token.Authenticator)
}
