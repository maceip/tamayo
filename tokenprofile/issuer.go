package tokenprofile

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/maceip/tamayo/mayo"
	"github.com/maceip/tamayo/pomfrit"
)

const (
	Algorithm                 = "PoMFRIT-MAYO1-FV1-128"
	authenticatorRandomLength = 32
)

// Issuer holds one PoMFRIT/MAYO issuer key epoch.
type Issuer struct {
	keyVersion uint32
	cpk        []byte
	csk        []byte
	epk        []byte
	tokenKeyID [32]byte
	owf        pomfrit.MayoOWF
	params     *mayo.Params
}

// NewIssuer creates a MAYO1/PoMFRIT issuer. If seed is nil or empty, fresh
// entropy is read from crypto/rand. Deterministic seeds are useful for tests and
// reproducible fixtures.
func NewIssuer(keyVersion uint32, seed []byte) (*Issuer, error) {
	if keyVersion == 0 {
		return nil, errors.New("key version must be > 0")
	}
	params := &mayo.Mayo1
	if len(seed) == 0 {
		var err error
		seed, err = randomBytes(params.SKSeedBytes)
		if err != nil {
			return nil, fmt.Errorf("issuer seed: %w", err)
		}
	}
	if len(seed) != params.SKSeedBytes {
		return nil, fmt.Errorf("issuer seed is %d bytes, want %d", len(seed), params.SKSeedBytes)
	}
	cpk, csk, err := params.CompactKeyGen(seed)
	if err != nil {
		return nil, err
	}
	epk, err := params.ExpandPK(cpk)
	if err != nil {
		return nil, err
	}
	return &Issuer{
		keyVersion: keyVersion,
		cpk:        cpk,
		csk:        csk,
		epk:        epk,
		tokenKeyID: sha256.Sum256(cpk),
		owf:        pomfrit.MayoOWFL1,
		params:     params,
	}, nil
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

// KeyVersion returns the issuer epoch identifier.
func (i *Issuer) KeyVersion() uint32 {
	return i.keyVersion
}

// CompactPublicKey returns a defensive copy of the MAYO compact public key.
func (i *Issuer) CompactPublicKey() []byte {
	return append([]byte(nil), i.cpk...)
}

// ExpandedPublicKey returns a defensive copy of the public map used by PoMFRIT
// verification.
func (i *Issuer) ExpandedPublicKey() []byte {
	return append([]byte(nil), i.epk...)
}

// TokenKeyID returns sha256(compact public key).
func (i *Issuer) TokenKeyID() [32]byte {
	return i.tokenKeyID
}

// BlindSign signs blinded PoMFRIT targets. It is intentionally type-oblivious:
// a burn-token target and a private-identity-token target have the same blinded
// shape.
func (i *Issuer) BlindSign(blinded [][]byte) ([][]byte, error) {
	out := make([][]byte, 0, len(blinded))
	for idx, target := range blinded {
		if len(target) != i.params.MBytes {
			return nil, fmt.Errorf("blinded target %d is %d bytes, want %d", idx, len(target), i.params.MBytes)
		}
		sig := i.params.SignWithoutHashing(target, i.csk)
		if len(sig) == 0 {
			return nil, fmt.Errorf("blinded target %d could not be signed", idx)
		}
		out = append(out, sig)
	}
	return out, nil
}

// VerifyMessage verifies a PoMFRIT authenticator over a token signed input.
func (i *Issuer) VerifyMessage(message, authenticator []byte) error {
	if len(authenticator) <= authenticatorRandomLength {
		return errors.New("authenticator too short")
	}
	additionalR := authenticator[:authenticatorRandomLength]
	proof := authenticator[authenticatorRandomLength:]
	if !i.owf.BlindVerify(i.epk, message, proof, additionalR) {
		return errors.New("pomfrit proof rejected")
	}
	return nil
}

// BlindState is the client-side state retained between PrepareBlind and
// FinalizeBlind.
type BlindState struct {
	additionalR [authenticatorRandomLength]byte
	proofState  pomfrit.MayoProveState
	h           []byte
}

// PrepareBlind blinds message and returns the issuer-facing target plus the
// client-side state needed to finalize the authenticator.
func PrepareBlind(message []byte, additionalR [authenticatorRandomLength]byte) ([]byte, BlindState) {
	target, proofState, h := pomfrit.MayoOWFL1.Sign1(message, additionalR[:])
	return target, BlindState{
		additionalR: additionalR,
		proofState:  proofState,
		h:           append([]byte(nil), h...),
	}
}

// FinalizeBlind converts a blind signature into an authenticator. The returned
// bytes are additional_r || PoMFRIT proof.
func FinalizeBlind(expandedPublicKey, blindSignature []byte, state BlindState) ([]byte, error) {
	proof := pomfrit.MayoOWFL1.Sign3(expandedPublicKey, state.h, blindSignature, state.proofState, state.additionalR[:])
	if len(proof.Bytes) == 0 {
		return nil, errors.New("empty PoMFRIT proof")
	}
	out := make([]byte, 0, authenticatorRandomLength+len(proof.Bytes))
	out = append(out, state.additionalR[:]...)
	out = append(out, proof.Bytes...)
	return out, nil
}

func digest(b []byte) [32]byte {
	return sha256.Sum256(b)
}
