package tokenauth

// The split attester/issuer trust boundary, ported from the reference
// authorize module and wire-compatible with it: an attester that verified
// gate evidence returns a short-lived, FAEST-128f-signed
// IssuanceAuthorization over the mint's channel binding, and an issuer in a
// different process mints only on presentation of a valid one — it never
// sees or judges the raw evidence, only the keyed rate-limit bucket. When
// attester and issuer live in the same process, the unsigned MintDecision
// is sufficient; this envelope exists for the cross-process split.

import (
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/maceip/tamayo/faest"
)

// AuthorizationVersion is the wire version; bump on breaking changes.
const AuthorizationVersion = uint32(1)

// DefaultAuthorizationTTLSecs is the authorization lifetime when the
// attester does not override.
const DefaultAuthorizationTTLSecs = uint64(60)

const authDomain = "eat-pass/issuance-auth\x00"

// IssuanceAuthorization is the signed payload authorizing one blind-sign
// batch. The issuer learns only RateLimitID (a keyed hash), never the raw
// measurement. JSON field encodings match the reference (hex binding,
// standard-base64 rate_limit_id and sig).
type IssuanceAuthorization struct {
	Version     uint32 `json:"version"`
	BindingHex  string `json:"binding"`
	RateLimitID []byte `json:"-"`
	PolicyLabel string `json:"policy_label"`
	MaxBatch    uint32 `json:"max_batch"`
	Exp         uint64 `json:"exp"`
	Iat         uint64 `json:"iat"`
	Sig         []byte `json:"-"`

	RateLimitIDB64 string `json:"rate_limit_id"`
	SigB64         string `json:"sig"`
}

// Normalize fills the raw fields from their encoded JSON forms (call after
// unmarshalling) and vice versa (call before marshalling).
func (a *IssuanceAuthorization) Normalize() error {
	var err error
	if a.RateLimitIDB64 != "" && a.RateLimitID == nil {
		if a.RateLimitID, err = base64.StdEncoding.DecodeString(a.RateLimitIDB64); err != nil {
			return fmt.Errorf("rate_limit_id: %w", err)
		}
	}
	if a.SigB64 != "" && a.Sig == nil {
		if a.Sig, err = base64.StdEncoding.DecodeString(a.SigB64); err != nil {
			return fmt.Errorf("sig: %w", err)
		}
	}
	a.RateLimitIDB64 = base64.StdEncoding.EncodeToString(a.RateLimitID)
	a.SigB64 = base64.StdEncoding.EncodeToString(a.Sig)
	return nil
}

func (a *IssuanceAuthorization) binding() ([32]byte, error) {
	var out [32]byte
	v, err := hex.DecodeString(a.BindingHex)
	if err != nil || len(v) != 32 {
		return out, errors.New("authorization binding must be 32 hex bytes")
	}
	copy(out[:], v)
	return out, nil
}

// SignedBytes is the canonical byte string the attester signs (everything
// except sig), byte-identical to the reference layout.
func (a *IssuanceAuthorization) SignedBytes() ([]byte, error) {
	binding, err := a.binding()
	if err != nil {
		return nil, err
	}
	v := make([]byte, 0, len(authDomain)+4+32+4+len(a.RateLimitID)+4+len(a.PolicyLabel)+16)
	v = append(v, authDomain...)
	v = binary.LittleEndian.AppendUint32(v, a.Version)
	v = append(v, binding[:]...)
	v = binary.LittleEndian.AppendUint32(v, uint32(len(a.RateLimitID)))
	v = append(v, a.RateLimitID...)
	v = binary.LittleEndian.AppendUint32(v, uint32(len(a.PolicyLabel)))
	v = append(v, a.PolicyLabel...)
	v = binary.LittleEndian.AppendUint32(v, a.MaxBatch)
	v = binary.LittleEndian.AppendUint64(v, a.Exp)
	v = binary.LittleEndian.AppendUint64(v, a.Iat)
	return v, nil
}

// Verify checks the wire version, batch bound, expiry, and the attester's
// FAEST-128f signature.
func (a *IssuanceAuthorization) Verify(attesterPub [32]byte, now uint64) error {
	if a.Version != AuthorizationVersion {
		return fmt.Errorf("authorization version %d unsupported (want %d)", a.Version, AuthorizationVersion)
	}
	if a.MaxBatch == 0 {
		return errors.New("authorization max_batch must be non-zero")
	}
	if now > a.Exp {
		return errors.New("authorization expired")
	}
	msg, err := a.SignedBytes()
	if err != nil {
		return err
	}
	pk := &faest.PublicKey{OwfInput: attesterPub[:16], OwfOutput: attesterPub[16:]}
	if !faest.FAEST128f.Verify(msg, pk, a.Sig) {
		return errors.New("authorization signature rejected")
	}
	return nil
}

// AttesterSigner holds the attester's FAEST-128f key. The seed-to-key
// derivation is Go-specific (SHAKE256, like transparency.LogSigner);
// published keys and signatures are wire-compatible with the reference.
type AttesterSigner struct {
	sk []byte
	pk *faest.PublicKey
}

// NewAttesterSigner derives the attester key pair from a 32-byte seed.
func NewAttesterSigner(seed []byte) (*AttesterSigner, error) {
	if len(seed) != 32 {
		return nil, errors.New("tokenauth: attester seed must be 32 bytes")
	}
	x := sha3.NewSHAKE256()
	x.Write([]byte("tamayo/issuance-auth/attester\x00"))
	x.Write(seed)
	sk, pk, err := faest.FAEST128f.KeyGen(x)
	if err != nil {
		return nil, err
	}
	return &AttesterSigner{sk: sk, pk: pk}, nil
}

// Public returns the 32-byte attester verification key.
func (s *AttesterSigner) Public() [32]byte {
	var out [32]byte
	copy(out[:16], s.pk.OwfInput)
	copy(out[16:], s.pk.OwfOutput)
	return out
}

// Sign fills auth.Sig (and the encoded JSON fields) over the canonical
// bytes. rho is the FAEST signer randomness (nil selects deterministic).
func (s *AttesterSigner) Sign(auth *IssuanceAuthorization, rho []byte) error {
	if rho == nil {
		rho = make([]byte, faest.FAEST128f.OWF.LambdaBytes)
	}
	msg, err := auth.SignedBytes()
	if err != nil {
		return err
	}
	auth.Sig = faest.FAEST128f.Sign(msg, s.sk, rho)
	return auth.Normalize()
}
