package tokenauth

// FAEST-signed policy sidecars, ported from the reference policy signing
// module: a policy JSON file travels with a detached `.sig` sidecar
// (standard-base64 FAEST-128f signature over the exact file bytes), and a
// runtime configured with trusted operator keys refuses a policy whose
// sidecar does not verify. Pure byte operations — file naming and I/O live
// with the caller (cmd/tamayo sign-policy, serve -policy-pub).

import (
	"crypto/sha3"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/maceip/tamayo/faest"
)

// PolicySigner holds an operator's FAEST-128f policy-signing key
// (Go-specific SHAKE256 seed derivation; wire-compatible signatures).
type PolicySigner struct {
	sk []byte
	pk *faest.PublicKey
}

// NewPolicySigner derives the operator key pair from a 32-byte seed.
func NewPolicySigner(seed []byte) (*PolicySigner, error) {
	if len(seed) != 32 {
		return nil, errors.New("tokenauth: policy signer seed must be 32 bytes")
	}
	x := sha3.NewSHAKE256()
	x.Write([]byte("tamayo/policy-sidecar\x00"))
	x.Write(seed)
	sk, pk, err := faest.FAEST128f.KeyGen(x)
	if err != nil {
		return nil, err
	}
	return &PolicySigner{sk: sk, pk: pk}, nil
}

// Public returns the 32-byte verification key operators publish.
func (s *PolicySigner) Public() [32]byte {
	var out [32]byte
	copy(out[:16], s.pk.OwfInput)
	copy(out[16:], s.pk.OwfOutput)
	return out
}

// SignPolicy checks that policyJSON compiles, then returns the sidecar
// content: a standard-base64 FAEST-128f signature over the exact bytes.
// rho is the FAEST signer randomness (nil selects deterministic).
func (s *PolicySigner) SignPolicy(policyJSON, rho []byte) (string, error) {
	if _, err := CompileJSON(policyJSON); err != nil {
		return "", err
	}
	if rho == nil {
		rho = make([]byte, faest.FAEST128f.OWF.LambdaBytes)
	}
	return base64.StdEncoding.EncodeToString(faest.FAEST128f.Sign(policyJSON, s.sk, rho)), nil
}

// VerifyPolicySidecar checks the sidecar signature over the exact policy
// bytes against any of the trusted operator keys. An empty trusted set
// means sidecar verification is not configured and always passes, matching
// the reference semantics.
func VerifyPolicySidecar(policyJSON []byte, sidecar string, trustedPubs [][32]byte) error {
	if len(trustedPubs) == 0 {
		return nil
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sidecar))
	if err != nil {
		return errors.New("policy sidecar bad base64")
	}
	for _, pub := range trustedPubs {
		pk := &faest.PublicKey{OwfInput: pub[:16], OwfOutput: pub[16:]}
		if faest.FAEST128f.Verify(policyJSON, pk, sig) {
			return nil
		}
	}
	return errors.New("policy sidecar signature does not verify under any trusted key")
}
