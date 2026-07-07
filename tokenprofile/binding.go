package tokenprofile

import (
	"crypto/sha256"
	"encoding/binary"
)

// bindingDomain matches the eat-pass reference (pomfrit/src/lib.rs
// BINDING_DOMAIN) so bindings are wire-compatible across the Rust and Go
// stacks.
const bindingDomain = "eat-pass/binding\x00"

// BindingOf is the channel binding over a batch of blinded targets
// (eat-pass binding_of): SHA-256 over the domain, the big-endian batch
// count, and each length-prefixed target. The attester quotes this value
// before authorization, and the issuer recomputes it from the presented
// batch, so an authorization cannot be replayed for different blinded
// targets even though the issuer never sees token contents.
func BindingOf(blinded [][]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(bindingDomain))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(blinded)))
	h.Write(n[:])
	for _, b := range blinded {
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
