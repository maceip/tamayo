package mayo

import (
	"encoding/binary"
	"errors"
	"io"
)

// Exported MAYO API. Thin wrappers over the byte-exact-verified internals
// (keypairCompact, signSignature, mayoVerify, expandPublicKey), mirroring the
// MAYO-C entry points mayo_keypair / mayo_sign_signature / mayo_verify /
// mayo_expand_pk.

// CompactKeyGen derives a compact keypair from a secret seed of SKSeedBytes,
// as MAYO-C mayo_keypair does from its DRBG output. Deterministic in seedSK.
func (p *Params) CompactKeyGen(seedSK []byte) (cpk, csk []byte, err error) {
	if len(seedSK) != p.SKSeedBytes {
		return nil, nil, errors.New("mayo: seed must be SKSeedBytes long")
	}
	cpk = make([]byte, p.CPKBytes)
	csk = make([]byte, p.CSKBytes)
	keypairCompact(p, seedSK, cpk, csk)
	return cpk, csk, nil
}

// KeyGen samples a compact keypair with a fresh seed drawn from rand.
func (p *Params) KeyGen(rand io.Reader) (cpk, csk []byte, err error) {
	seed := make([]byte, p.SKSeedBytes)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	return p.CompactKeyGen(seed)
}

// Sign produces a MAYO signature (SigBytes: s ‖ salt) on msg under csk. The
// salt is derived from randomizer (SaltBytes), matching the reference flow
// where the NIST DRBG supplies it; fixing randomizer makes signing
// deterministic and reproduces the NIST KAT signatures byte-for-byte.
func (p *Params) Sign(msg, csk, randomizer []byte) ([]byte, error) {
	if len(csk) != p.CSKBytes {
		return nil, errors.New("mayo: bad csk length")
	}
	if len(randomizer) < p.SaltBytes {
		return nil, errors.New("mayo: randomizer must be at least SaltBytes")
	}
	sig := make([]byte, p.SigBytes)
	if err := signSignature(p, sig, msg, csk, randomizer); err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify reports whether sig is a valid MAYO signature on msg under the
// compact public key cpk.
func (p *Params) Verify(msg, sig, cpk []byte) bool {
	if len(sig) != p.SigBytes || len(cpk) != p.CPKBytes {
		return false
	}
	return mayoVerify(p, msg, sig, cpk)
}

// ExpandPK expands the compact public key into the full bitsliced public map
// P1 ‖ P2 ‖ P3 serialized as little-endian uint64 limbs — byte-identical to
// MAYO-C mayo_expand_pk's output buffer, and the epk format the pomfrit
// blind-signature engine consumes.
func (p *Params) ExpandPK(cpk []byte) ([]byte, error) {
	if len(cpk) != p.CPKBytes {
		return nil, errors.New("mayo: bad cpk length")
	}
	pk, p3 := expandPublicKey(p, cpk)
	out := make([]byte, (len(pk)+len(p3))*8)
	for i, v := range pk {
		binary.LittleEndian.PutUint64(out[i*8:], v)
	}
	off := len(pk) * 8
	for i, v := range p3 {
		binary.LittleEndian.PutUint64(out[off+i*8:], v)
	}
	return out, nil
}
