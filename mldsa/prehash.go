package mldsa

// HashML-DSA (FIPS 204 §5.4, algorithms 4/5): the pre-hash variant signs a
// digest of the message under a hash function identified by its OID, instead
// of the message itself. The formatted representative is
//
//	M' = 0x01 || len(ctx) || ctx || OID(PH) || PH(M)
//
// and the internal signing/verification are identical to pure ML-DSA — only
// the leading domain byte (0x01 vs 0x00) and the OID||digest tail differ.

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
)

// PreHash identifies an approved pre-hash function: its DER-encoded OID and
// the digest it produces. The zero value is invalid.
type PreHash struct {
	name string
	oid  []byte
	sum  func([]byte) []byte
}

// Name returns the ACVP/JOSE label (e.g. "SHA2-256").
func (p PreHash) Name() string { return p.name }

// oidTail builds the 11-byte DER OID 2.16.840.1.101.3.4.2.<n> shared by all
// the NIST hash functions.
func oidTail(n byte) []byte {
	return []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, n}
}

func shakeSum(bits int) func([]byte) []byte {
	return func(m []byte) []byte {
		x := sha3.NewSHAKE256()
		if bits == 256 {
			x = sha3.NewSHAKE128()
		}
		x.Write(m)
		out := make([]byte, bits/8) // SHAKE-128 -> 256 bits, SHAKE-256 -> 512 bits
		x.Read(out)
		return out
	}
}

// The twelve approved pre-hash functions (FIPS 204 + NIST CSOR OIDs).
var (
	PreHashSHA224     = PreHash{"SHA2-224", oidTail(4), func(m []byte) []byte { s := sha256.Sum224(m); return s[:] }}
	PreHashSHA256     = PreHash{"SHA2-256", oidTail(1), func(m []byte) []byte { s := sha256.Sum256(m); return s[:] }}
	PreHashSHA384     = PreHash{"SHA2-384", oidTail(2), func(m []byte) []byte { s := sha512.Sum384(m); return s[:] }}
	PreHashSHA512     = PreHash{"SHA2-512", oidTail(3), func(m []byte) []byte { s := sha512.Sum512(m); return s[:] }}
	PreHashSHA512_224 = PreHash{"SHA2-512/224", oidTail(5), func(m []byte) []byte { s := sha512.Sum512_224(m); return s[:] }}
	PreHashSHA512_256 = PreHash{"SHA2-512/256", oidTail(6), func(m []byte) []byte { s := sha512.Sum512_256(m); return s[:] }}
	PreHashSHA3_224   = PreHash{"SHA3-224", oidTail(7), func(m []byte) []byte { s := sha3.Sum224(m); return s[:] }}
	PreHashSHA3_256   = PreHash{"SHA3-256", oidTail(8), func(m []byte) []byte { s := sha3.Sum256(m); return s[:] }}
	PreHashSHA3_384   = PreHash{"SHA3-384", oidTail(9), func(m []byte) []byte { s := sha3.Sum384(m); return s[:] }}
	PreHashSHA3_512   = PreHash{"SHA3-512", oidTail(10), func(m []byte) []byte { s := sha3.Sum512(m); return s[:] }}
	PreHashSHAKE128   = PreHash{"SHAKE-128", oidTail(11), shakeSum(256)}
	PreHashSHAKE256   = PreHash{"SHAKE-256", oidTail(12), shakeSum(512)}
)

// formatPreHash builds M' for the pre-hash variant.
func formatPreHash(ph PreHash, msg, ctx []byte) ([]byte, error) {
	if ph.sum == nil {
		return nil, errors.New("mldsa: invalid pre-hash function")
	}
	if len(ctx) > 255 {
		return nil, errors.New("mldsa: context longer than 255 bytes")
	}
	digest := ph.sum(msg)
	m := make([]byte, 0, 2+len(ctx)+len(ph.oid)+len(digest))
	m = append(m, 1, byte(len(ctx)))
	m = append(m, ctx...)
	m = append(m, ph.oid...)
	return append(m, digest...), nil
}

// SignPreHash is HashML-DSA.Sign (FIPS 204 algorithm 4) with caller-supplied
// 32-byte randomness rnd (pass 32 zero bytes for the deterministic variant).
func (p *Params) SignPreHash(sk, msg, ctx []byte, ph PreHash, rnd []byte) ([]byte, error) {
	m, err := formatPreHash(ph, msg, ctx)
	if err != nil {
		return nil, err
	}
	return p.SignInternal(sk, m, rnd)
}

// VerifyPreHash is HashML-DSA.Verify (FIPS 204 algorithm 5).
func (p *Params) VerifyPreHash(pk, msg, sig, ctx []byte, ph PreHash) bool {
	m, err := formatPreHash(ph, msg, ctx)
	if err != nil {
		return false
	}
	return p.VerifyInternal(pk, m, sig)
}
