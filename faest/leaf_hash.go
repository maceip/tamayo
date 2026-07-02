package faest

import "github.com/maceip/tamayo/field"

// LeafHash is the BAVC leaf-commitment hash, h = u·x0 + x1, computed in the
// degree-3 extension field ext (GF384/576/768). Transpiled from faest-rs
// universal_hashing.rs (LeafHasher::hash).
//
// uhash is 3·lambda bytes (an extension element u), x is 4·lambda bytes where the
// first lambda bytes are the base element x0 (embedded into ext) and the
// remaining 3·lambda bytes are the extension element x1. The result is 3·lambda
// bytes.
func LeafHash(ext field.Big, uhash, x []byte) []byte {
	lam := ext.Bytes / 3 // base field byte length (lambda)

	u := ext.FromBytes(uhash)

	x0pad := make([]byte, ext.Bytes)
	copy(x0pad, x[:lam]) // embed the base element into the low bits of ext
	x0 := ext.FromBytes(x0pad)

	x1 := ext.FromBytes(x[lam : 4*lam])

	h := ext.Add(ext.Mul(u, x0), x1)
	return ext.ToBytes(h)
}
