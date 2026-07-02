package faest

import "github.com/maceip/tamayo/field"

// ZKHasher is the FAEST/QuickSilver ZK universal hash. It compresses a sequence
// of field elements v_0..v_{n-1} into two running Horner accumulators (one keyed
// by s in the full field, one by t in GF(2^64)) and combines them at finalize.
// Transpiled from faest-rs src/universal_hashing.rs (ZKHasher).
//
// The seed sd is 3*lambda + 8 bytes: r0, r1, s (each a field element) then an
// 8-byte GF64 value t.
type ZKHasher struct {
	f      field.Big
	h0, h1 []uint64
	s      []uint64
	t      field.GF64
	r0, r1 []uint64
}

// NewZKHasher initializes a ZK hasher from the seed sd.
func NewZKHasher(f field.Big, sd []byte) *ZKHasher {
	l := f.Bytes
	return &ZKHasher{
		f:  f,
		h0: f.Zero(),
		h1: f.Zero(),
		r0: f.FromBytes(sd[0:l]),
		r1: f.FromBytes(sd[l : 2*l]),
		s:  f.FromBytes(sd[2*l : 3*l]),
		t:  field.GF64FromBytes(sd[3*l : 3*l+8]),
	}
}

// Update folds one field element v into both accumulators:
// h0 = h0*s + v and h1 = h1*t + v.
func (z *ZKHasher) Update(v []uint64) {
	z.h0 = z.f.Add(z.f.Mul(z.h0, z.s), v)
	z.h1 = z.f.Add(z.f.MulGF64(z.h1, z.t), v)
}

// Finalize combines the accumulators with the seed and the final element x1:
// r0*h0 + r1*h1 + x1.
func (z *ZKHasher) Finalize(x1 []uint64) []uint64 {
	return z.f.Add(z.f.Add(z.f.Mul(z.r0, z.h0), z.f.Mul(z.r1, z.h1)), x1)
}
