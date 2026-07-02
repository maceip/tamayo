package faest

import "github.com/maceip/tamayo/field"

// VoleHasher is the FAEST VOLE universal hash, used for the VOLE consistency
// check. Transpiled from faest-rs src/universal_hashing.rs (VoleHasher,
// new_vole_hasher, process/process_split/process_block). It is generic over the
// security-level field via field.Big; the inner lane uses GF64.
type VoleHasher struct {
	f field.Big
	r [4][]uint64
	s []uint64
	t field.GF64
}

// NewVoleHasher builds the hasher from the seed sd, which is
// 5*Bytes + 8 bytes long: r[0..3], s (each a field element), then an 8-byte GF64
// value t.
func NewVoleHasher(f field.Big, sd []byte) *VoleHasher {
	fl := f.Bytes
	vh := &VoleHasher{f: f}
	for i := 0; i < 4; i++ {
		vh.r[i] = f.FromBytes(sd[i*fl : (i+1)*fl])
	}
	vh.s = f.FromBytes(sd[4*fl : 5*fl])
	vh.t = field.GF64FromBytes(sd[5*fl : 5*fl+8])
	return vh
}

// outputLen is Bytes + 2 (the field element plus the extra B = 2 bytes).
func (vh *VoleHasher) outputLen() int { return vh.f.Bytes + 2 }

func (vh *VoleHasher) processBlock(h0 *[]uint64, h1 *field.GF64, block []byte) {
	*h0 = vh.f.Add(vh.f.Mul(*h0, vh.s), vh.f.FromBytes(block))
	for j := 0; j+8 <= len(block); j += 8 {
		*h1 = (*h1).Mul(vh.t).Add(field.GF64FromBytes(block[j : j+8]))
	}
}

// Process hashes x (which must be longer than the output length) to outputLen
// bytes.
func (vh *VoleHasher) Process(x []byte) []byte {
	ol := vh.outputLen()
	fl := vh.f.Bytes
	x0 := x[:len(x)-ol]
	x1 := x[len(x)-ol:]

	h0 := vh.f.Zero()
	var h1 field.GF64

	i := 0
	for i+fl <= len(x0) {
		vh.processBlock(&h0, &h1, x0[i:i+fl])
		i += fl
	}
	if i < len(x0) {
		buf := make([]byte, fl)
		copy(buf, x0[i:])
		vh.processBlock(&h0, &h1, buf)
	}

	h2 := vh.f.Add(vh.f.Mul(vh.r[0], h0), vh.f.MulGF64(vh.r[1], h1))
	h3 := vh.f.Add(vh.f.Mul(vh.r[2], h0), vh.f.MulGF64(vh.r[3], h1))

	out := make([]byte, ol)
	copy(out[:fl], vh.f.ToBytes(h2))
	h3b := vh.f.ToBytes(h3)
	copy(out[fl:fl+2], h3b[:2])
	for j := 0; j < ol; j++ {
		out[j] ^= x1[j]
	}
	return out
}
