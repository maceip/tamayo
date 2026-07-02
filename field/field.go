// Package field implements arithmetic over the binary Galois fields GF(2^128),
// GF(2^192) and GF(2^256) used by the VOLE-in-the-Head / FAEST proof system.
//
// Elements are stored as little-endian uint64 limbs (tight: 2/3/4 limbs). All
// operations are branch-free and constant time, pure Go, and build for every
// GOOS=tamago target.
//
// Transpiled from ait-crypto/faest-rs src/fields/large_fields.rs, using the
// generic bit-serial multiply (gf_mul / ShiftLeft1 / ToMask / Modulus). The
// reference's u128 Karatsuba+PCLMUL path is a later optimization that produces
// identical results. Reduction polynomials:
//
//	GF128: x^128 + x^7 + x^2 + x + 1   (tail 0x87)
//	GF192: x^192 + x^7 + x^2 + x + 1   (tail 0x87)
//	GF256: x^256 + x^10 + x^5 + x^2 + 1 (tail 0x425)
package field

import "encoding/binary"

const (
	gf128Mod uint64 = 0x87
	gf192Mod uint64 = 0x87
	gf256Mod uint64 = 0x425
)

// GF128, GF192, GF256 hold field elements as little-endian uint64 limbs.
type (
	GF128 [2]uint64
	GF192 [3]uint64
	GF256 [4]uint64
)

// maskBit returns all-ones if bit `bit` of v is set, else 0.
func maskBit(v []uint64, bit int) uint64 {
	return -((v[bit>>6] >> uint(bit&63)) & 1)
}

// shl1 shifts the limb array left by one bit (little-endian, low limb first).
func shl1(v []uint64) {
	for i := len(v) - 1; i > 0; i-- {
		v[i] = (v[i] << 1) | (v[i-1] >> 63)
	}
	v[0] <<= 1
}

// mul computes dst = a*b in GF(2^length) with length == 64*len(a) and reduction
// tail modLow, via the constant-time bit-serial schoolbook method.
func mul(dst, a, b []uint64, length int, modLow uint64) {
	n := len(a)
	self := make([]uint64, n)
	copy(self, a)
	res := make([]uint64, n)

	m0 := maskBit(b, 0)
	for i := 0; i < n; i++ {
		res[i] = self[i] & m0
	}
	for idx := 1; idx < length; idx++ {
		top := maskBit(self, length-1)
		shl1(self)
		self[0] ^= top & modLow
		mb := maskBit(b, idx)
		for i := 0; i < n; i++ {
			res[i] ^= self[i] & mb
		}
	}
	copy(dst, res)
}

// --- GF128 ---

// GF128One is the multiplicative identity.
var GF128One = GF128{1, 0}

func (a GF128) Add(b GF128) GF128 { return GF128{a[0] ^ b[0], a[1] ^ b[1]} }
func (a GF128) Mul(b GF128) GF128 { var o GF128; mul(o[:], a[:], b[:], 128, gf128Mod); return o }
func (a GF128) Square() GF128     { return a.Mul(a) }

func (a GF128) Bytes() [16]byte {
	var out [16]byte
	binary.LittleEndian.PutUint64(out[0:], a[0])
	binary.LittleEndian.PutUint64(out[8:], a[1])
	return out
}

// GF128FromBytes decodes a 16-byte little-endian element.
func GF128FromBytes(b []byte) GF128 {
	return GF128{binary.LittleEndian.Uint64(b[0:]), binary.LittleEndian.Uint64(b[8:])}
}

// --- GF192 ---

var GF192One = GF192{1, 0, 0}

func (a GF192) Add(b GF192) GF192 { return GF192{a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]} }
func (a GF192) Mul(b GF192) GF192 { var o GF192; mul(o[:], a[:], b[:], 192, gf192Mod); return o }
func (a GF192) Square() GF192     { return a.Mul(a) }

func (a GF192) Bytes() [24]byte {
	var out [24]byte
	binary.LittleEndian.PutUint64(out[0:], a[0])
	binary.LittleEndian.PutUint64(out[8:], a[1])
	binary.LittleEndian.PutUint64(out[16:], a[2])
	return out
}

// GF192FromBytes decodes a 24-byte little-endian element.
func GF192FromBytes(b []byte) GF192 {
	return GF192{
		binary.LittleEndian.Uint64(b[0:]),
		binary.LittleEndian.Uint64(b[8:]),
		binary.LittleEndian.Uint64(b[16:]),
	}
}

// --- GF256 ---

var GF256One = GF256{1, 0, 0, 0}

func (a GF256) Add(b GF256) GF256 {
	return GF256{a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]}
}
func (a GF256) Mul(b GF256) GF256 { var o GF256; mul(o[:], a[:], b[:], 256, gf256Mod); return o }
func (a GF256) Square() GF256     { return a.Mul(a) }

func (a GF256) Bytes() [32]byte {
	var out [32]byte
	binary.LittleEndian.PutUint64(out[0:], a[0])
	binary.LittleEndian.PutUint64(out[8:], a[1])
	binary.LittleEndian.PutUint64(out[16:], a[2])
	binary.LittleEndian.PutUint64(out[24:], a[3])
	return out
}

// GF256FromBytes decodes a 32-byte little-endian element.
func GF256FromBytes(b []byte) GF256 {
	return GF256{
		binary.LittleEndian.Uint64(b[0:]),
		binary.LittleEndian.Uint64(b[8:]),
		binary.LittleEndian.Uint64(b[16:]),
		binary.LittleEndian.Uint64(b[24:]),
	}
}
