package field

import "encoding/binary"

// gf64Mod is the reduction tail of GF(2^64) = GF(2)[x]/(x^64+x^4+x^3+x+1).
const gf64Mod uint64 = 0x1b

// GF64 is an element of GF(2^64). Transpiled from faest-rs
// src/fields/small_fields.rs (SmallGF<u64>, GaloisFieldHelper::mul_helper).
type GF64 uint64

// GF64One is the multiplicative identity.
const GF64One GF64 = 1

// Add returns a + b (XOR).
func (a GF64) Add(b GF64) GF64 { return a ^ b }

// Mul returns a * b, constant-time bit-serial multiply with reduction.
func (a GF64) Mul(b GF64) GF64 {
	x := uint64(a)
	y := uint64(b)
	res := x & -(y & 1)
	for i := 1; i < 64; i++ {
		m := gf64Mod & -((x >> 63) & 1)
		x = (x << 1) ^ m
		res ^= x & -((y >> uint(i)) & 1)
	}
	return GF64(res)
}

// Bytes returns the 8-byte little-endian encoding.
func (a GF64) Bytes() [8]byte {
	var o [8]byte
	binary.LittleEndian.PutUint64(o[:], uint64(a))
	return o
}

// GF64FromBytes decodes an 8-byte little-endian element.
func GF64FromBytes(b []byte) GF64 { return GF64(binary.LittleEndian.Uint64(b)) }

// MulGF64 multiplies a GF128 element by a GF64 element embedded as a degree-<64
// polynomial (faest-rs Mul<GF64> for BigGF).
func (a GF128) MulGF64(b GF64) GF128 { return a.Mul(GF128{uint64(b), 0}) }

// MulGF64 multiplies a GF192 element by an embedded GF64 element.
func (a GF192) MulGF64(b GF64) GF192 { return a.Mul(GF192{uint64(b), 0, 0}) }

// MulGF64 multiplies a GF256 element by an embedded GF64 element.
func (a GF256) MulGF64(b GF64) GF256 { return a.Mul(GF256{uint64(b), 0, 0, 0}) }
