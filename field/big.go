package field

import "encoding/binary"

// Big is a raw-limb descriptor for one of the large binary fields, used by
// generic VOLE-in-the-Head engine code that must operate over the
// security-level field chosen at run time. Elements are []uint64 of length N
// (little-endian, tight).
type Big struct {
	Bytes  int // byte length of an element (16/24/32)
	N      int // number of uint64 limbs
	length int // field degree in bits
	mod    uint64
}

// Large-field descriptors: the three base fields, their degree-3 extension
// fields (GF384/576/768) used for VOLE tags and leaf commitments, and the
// RainHash GF512 field. Reduction tails from faest-rs large_fields.rs and
// rainhash_plain (x^512 + x^8 + x^5 + x^2 + 1).
var (
	Big128 = Big{Bytes: 16, N: 2, length: 128, mod: gf128Mod}
	Big192 = Big{Bytes: 24, N: 3, length: 192, mod: gf192Mod}
	Big256 = Big{Bytes: 32, N: 4, length: 256, mod: gf256Mod}

	Big384 = Big{Bytes: 48, N: 6, length: 384, mod: 0x100D}
	Big576 = Big{Bytes: 72, N: 9, length: 576, mod: 0x2019}
	Big768 = Big{Bytes: 96, N: 12, length: 768, mod: 0xA0011}

	Big512 = Big{Bytes: 64, N: 8, length: 512, mod: 0x125}
)

// Zero returns the additive identity.
func (p Big) Zero() []uint64 { return make([]uint64, p.N) }

// FromBytes decodes p.Bytes little-endian bytes into a field element.
func (p Big) FromBytes(b []byte) []uint64 {
	e := make([]uint64, p.N)
	for i := 0; i < p.N; i++ {
		e[i] = binary.LittleEndian.Uint64(b[i*8 : i*8+8])
	}
	return e
}

// ToBytes encodes a field element into p.Bytes little-endian bytes.
func (p Big) ToBytes(a []uint64) []byte {
	b := make([]byte, p.Bytes)
	for i := 0; i < p.N; i++ {
		binary.LittleEndian.PutUint64(b[i*8:i*8+8], a[i])
	}
	return b
}

// Add returns a + b.
func (p Big) Add(a, b []uint64) []uint64 {
	o := make([]uint64, p.N)
	for i := 0; i < p.N; i++ {
		o[i] = a[i] ^ b[i]
	}
	return o
}

// Mul returns a * b.
func (p Big) Mul(a, b []uint64) []uint64 {
	o := make([]uint64, p.N)
	mul(o, a, b, p.length, p.mod)
	return o
}

// MulGF64 returns a * b, with b a GF64 element embedded as a degree-<64 polynomial.
func (p Big) MulGF64(a []uint64, b GF64) []uint64 {
	tmp := make([]uint64, p.N)
	tmp[0] = uint64(b)
	return p.Mul(a, tmp)
}
