package field

// GF8 is an element of GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1
// (the AES field; modulus low byte 0x1b). Transpiled from faest-rs
// src/fields/small_fields.rs (SmallGF<u8>).
type GF8 uint8

// Mul returns a * b via bit-serial multiplication with reduction by 0x1b.
// Branch-free: FAEST's witness extension calls this on secret key material
// (invnorm), so like the other fields here it must not branch on operands.
func (a GF8) Mul(b GF8) GF8 {
	l := uint8(a)
	r := uint8(b)
	res := l & -(r & 1)
	for i := 1; i < 8; i++ {
		l = (l << 1) ^ (0x1b & -(l >> 7))
		res ^= l & -((r >> uint(i)) & 1)
	}
	return GF8(res)
}

// Square returns a * a.
func (a GF8) Square() GF8 { return a.Mul(a) }

// SquareBits returns a^2 via the closed-form bit formula (equivalent to Square).
// Transpiled from faest-rs src/fields/small_fields.rs (GF8::square_bits).
func (a GF8) SquareBits() GF8 {
	x := uint8(a)
	res := (x ^ (x >> 4) ^ (x >> 6)) & 0x1
	res |= ((x >> 3) ^ (x >> 5) ^ (x >> 6)) & 0x2
	res |= ((x << 1) ^ (x >> 3)) & 0x4
	res |= ((x >> 1) ^ (x >> 2) ^ (x >> 3) ^ (x >> 4)) & 0x8
	res |= ((x << 2) ^ x ^ (x >> 3)) & 0x10
	res |= (x ^ (x >> 1)) & 0x20
	res |= ((x << 3) ^ (x << 1)) & 0x40
	res |= ((x << 1) ^ x) & 0x80
	return GF8(res)
}
