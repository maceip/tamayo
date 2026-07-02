package faest

import "crypto/sha3"

// FAEST random-oracle domain-separation bytes (faest-rs src/random_oracles.rs:
// H0=0, H1=1, H2^{0..3}=8..11, H3=3, H4=4).
const (
	sepH0  byte = 0
	sepH1  byte = 1
	sepH2a byte = 8  // H2^0
	sepH2b byte = 9  // H2^1
	sepH2c byte = 10 // H2^2
	sepH2d byte = 11 // H2^3
	sepH3  byte = 3
	sepH4  byte = 4
)

// Hasher is a FAEST random oracle: a SHAKE XOF that appends a domain-separation
// byte before finalization. Transpiled from faest-rs src/random_oracles.rs
// (Hasher128/Hasher256). SHAKE128 is used at the 128-bit level, SHAKE256 at 192
// and 256.
type Hasher struct {
	x   *sha3.SHAKE
	sep byte
}

func newHasher(use256 bool, sep byte) *Hasher {
	if use256 {
		return &Hasher{x: sha3.NewSHAKE256(), sep: sep}
	}
	return &Hasher{x: sha3.NewSHAKE128(), sep: sep}
}

// Update absorbs data into the hash.
func (h *Hasher) Update(data []byte) { h.x.Write(data) }

// Finish appends the domain-separation byte and returns the XOF reader (the
// underlying SHAKE, whose Read produces the squeezed output).
func (h *Hasher) Finish() *sha3.SHAKE {
	h.x.Write([]byte{h.sep})
	return h.x
}

// Named constructors for the FAEST random oracles.
func H0(use256 bool) *Hasher  { return newHasher(use256, sepH0) }
func H1(use256 bool) *Hasher  { return newHasher(use256, sepH1) }
func H2a(use256 bool) *Hasher { return newHasher(use256, sepH2a) }
func H2b(use256 bool) *Hasher { return newHasher(use256, sepH2b) }
func H2c(use256 bool) *Hasher { return newHasher(use256, sepH2c) }
func H2d(use256 bool) *Hasher { return newHasher(use256, sepH2d) }
func H3(use256 bool) *Hasher  { return newHasher(use256, sepH3) }
func H4(use256 bool) *Hasher  { return newHasher(use256, sepH4) }
