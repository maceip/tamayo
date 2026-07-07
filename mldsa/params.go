// Package mldsa implements the ML-DSA (FIPS 204) lattice signature at the
// three standardized parameter sets, pure Go and cgo-free. Transpiled from
// the FIPS 204 final pseudocode (August 2024); verified byte-exact against
// the NIST ACVP ML-DSA-{keyGen,sigGen,sigVer}-FIPS204 vector sets vendored
// in testdata/ (see SOURCES.md).
package mldsa

// Ring and rounding constants shared by every parameter set (FIPS 204 §4).
const (
	q     = 8380417 // 2^23 - 2^13 + 1
	n     = 256
	d     = 13
	zeta  = 1753    // 512th root of unity mod q
	nInv  = 8347681 // 256^-1 mod q
	seedB = 32      // xi, rho, K sizes
)

// Params holds one ML-DSA parameter set (FIPS 204 table 1) plus its derived
// sizes. The three instances below are the only valid values.
type Params struct {
	Name   string
	K, L   int   // matrix dimensions
	Eta    int32 // secret key range
	Tau    int   // # of +-1s in the challenge polynomial
	Beta   int32 // Tau * Eta
	Gamma1 int32 // y coefficient range, 2^17 or 2^19
	Gamma2 int32 // low-order rounding range, (q-1)/88 or (q-1)/32
	Omega  int   // max # of hint bits
	Lambda int   // collision strength: c-tilde is Lambda/4 bytes

	etaBits int // bits per s1/s2 coefficient: bitlen(2*Eta)
	zBits   int // bits per z coefficient: 1 + bitlen(Gamma1-1)
	w1Bits  int // bits per w1 coefficient: bitlen((q-1)/(2*Gamma2)-1)

	PublicKeySize  int
	PrivateKeySize int
	SignatureSize  int
}

func newParams(name string, k, l int, eta int32, tau int, gamma1, gamma2 int32, omega, lambda, etaBits, zBits, w1Bits int) *Params {
	p := &Params{
		Name: name, K: k, L: l, Eta: eta, Tau: tau, Beta: int32(tau) * eta,
		Gamma1: gamma1, Gamma2: gamma2, Omega: omega, Lambda: lambda,
		etaBits: etaBits, zBits: zBits, w1Bits: w1Bits,
	}
	p.PublicKeySize = seedB + k*n/8*10
	p.PrivateKeySize = 2*seedB + 64 + (k+l)*n/8*etaBits + k*n/8*d
	p.SignatureSize = lambda/4 + l*n/8*zBits + omega + k
	return p
}

// The three FIPS 204 parameter sets.
var (
	MLDSA44 = newParams("ML-DSA-44", 4, 4, 2, 39, 1<<17, (q-1)/88, 80, 128, 3, 18, 6)
	MLDSA65 = newParams("ML-DSA-65", 6, 5, 4, 49, 1<<19, (q-1)/32, 55, 192, 4, 20, 4)
	MLDSA87 = newParams("ML-DSA-87", 8, 7, 2, 60, 1<<19, (q-1)/32, 75, 256, 3, 20, 4)
)
