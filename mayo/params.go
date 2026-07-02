// Package mayo implements the MAYO post-quantum signature scheme (NIST PQC
// round 2 parameters), a whipped Oil-and-Vinegar multivariate signature over
// GF(16).
//
// It is a pure-Go port of the MAYO reference (PQCMayo/MAYO-C, cross-checked
// against the pq-mayo Rust crate) and is validated against the official MAYO
// round 2 known-answer tests. It has no dependencies beyond the Go standard
// library and this repository's crypto/gf16, so it builds for every
// GOOS=tamago target.
package mayo

// F_TAIL_LEN is the number of tail coefficients of the field polynomial f(X).
const fTailLen = 4

// Params holds the constants of one MAYO parameter set.
//
// Field element count is over GF(16); byte sizes below are the nibble-packed
// serializations used by the reference.
type Params struct {
	Name string

	N int // total variables
	M int // equations
	O int // oil dimension
	K int // whipping parameter

	MVecLimbs int // u64 limbs per m-vector (bitsliced form)

	MBytes int // m field elements, nibble-packed
	OBytes int // O matrix, nibble-packed
	VBytes int // vinegar vector, nibble-packed
	RBytes int // random vector r, nibble-packed

	P1Bytes int
	P2Bytes int
	P3Bytes int

	CSKBytes int // compact secret key
	CPKBytes int // compact public key
	SigBytes int

	SaltBytes   int
	DigestBytes int
	PKSeedBytes int
	SKSeedBytes int

	FTail [fTailLen]byte // tail coefficients of the irreducible f(X)
}

// V is the vinegar dimension v = n - o.
func (p *Params) V() int { return p.N - p.O }

// ACols is the number of columns of the linearized system A (k*o + 1).
func (p *Params) ACols() int { return p.K*p.O + 1 }

// P1Limbs is the number of u64 limbs for P1 in bitsliced form.
func (p *Params) P1Limbs() int { v := p.V(); return v * (v + 1) / 2 * p.MVecLimbs }

// P2Limbs is the number of u64 limbs for P2 in bitsliced form.
func (p *Params) P2Limbs() int { return p.V() * p.O * p.MVecLimbs }

// P3Limbs is the number of u64 limbs for P3 in bitsliced form.
func (p *Params) P3Limbs() int { return p.O * (p.O + 1) / 2 * p.MVecLimbs }

// The four MAYO round 2 parameter sets.
var (
	Mayo1 = Params{
		Name: "MAYO_1",
		N:    86, M: 78, O: 8, K: 10, MVecLimbs: 5,
		MBytes: 39, OBytes: 312, VBytes: 39, RBytes: 40,
		P1Bytes: 120159, P2Bytes: 24336, P3Bytes: 1404,
		CSKBytes: 24, CPKBytes: 1420, SigBytes: 454,
		SaltBytes: 24, DigestBytes: 32, PKSeedBytes: 16, SKSeedBytes: 24,
		FTail: [4]byte{8, 1, 1, 0},
	}
	Mayo2 = Params{
		Name: "MAYO_2",
		N:    96, M: 64, O: 16, K: 4, MVecLimbs: 4,
		MBytes: 32, OBytes: 640, VBytes: 40, RBytes: 32,
		P1Bytes: 103680, P2Bytes: 40960, P3Bytes: 4352,
		CSKBytes: 24, CPKBytes: 4368, SigBytes: 216,
		SaltBytes: 24, DigestBytes: 32, PKSeedBytes: 16, SKSeedBytes: 24,
		FTail: [4]byte{8, 0, 2, 8},
	}
	Mayo3 = Params{
		Name: "MAYO_3",
		N:    118, M: 108, O: 10, K: 11, MVecLimbs: 7,
		MBytes: 54, OBytes: 540, VBytes: 54, RBytes: 55,
		P1Bytes: 317844, P2Bytes: 58320, P3Bytes: 2970,
		CSKBytes: 32, CPKBytes: 2986, SigBytes: 681,
		SaltBytes: 32, DigestBytes: 48, PKSeedBytes: 16, SKSeedBytes: 32,
		FTail: [4]byte{8, 0, 1, 7},
	}
	Mayo5 = Params{
		Name: "MAYO_5",
		N:    154, M: 142, O: 12, K: 12, MVecLimbs: 9,
		MBytes: 71, OBytes: 852, VBytes: 71, RBytes: 72,
		P1Bytes: 720863, P2Bytes: 120984, P3Bytes: 5538,
		CSKBytes: 40, CPKBytes: 5554, SigBytes: 964,
		SaltBytes: 40, DigestBytes: 64, PKSeedBytes: 16, SKSeedBytes: 40,
		FTail: [4]byte{4, 0, 8, 1},
	}
)
