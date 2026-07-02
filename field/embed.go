package field

import "strconv"

// Field operations for embedding GF(2^8) bytes into the large binary fields,
// used by the FAEST OWF constraint circuit. Transpiled from faest-rs
// src/fields/large_fields.rs (Double, FromBit, ByteCombine, SumPoly) with the
// ALPHA basis from src/fields/large_fields_constants.rs.

// hexToLimbs parses a big-endian hex value into n little-endian uint64 limbs
// (limb 0 holds the least-significant 64 bits).
func hexToLimbs(s string, n int) []uint64 {
	for len(s) < n*16 {
		s = "0" + s
	}
	limbs := make([]uint64, n)
	for i := 0; i < n; i++ {
		v, err := strconv.ParseUint(s[len(s)-16*(i+1):len(s)-16*i], 16, 64)
		if err != nil {
			panic("field: bad ALPHA constant: " + err.Error())
		}
		limbs[i] = v
	}
	return limbs
}

var (
	alphaCache    = map[int][][]uint64{}
	sigmaCache    = map[int][][]uint64{}
	sigmaSqCache  = map[int][][]uint64{}
	betaSqCache   = map[int][][]uint64{}
	betaCubeCache = map[int][][]uint64{}
)

func buildCache(src map[int][]string) map[int][][]uint64 {
	out := map[int][][]uint64{}
	for length, hs := range src {
		n := length / 64
		arr := make([][]uint64, len(hs))
		for i := range hs {
			arr[i] = hexToLimbs(hs[i], n)
		}
		out[length] = arr
	}
	return out
}

func init() {
	alphaCache = buildCache(alphaHexGen)
	sigmaCache = buildCache(sigmaHexGen)
	sigmaSqCache = buildCache(sigmaSqHexGen)
	betaSqCache = buildCache(betaSqHexGen)
	betaCubeCache = buildCache(betaCubeHexGen)
}

// Sigma returns the S-box affine constants SIGMA (or SIGMA_SQUARES if sq).
func (p Big) Sigma(sq bool) [][]uint64 {
	if sq {
		return sigmaSqCache[p.length]
	}
	return sigmaCache[p.length]
}

// BetaSquares returns the BETA_SQUARES conjugate constants.
func (p Big) BetaSquares() [][]uint64 { return betaSqCache[p.length] }

// BetaCubes returns the BETA_CUBES conjugate constants.
func (p Big) BetaCubes() [][]uint64 { return betaCubeCache[p.length] }

// ByteCombine2/3 and their squared variants are the MixColumns constants,
// derived from ALPHA: BYTE_COMBINE_2 = ALPHA[0], BYTE_COMBINE_3 = ALPHA[0]+1,
// BYTE_COMBINE_SQ_2 = ALPHA[1], BYTE_COMBINE_SQ_3 = ALPHA[1]+1.
func (p Big) ByteCombine2(sq bool) []uint64 {
	if sq {
		return alphaCache[p.length][1]
	}
	return alphaCache[p.length][0]
}

func (p Big) ByteCombine3(sq bool) []uint64 {
	return p.Add(p.ByteCombine2(sq), p.One())
}

// One returns the multiplicative identity.
func (p Big) One() []uint64 {
	e := make([]uint64, p.N)
	e[0] = 1
	return e
}

func (p Big) two() []uint64 {
	e := make([]uint64, p.N)
	e[0] = 2
	return e
}

// Double returns a * X (multiplication by the field element 2).
func (p Big) Double(a []uint64) []uint64 { return p.Mul(a, p.two()) }

// FromBit returns One if the low bit of x is set, else Zero.
func (p Big) FromBit(x byte) []uint64 {
	if x&1 != 0 {
		return p.One()
	}
	return p.Zero()
}

// SumPoly evaluates the polynomial with coefficients v at X = 2:
// sum_i v[i] * 2^i. Transpiled from large_fields.rs SumPoly::sum_poly.
func (p Big) SumPoly(v [][]uint64) []uint64 {
	sum := append([]uint64(nil), v[len(v)-1]...)
	for i := len(v) - 2; i >= 0; i-- {
		sum = p.Add(p.Double(sum), v[i])
	}
	return sum
}

// SumPolyBits is SumPoly over the individual bits of v (LSB-first per byte).
func (p Big) SumPolyBits(v []byte) []uint64 {
	n := len(v) * 8
	sum := p.FromBit(v[len(v)-1] >> 7)
	for i := n - 2; i >= 0; i-- {
		sum = p.Add(p.Double(sum), p.FromBit(v[i/8]>>(i%8)))
	}
	return sum
}

// ByteCombine maps the eight field elements x (one per bit of a GF(2^8) byte)
// into a single field element x[0] + sum_{i=1..7} ALPHA[i-1]*x[i].
func (p Big) ByteCombine(x [][]uint64) []uint64 {
	alpha := alphaCache[p.length]
	sum := append([]uint64(nil), x[0]...)
	for i := 1; i < 8; i++ {
		sum = p.Add(sum, p.Mul(alpha[i-1], x[i]))
	}
	return sum
}

// ByteCombineBits maps the eight bits of x into a field element via the ALPHA
// basis.
func (p Big) ByteCombineBits(x byte) []uint64 {
	alpha := alphaCache[p.length]
	sum := p.FromBit(x)
	for i := 0; i < 7; i++ {
		if (x>>(i+1))&1 != 0 {
			sum = p.Add(sum, alpha[i])
		}
	}
	return sum
}

// Square returns a * a.
func (p Big) Square(a []uint64) []uint64 { return p.Mul(a, a) }

// GF4Embed returns the GF(16) generator powers [x, x^2, x^3] embedded into this
// field, used by the MAYO-eval circuit's GF(16)->GF(2^lambda) embedding.
func (p Big) GF4Embed() [3][]uint64 {
	b := gf4InGF[p.length]
	return [3][]uint64{p.FromBytes(b[0]), p.FromBytes(b[1]), p.FromBytes(b[2])}
}

// SquareByte maps the eight field elements representing a GF(2^8) byte to the
// eight elements of its square (the GF(2^8) Frobenius as a linear map).
// Transpiled from large_fields.rs SquareBytes::square_byte.
func (p Big) SquareByte(x [][]uint64) [][]uint64 {
	sq := make([][]uint64, 8)
	sq[0] = p.Add(p.Add(x[0], x[4]), x[6])
	sq[2] = p.Add(x[1], x[5])
	sq[4] = p.Add(p.Add(x[2], x[4]), x[7])
	sq[5] = p.Add(x[5], x[6])
	sq[6] = p.Add(x[3], x[5])
	sq[7] = p.Add(x[6], x[7])
	sq[1] = p.Add(x[4], sq[7])
	sq[3] = p.Add(x[5], sq[1])
	return sq
}

// ByteCombineSq is ByteCombine of the squared byte (byte_combine_sq_slice).
func (p Big) ByteCombineSq(x [][]uint64) []uint64 {
	return p.ByteCombine(p.SquareByte(x))
}

// ByteCombineBitsSq combines the bits of x^2 (byte_combine_bits_sq).
func (p Big) ByteCombineBitsSq(x byte) []uint64 {
	return p.ByteCombineBits(byte(GF8(x).SquareBits()))
}
