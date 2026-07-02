package faest

import "github.com/maceip/tamayo/field"

// Degree-2 QuickSilver for the PoMFRIT One-More-MAYO proof (QS_DEGREE = 2).
// Transpiled from pq_blind_signatures vole/optimized_bs/quicksilver.hpp:
// quicksilver_state<S, verifier, max_deg=2> and its value types
// quicksilver_gf2 / quicksilver_gfsecpar, with the challenge layout from
// constants.hpp (QS_CONSTANTS::CHALLENGE_BYTES = (3*lambda + 64)/8) and the
// constraint hashing from universal_hash.hpp.
//
// Representation notes, mapped from the reference:
//
//   - A prover gfsecpar value of degree d is a poly2d<d+1, lambda>: d+1 MAC
//     coefficients ascending in Delta, coeffs[d] being the committed value.
//     A prover gf2 value keeps its d MAC coefficients and the committed bit
//     (the leading coefficient) separately. A verifier value is only the
//     evaluation of that polynomial at Delta, plus its degree.
//   - The reference hash pair (hasher_gfsecpar_state keyed by
//     challenge[2L:3L], hasher_gfsecpar_64_state keyed by challenge[3L:3L+8],
//     combined with hash_combination = challenge[0:L], challenge[L:2L] in
//     finalize_hashes) is exactly the ZKHasher Horner hash with seed layout
//     (r0, r1, s, t): the KEY_POWS batching and the deferred poly_2secpar
//     reduction are performance shapes of the same GF(2)[X] expression, and
//     reduction is a ring homomorphism, so reducing per multiplication gives
//     identical bytes.
//   - combine_mac_masks(macs, off) computes Sum_t macs[off+t] * X^t; reduced
//     into the field that is SumPoly (Horner at the field element X).
//   - from_8_self / from_8_poly1 are ByteCombine / ByteCombineBits (the
//     gf8_in_gf* tables equal the ALPHA basis byte for byte), and
//     from_4_self / from_4_poly1 use the gf4_in_gf* tables (GF4Embed).

const qs2MaxDeg = 2

// --- prover ---

// QS2Prover mirrors quicksilver_state<S, false, 2>. macs holds one field
// element per witness bit, including the lambda MAC-mask bits appended after
// the real witness; witness likewise carries lambda/8 extra mask bytes.
type QS2Prover struct {
	f       field.Big
	witness []byte
	macs    [][]uint64
	h       [qs2MaxDeg]*ZKHasher
}

// NewQS2Prover initializes the prover state from the 3*lambda+64-bit
// QuickSilver challenge, one ZKHasher per MAC-polynomial coefficient.
func NewQS2Prover(f field.Big, witness []byte, macs [][]uint64, challenge []byte) *QS2Prover {
	return &QS2Prover{f: f, witness: witness, macs: macs,
		h: [qs2MaxDeg]*ZKHasher{NewZKHasher(f, challenge), NewZKHasher(f, challenge)}}
}

// QSP2Bit mirrors quicksilver_gf2<prover, deg>: deg ascending MAC coefficients
// plus the committed bit.
type QSP2Bit struct {
	f     field.Big
	mac   [][]uint64
	value byte
}

// QSP2El mirrors quicksilver_gfsecpar<prover, deg>: deg+1 ascending MAC
// coefficients, mac[deg] being the committed value.
type QSP2El struct {
	f   field.Big
	mac [][]uint64
}

// Deg returns the polynomial degree.
func (a QSP2Bit) Deg() int { return len(a.mac) }

// Deg returns the polynomial degree.
func (a QSP2El) Deg() int { return len(a.mac) - 1 }

// Value returns the committed bit.
func (a QSP2Bit) Value() byte { return a.value }

// Value returns the committed field element (the leading MAC coefficient).
func (a QSP2El) Value() []uint64 { return a.mac[len(a.mac)-1] }

// ToEl converts gf2 to gfsecpar of the same degree
// (quicksilver_gfsecpar(const quicksilver_gf2&)): the MAC coefficients carry
// over and the bit becomes the leading coefficient via from_1.
func (a QSP2Bit) ToEl() QSP2El {
	mac := make([][]uint64, len(a.mac)+1)
	copy(mac, a.mac)
	mac[len(a.mac)] = a.f.FromBit(a.value)
	return QSP2El{f: a.f, mac: mac}
}

// lift raises a to degree d (mac.shift_left<d-deg>): coefficients move up and
// the vacated low coefficients are zero.
func (a QSP2El) lift(d int) QSP2El {
	if d == a.Deg() {
		return a
	}
	shift := d - a.Deg()
	mac := make([][]uint64, d+1)
	for i := range mac {
		mac[i] = a.f.Zero()
	}
	copy(mac[shift:], a.mac)
	return QSP2El{f: a.f, mac: mac}
}

// Add returns a + b, lifting the lower-degree operand as the reference's
// implicit conversion constructors do.
func (a QSP2El) Add(b QSP2El) QSP2El {
	d := max(a.Deg(), b.Deg())
	a, b = a.lift(d), b.lift(d)
	mac := make([][]uint64, d+1)
	for i := range mac {
		mac[i] = a.f.Add(a.mac[i], b.mac[i])
	}
	return QSP2El{f: a.f, mac: mac}
}

// AddBit returns a + b (gfsecpar + gf2 goes through the gfsecpar conversion).
func (a QSP2El) AddBit(b QSP2Bit) QSP2El { return a.Add(b.ToEl()) }

// AddOne returns a + 1 (operator+(a, poly1)): the constant is a same-degree
// gfsecpar whose only nonzero coefficient is the leading one.
func (a QSP2El) AddOne() QSP2El {
	mac := make([][]uint64, len(a.mac))
	copy(mac, a.mac)
	mac[a.Deg()] = a.f.Add(mac[a.Deg()], a.f.One())
	return QSP2El{f: a.f, mac: mac}
}

// Add returns a + b over gf2. Only same-degree addition exists in the
// reference (mixed-degree gf2 sums are ambiguous there and never occur).
func (a QSP2Bit) Add(b QSP2Bit) QSP2Bit {
	if a.Deg() != b.Deg() {
		panic("faest: quicksilver gf2 add degree mismatch")
	}
	mac := make([][]uint64, len(a.mac))
	for i := range mac {
		mac[i] = a.f.Add(a.mac[i], b.mac[i])
	}
	return QSP2Bit{f: a.f, mac: mac, value: a.value ^ b.value}
}

// Mul returns a * b; degrees add. Coefficient k of the product MAC polynomial
// is Sum_{i+j=k} a[i]*b[j] (poly2d operator* followed by reduce_to).
func (a QSP2El) Mul(b QSP2El) QSP2El {
	f := a.f
	d := a.Deg() + b.Deg()
	if d > qs2MaxDeg {
		panic("faest: quicksilver degree overflow")
	}
	mac := make([][]uint64, d+1)
	for i := range mac {
		mac[i] = f.Zero()
	}
	for i, ai := range a.mac {
		for j, bj := range b.mac {
			mac[i+j] = f.Add(mac[i+j], f.Mul(ai, bj))
		}
	}
	return QSP2El{f: f, mac: mac}
}

// MulBit returns a * b for gfsecpar a and gf2 b:
// a.mac*b.mac + (a.mac * b.value) << deg(b).
func (a QSP2El) MulBit(b QSP2Bit) QSP2El {
	f := a.f
	d := a.Deg() + b.Deg()
	if d > qs2MaxDeg {
		panic("faest: quicksilver degree overflow")
	}
	mac := make([][]uint64, d+1)
	for i := range mac {
		mac[i] = f.Zero()
	}
	for i, ai := range a.mac {
		for j, bj := range b.mac {
			mac[i+j] = f.Add(mac[i+j], f.Mul(ai, bj))
		}
	}
	if b.value != 0 {
		for i, ai := range a.mac {
			mac[i+b.Deg()] = f.Add(mac[i+b.Deg()], ai)
		}
	}
	return QSP2El{f: f, mac: mac}
}

// MulBit returns a * b over gf2:
// a.mac*b.mac + (a.mac*b.value) << deg(b) + (b.mac*a.value) << deg(a),
// value = a.value & b.value.
func (a QSP2Bit) MulBit(b QSP2Bit) QSP2Bit {
	f := a.f
	d := a.Deg() + b.Deg()
	if d > qs2MaxDeg {
		panic("faest: quicksilver degree overflow")
	}
	mac := make([][]uint64, d)
	for i := range mac {
		mac[i] = f.Zero()
	}
	for i, ai := range a.mac {
		for j, bj := range b.mac {
			mac[i+j] = f.Add(mac[i+j], f.Mul(ai, bj))
		}
	}
	if b.value != 0 {
		for i, ai := range a.mac {
			mac[i+b.Deg()] = f.Add(mac[i+b.Deg()], ai)
		}
	}
	if a.value != 0 {
		for j, bj := range b.mac {
			mac[j+a.Deg()] = f.Add(mac[j+a.Deg()], bj)
		}
	}
	return QSP2Bit{f: f, mac: mac, value: a.value & b.value}
}

// MulScalar returns c * a for a public field element c
// (quicksilver_gfsecpar<0>(c) * a): every coefficient is scaled.
func (a QSP2El) MulScalar(c []uint64) QSP2El {
	mac := make([][]uint64, len(a.mac))
	for i := range a.mac {
		mac[i] = a.f.Mul(a.mac[i], c)
	}
	return QSP2El{f: a.f, mac: mac}
}

// ConstEl returns the degree-0 public constant c.
func (p *QS2Prover) ConstEl(c []uint64) QSP2El {
	return QSP2El{f: p.f, mac: [][]uint64{c}}
}

// ZeroEl returns the zero element of degree d.
func (p *QS2Prover) ZeroEl(d int) QSP2El {
	mac := make([][]uint64, d+1)
	for i := range mac {
		mac[i] = p.f.Zero()
	}
	return QSP2El{f: p.f, mac: mac}
}

// GetWitnessBit mirrors get_witness_bit: degree-1 gf2 with the bit's MAC as
// the constant coefficient.
func (p *QS2Prover) GetWitnessBit(index int) QSP2Bit {
	return QSP2Bit{f: p.f,
		mac:   [][]uint64{p.macs[index]},
		value: (p.witness[index/8] >> (index % 8)) & 1}
}

// combineBits mirrors combine_8_bits / combine_4_bits (prover side): each MAC
// coefficient goes through from_{8,4}_self and the bits through
// from_{8,4}_poly1.
func (p *QS2Prover) combineBits(bits []QSP2Bit) QSP2El {
	f := p.f
	deg := bits[0].Deg()
	mac := make([][]uint64, deg+1)
	for i := 0; i < deg; i++ {
		macsI := make([][]uint64, len(bits))
		for j := range bits {
			macsI[j] = bits[j].mac[i]
		}
		mac[i] = combineEmbedTags(f, macsI)
	}
	var b byte
	for j := range bits {
		b |= bits[j].value << j
	}
	mac[deg] = combineEmbedBits(f, b, len(bits))
	return QSP2El{f: f, mac: mac}
}

// LoadWitness8BitsAndCombine mirrors load_witness_8_bits_and_combine.
func (p *QS2Prover) LoadWitness8BitsAndCombine(bitIndex int) QSP2El {
	bits := make([]QSP2Bit, 8)
	for j := range bits {
		bits[j] = p.GetWitnessBit(bitIndex + j)
	}
	return p.combineBits(bits)
}

// LoadWitness4BitsAndCombine mirrors load_witness_4_bits_and_combine.
func (p *QS2Prover) LoadWitness4BitsAndCombine(bitIndex int) QSP2El {
	bits := make([]QSP2Bit, 4)
	for j := range bits {
		bits[j] = p.GetWitnessBit(bitIndex + j)
	}
	return p.combineBits(bits)
}

// AddConstraint mirrors add_constraint: x is lifted to degree 2, its committed
// value must be zero, and MAC coefficient i feeds hasher i.
func (p *QS2Prover) AddConstraint(x QSP2El) {
	x = x.lift(qs2MaxDeg)
	for _, limb := range x.Value() {
		if limb != 0 {
			panic("faest: quicksilver constraint value != 0")
		}
	}
	p.h[0].Update(x.mac[0])
	p.h[1].Update(x.mac[1])
}

// Prove mirrors prove(witness_bits, proof, check). The MAC mask
// (combine_mac_masks over the lambda mask bits) enters the coefficient-0 hash
// and the mask witness bits, read as a field element, the coefficient-1 hash.
func (p *QS2Prover) Prove(witnessBits int) (proof, check []byte) {
	f := p.f
	lambda := f.Bytes * 8
	maskMac := f.SumPoly(p.macs[witnessBits : witnessBits+lambda])
	maskValue := f.FromBytes(p.witness[witnessBits/8 : witnessBits/8+f.Bytes])
	check = f.ToBytes(p.h[0].Finalize(maskMac))
	proof = f.ToBytes(p.h[1].Finalize(maskValue))
	return proof, check
}

// --- verifier ---

// QS2Verifier mirrors quicksilver_state<S, true, 2>. macs holds the verifier
// keys (tag + bit*Delta) for every witness bit including the mask bits.
type QS2Verifier struct {
	f           field.Big
	macs        [][]uint64
	deltaPowers [qs2MaxDeg][]uint64
	h           *ZKHasher
}

// NewQS2Verifier initializes the verifier state; deltaPowers = [Delta,
// Delta^2] as in the reference constructor.
func NewQS2Verifier(f field.Big, macs [][]uint64, delta []uint64, challenge []byte) *QS2Verifier {
	v := &QS2Verifier{f: f, macs: macs, h: NewZKHasher(f, challenge)}
	v.deltaPowers[0] = delta
	v.deltaPowers[1] = f.Mul(delta, delta)
	return v
}

// QSV2El mirrors both verifier value types (gf2 derives from gfsecpar in the
// reference): the MAC polynomial evaluated at Delta, plus the degree.
type QSV2El struct {
	st  *QS2Verifier
	deg int
	mac []uint64
}

// Deg returns the polynomial degree.
func (a QSV2El) Deg() int { return a.deg }

// lift raises a to degree d by multiplying with Delta^(d-deg)
// (delta_powers[d-deg-1]).
func (a QSV2El) lift(d int) QSV2El {
	if d == a.deg {
		return a
	}
	return QSV2El{st: a.st, deg: d, mac: a.st.f.Mul(a.mac, a.st.deltaPowers[d-a.deg-1])}
}

// Add returns a + b, lifting the lower-degree operand.
func (a QSV2El) Add(b QSV2El) QSV2El {
	d := max(a.deg, b.deg)
	a, b = a.lift(d), b.lift(d)
	return QSV2El{st: a.st, deg: d, mac: a.st.f.Add(a.mac, b.mac)}
}

// AddOne returns a + 1: the same-degree constant 1 evaluates to Delta^deg.
func (a QSV2El) AddOne() QSV2El {
	c := a.st.f.One()
	if a.deg > 0 {
		c = a.st.deltaPowers[a.deg-1]
	}
	return QSV2El{st: a.st, deg: a.deg, mac: a.st.f.Add(a.mac, c)}
}

// Mul returns a * b; evaluations multiply and degrees add.
func (a QSV2El) Mul(b QSV2El) QSV2El {
	d := a.deg + b.deg
	if d > qs2MaxDeg {
		panic("faest: quicksilver degree overflow")
	}
	return QSV2El{st: a.st, deg: d, mac: a.st.f.Mul(a.mac, b.mac)}
}

// MulScalar returns c * a for a public field element c (degree preserved).
func (a QSV2El) MulScalar(c []uint64) QSV2El {
	return QSV2El{st: a.st, deg: a.deg, mac: a.st.f.Mul(a.mac, c)}
}

// ConstEl returns the degree-0 public constant c.
func (v *QS2Verifier) ConstEl(c []uint64) QSV2El {
	return QSV2El{st: v, deg: 0, mac: c}
}

// ZeroEl returns the zero element of degree d.
func (v *QS2Verifier) ZeroEl(d int) QSV2El {
	return QSV2El{st: v, deg: d, mac: v.f.Zero()}
}

// GetWitnessBit mirrors get_witness_bit (verifier): degree 1, the key.
func (v *QS2Verifier) GetWitnessBit(index int) QSV2El {
	return QSV2El{st: v, deg: 1, mac: v.macs[index]}
}

// LoadWitness8BitsAndCombine mirrors the verifier combine_8_bits path.
func (v *QS2Verifier) LoadWitness8BitsAndCombine(bitIndex int) QSV2El {
	macs := make([][]uint64, 8)
	for j := range macs {
		macs[j] = v.macs[bitIndex+j]
	}
	return QSV2El{st: v, deg: 1, mac: combineEmbedTags(v.f, macs)}
}

// LoadWitness4BitsAndCombine mirrors the verifier combine_4_bits path.
func (v *QS2Verifier) LoadWitness4BitsAndCombine(bitIndex int) QSV2El {
	macs := make([][]uint64, 4)
	for j := range macs {
		macs[j] = v.macs[bitIndex+j]
	}
	return QSV2El{st: v, deg: 1, mac: combineEmbedTags(v.f, macs)}
}

// AddConstraint mirrors add_constraint (verifier): lift to degree 2 and hash
// the evaluation.
func (v *QS2Verifier) AddConstraint(x QSV2El) {
	v.h.Update(x.lift(qs2MaxDeg).mac)
}

// Verify mirrors verify(witness_bits, proof, check): the key mask plus
// proof * Delta^(max_deg-1) closes the hash.
func (v *QS2Verifier) Verify(witnessBits int, proof []byte) (check []byte) {
	f := v.f
	lambda := f.Bytes * 8
	mask := f.SumPoly(v.macs[witnessBits : witnessBits+lambda])
	mask = f.Add(mask, f.Mul(f.FromBytes(proof), v.deltaPowers[qs2MaxDeg-2]))
	return f.ToBytes(v.h.Finalize(mask))
}

// --- shared embedding helpers ---

// combineEmbedTags is from_8_self / from_4_self: x[0] + Sum x[i]*basis[i-1],
// with the GF(2^8) ALPHA basis for 8 elements and the GF(16) gf4_in_gf basis
// for 4.
func combineEmbedTags(f field.Big, x [][]uint64) []uint64 {
	if len(x) == 8 {
		return f.ByteCombine(x)
	}
	g := f.GF4Embed()
	sum := append([]uint64(nil), x[0]...)
	for i := 1; i < 4; i++ {
		sum = f.Add(sum, f.Mul(x[i], g[i-1]))
	}
	return sum
}

// combineEmbedBits is from_8_poly1 / from_4_poly1 over the bits of b.
func combineEmbedBits(f field.Big, b byte, n int) []uint64 {
	if n == 8 {
		return f.ByteCombineBits(b)
	}
	g := f.GF4Embed()
	sum := f.FromBit(b)
	for i := 1; i < 4; i++ {
		if (b>>i)&1 != 0 {
			sum = f.Add(sum, g[i-1])
		}
	}
	return sum
}
