package pomfrit

import (
	"crypto/sha3"

	"github.com/maceip/tamayo/field"
)

// MAYO-eval OWF constraint circuit for One-More-MAYO. Transpiled from
// pq_blind_signatures vole/optimized_bs/owf_proof.inc (enc_constraints /
// owf_constraints) onto the degree-2 QuickSilver (quicksilver2.go). The circuit
// proves the whipped MAYO relation T*(s) = h + r with a single degree-2
// constraint, collapsing MAYO's m row-equations via a random
// GF(16)->GF(2^lambda) embedding drawn from chal2.

// sampleRandomEmbedding builds the m*16 embedding table from chal2: for each
// row i a field element r_i = SHAKE(chal2[:2*lambda])[i] is drawn, and entry
// [16i+n] = r_i * embed(n) with embed(n) the GF(16) nibble n mapped by the
// basis {1, W, W^2, W^3} (W = gf4_in_gf[0]). Transpiled from
// owf_proof.inc sample_random_embedding.
func (p MayoParams) sampleRandomEmbedding(f field.Big, chal2 []byte) [][]uint64 {
	lam := f.Bytes
	gf4 := f.GF4Embed() // [W, W^2, W^3]

	var h *sha3.SHAKE
	if lam == 16 {
		h = sha3.NewSHAKE128()
	} else {
		h = sha3.NewSHAKE256()
	}
	h.Write(chal2[:2*lam])
	// The reference consumes randomness in sizeof(poly_secpar<S>) strides:
	// poly<192> is two 128-bit lanes (32 bytes, top 64 bits ignored), so at
	// lambda=192 each element strides 32 bytes but only its first 24 are used.
	// lambda 128/256 have no gap (16/32 == lambda bytes).
	polySize := lam
	if lam == 24 {
		polySize = 32
	}
	randomness := make([]byte, p.M*polySize)
	h.Read(randomness)

	table := make([][]uint64, p.M*16)
	for i := 0; i < p.M; i++ {
		ri := f.FromBytes(randomness[i*polySize : i*polySize+lam])
		b := i * 16
		table[b+0] = f.Zero()
		table[b+1] = ri
		table[b+2] = f.Mul(gf4[0], ri)
		table[b+4] = f.Mul(gf4[1], ri)
		table[b+8] = f.Mul(gf4[2], ri)
		table[b+3] = f.Add(table[b+2], table[b+1])
		table[b+5] = f.Add(table[b+4], table[b+1])
		table[b+6] = f.Add(table[b+4], table[b+2])
		table[b+7] = f.Add(table[b+4], table[b+3])
		for n := 9; n < 16; n++ {
			table[b+n] = f.Add(table[b+8], table[b+n-8])
		}
	}
	return table
}

// embedGF16Vec embeds a nibble-packed public GF(16) m-vector into a single field
// element via the embedding table. Transpiled from owf_proof.inc embed_gf16_vec.
func (p MayoParams) embedGF16Vec(f field.Big, table [][]uint64, vec []byte) []uint64 {
	poly := f.Zero()
	for i := 0; i < p.M; i += 2 {
		lo := int(vec[i/2] & 0xf)
		hi := int((vec[i/2] >> 4) & 0xf)
		poly = f.Add(poly, table[i*16+lo])
		poly = f.Add(poly, table[(i+1)*16+hi])
	}
	return poly
}

// embedGF16VecAt embeds the m-vector stored at u64 offset off of data.
func (p MayoParams) embedGF16VecAt(f field.Big, table [][]uint64, data []uint64, off int) []uint64 {
	poly := f.Zero()
	for i := 0; i < p.M; i += 2 {
		b := mayoMVecByte(data, off, i/2)
		poly = f.Add(poly, table[i*16+int(b&0xf)])
		poly = f.Add(poly, table[(i+1)*16+int((b>>4)&0xf)])
	}
	return poly
}

// MayoConstraintProve builds the prover's degree-2 constraint element u +
// t_embedded and folds it into the QuickSilver via AddConstraint. Transpiled
// from enc_constraints (prover instantiation).
func (p MayoParams) MayoConstraintProve(qs *QS2Prover, pkBytes, h, chal2 []byte) {
	f := qs.f
	table := p.sampleRandomEmbedding(f, chal2)
	u64s := p.u64sPerVec()

	r := make([]QSP2El, p.M)
	for i := 0; i < p.M; i++ {
		r[i] = qs.LoadWitness4BitsAndCombine(4 * i)
	}
	rEmb := qs.ZeroEl(1)
	for i := 0; i < p.M; i++ {
		rEmb = rEmb.Add(r[i].MulScalar(table[16*i+1]))
	}

	sN := p.K * p.N
	s := make([]QSP2El, sN)
	for idx := 0; idx < sN; idx++ {
		s[idx] = qs.LoadWitness4BitsAndCombine(4 * (p.M + idx))
	}

	hEmb := p.embedGF16Vec(f, table, h)
	tEmb := qs.ConstEl(hEmb).lift(1).Add(rEmb)

	expandedPk := p.combineP1P2P3(pkBytes)
	u := qs.ZeroEl(2)
	As := make([]QSP2El, p.N)
	for i := 0; i < p.K; i++ {
		for j := p.K - 1; j >= i; j-- {
			if i != 0 || j != p.K-1 {
				p.applyEP(expandedPk, p.N*(p.N+1)/2)
			}
			for a := 0; a < p.N; a++ {
				As[a] = qs.ZeroEl(1)
			}
			ctr := 0
			for a := 0; a < p.N; a++ {
				if i != j {
					ctr++
				}
				bStart := a
				if i != j {
					bStart = a + 1
				}
				for b := bStart; b < p.N; b++ {
					col := p.embedGF16VecAt(f, table, expandedPk, ctr*u64s)
					ctr++
					As[a] = As[a].Add(s[j*p.N+b].MulScalar(col))
					if i != j {
						As[b] = As[b].Add(s[j*p.N+a].MulScalar(col))
					}
				}
			}
			for a := 0; a < p.N; a++ {
				u = u.Add(As[a].Mul(s[i*p.N+a]))
			}
		}
	}

	qs.AddConstraint(u.Add(tEmb))
}

// MayoConstraintVerify builds the verifier's evaluation of u + t_embedded and
// folds it into the QuickSilver. Transpiled from enc_constraints (verifier).
func (p MayoParams) MayoConstraintVerify(qs *QS2Verifier, pkBytes, h, chal2 []byte) {
	f := qs.f
	table := p.sampleRandomEmbedding(f, chal2)
	u64s := p.u64sPerVec()

	r := make([]QSV2El, p.M)
	for i := 0; i < p.M; i++ {
		r[i] = qs.LoadWitness4BitsAndCombine(4 * i)
	}
	rEmb := qs.ZeroEl(1)
	for i := 0; i < p.M; i++ {
		rEmb = rEmb.Add(r[i].MulScalar(table[16*i+1]))
	}

	sN := p.K * p.N
	s := make([]QSV2El, sN)
	for idx := 0; idx < sN; idx++ {
		s[idx] = qs.LoadWitness4BitsAndCombine(4 * (p.M + idx))
	}

	hEmb := p.embedGF16Vec(f, table, h)
	tEmb := qs.ConstEl(hEmb).lift(1).Add(rEmb)

	expandedPk := p.combineP1P2P3(pkBytes)
	u := qs.ZeroEl(2)
	As := make([]QSV2El, p.N)
	for i := 0; i < p.K; i++ {
		for j := p.K - 1; j >= i; j-- {
			if i != 0 || j != p.K-1 {
				p.applyEP(expandedPk, p.N*(p.N+1)/2)
			}
			for a := 0; a < p.N; a++ {
				As[a] = qs.ZeroEl(1)
			}
			ctr := 0
			for a := 0; a < p.N; a++ {
				if i != j {
					ctr++
				}
				bStart := a
				if i != j {
					bStart = a + 1
				}
				for b := bStart; b < p.N; b++ {
					col := p.embedGF16VecAt(f, table, expandedPk, ctr*u64s)
					ctr++
					As[a] = As[a].Add(s[j*p.N+b].MulScalar(col))
					if i != j {
						As[b] = As[b].Add(s[j*p.N+a].MulScalar(col))
					}
				}
			}
			for a := 0; a < p.N; a++ {
				u = u.Add(As[a].Mul(s[i*p.N+a]))
			}
		}
	}

	qs.AddConstraint(u.Add(tEmb))
}

// field on QS2Prover/Verifier exposes the working field for callers.
func (p *QS2Prover) Field() field.Big   { return p.f }
func (v *QS2Verifier) Field() field.Big { return v.f }

// newSHAKEForDiag exposes the embedding SHAKE selection for the diagnostic test.
func (p MayoParams) newSHAKEForDiag(lambdaBytes int) *sha3.SHAKE {
	if lambdaBytes == 16 {
		return sha3.NewSHAKE128()
	}
	return sha3.NewSHAKE256()
}
