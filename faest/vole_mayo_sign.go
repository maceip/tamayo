package faest

import "crypto/sha3"

// One-More-MAYO VOLE prover transcript. Transpiled from pq_blind_signatures
// vole/optimized_bs/faest.inc (vole_prove_1 + vole_prove_2) for the v1 MAYO
// parameter sets, which use the ggm_forest BAVC with no grinding
// (use_grinding == false, grinding_counter_size == 0). The random oracle is
// plain SHAKE (SHAKE128 at lambda=128, else SHAKE256) with a trailing
// domain-separation byte, exactly as the reference's hash_state.

// MayoOWF binds the ggm_forest/VOLE parameters (MayoForest) with the whipped
// MAYO map parameters (MayoParams) for one security level.
type MayoOWF struct {
	F MayoForest
	P MayoParams
}

// The three v1 MAYO small instances.
var (
	MayoOWFL1 = MayoOWF{MayoForestL1, VoleMayoL1}
	MayoOWFL3 = MayoOWF{MayoForestL3, VoleMayoL3}
	MayoOWFL5 = MayoOWF{MayoForestL5, VoleMayoL5}
)

func (o MayoOWF) lam() int          { return o.F.LambdaBytes }
func (o MayoOWF) rBytes() int       { return o.P.M / 2 }           // ceil(4*M/8)
func (o MayoOWF) witnessBytes() int { return o.F.WitnessBits / 8 } // WITNESS_BITS % 8 == 0
func (o MayoOWF) expandedPkBytes() int {
	return o.P.N * (o.P.N + 1) / 2 * o.P.u64sPerVec() * 8
}
func (o MayoOWF) hBytes() int { return o.P.M / 2 }

// publicSize / secret layout (VOLEMAYO_PUBLIC_SIZE_BYTES etc).
func (o MayoOWF) publicSize() int { return o.expandedPkBytes() + o.hBytes() }

// voleCheckChallengeBytes = 5*lambda+8; qsChallengeBytes = 3*lambda+8.
func (o MayoOWF) voleCheckChallengeBytes() int { return 5*o.lam() + 8 }
func (o MayoOWF) qsChallengeBytes() int        { return 3*o.lam() + 8 }
func (o MayoOWF) voleCommitSize() int          { return (o.F.voleRows() / 8) * (o.F.Tau - 1) }
func (o MayoOWF) voleCheckProofBytes() int     { return o.lam() + 2 }
func (o MayoOWF) qsProofBytes() int            { return o.lam() }
func (o MayoOWF) openSize() int {
	return o.F.LambdaBytes*8*o.lam() + o.F.Tau*2*o.lam() // delta_bits*lambda + tau*hash_len
}

func (o MayoOWF) newXOF() *sha3.SHAKE {
	if o.lam() == 16 {
		return sha3.NewSHAKE128()
	}
	return sha3.NewSHAKE256()
}

// shakeS = SHAKE_S(concat(parts) || domain) squeezed to outLen bytes. domain < 0
// omits the trailing byte (used for the plain r_additional hash).
func (o MayoOWF) shakeS(outLen int, domain int, parts ...[]byte) []byte {
	x := o.newXOF()
	for _, p := range parts {
		x.Write(p)
	}
	if domain >= 0 {
		x.Write([]byte{byte(domain)})
	}
	out := make([]byte, outLen)
	x.Read(out)
	return out
}

// expandBitsToBytes maps the low nbits of x (LSB-first per byte) to nbits bytes,
// each 0x00 or 0xff. Transpiled from util.hpp expand_bits_to_bytes.
func expandBitsToBytes(x []byte, nbits int) []byte {
	out := make([]byte, nbits)
	for i := 0; i < nbits; i++ {
		if (x[i/8]>>(i%8))&1 != 0 {
			out[i] = 0xff
		}
	}
	return out
}

// MayoProof holds the assembled One-More-MAYO VOLE proof and its ordered
// segments, matching the reference proof byte layout.
type MayoProof struct {
	Bytes      []byte
	Commitment []byte
	UTilde     []byte
	D          []byte
	QSProof    []byte
	Opening    []byte
	Delta      []byte
	IVPre      []byte
}

// Prove runs vole_prove_1 + vole_prove_2 and returns the full proof. sk is the
// packed secret key (public || witness), pk the packed public key (expanded_pk
// || h), rAdditional the 32-byte blind-signature blinding value. Deterministic
// (seed derived from SHAKE(0x03)) exactly as the reference test harness.
func (o MayoOWF) Prove(sk, pk, rAdditional []byte) MayoProof {
	f := o.F.field()
	lam := o.lam()

	// vole_prove_1: (seed, iv_pre) = H(0x03); iv = H(iv_pre || 0x04).
	seedIVPre := o.shakeS(lam+16, 0x03)
	seed := seedIVPre[:lam]
	ivPre := seedIVPre[lam : lam+16]
	iv := o.shakeS(16, 0x04, ivPre)

	vc := o.F.MayoVoleCommit(seed, iv)

	rAddHash := o.shakeS(32, -1, rAdditional)
	chal1 := o.shakeS(o.voleCheckChallengeBytes(), 0x09, rAddHash, vc.Check, vc.Commitment, iv)

	// vole_prove_2: correction d (r part zero, s part u^s) and chal2.
	rB := o.rBytes()
	wB := o.witnessBytes()
	sPart := sk[o.publicSize()+rB : o.publicSize()+wB]
	d := make([]byte, wB)
	for i := rB; i < wB; i++ {
		d[i] = vc.U[i] ^ sPart[i-rB]
	}

	uTilde, colHashes := o.F.VoleCheckSenderBlocks(vc.U, vc.V, chal1)

	chal2Parts := [][]byte{rAdditional, chal1, uTilde}
	chal2Parts = append(chal2Parts, colHashes...)
	chal2Parts = append(chal2Parts, d)
	chal2 := o.shakeS(o.qsChallengeBytes(), 0x0a, chal2Parts...)

	// QS witness = VOLE u with the s region overwritten by the real s.
	qsWit := make([]byte, len(vc.U))
	copy(qsWit, vc.U)
	copy(qsWit[rB:wB], sPart)
	macsBytes := o.F.TransposeToMacs(vc.V, o.F.WitnessBits+lam*8)
	macs := make([][]uint64, len(macsBytes))
	for i := range macsBytes {
		macs[i] = f.FromBytes(macsBytes[i])
	}

	expandedPk := pk[:o.expandedPkBytes()]
	h := pk[o.expandedPkBytes() : o.expandedPkBytes()+o.hBytes()]

	qs := NewQS2Prover(f, qsWit, macs, chal2)
	o.P.MayoConstraintProve(qs, expandedPk, h, chal2)
	qsProof, qsCheck := qs.Prove(o.F.WitnessBits)

	// delta = H(chal2 || qs_check || qs_proof || 0x0B); open BAVC at delta.
	delta := o.shakeS(lam, 0x0b, chal2, qsCheck, qsProof)
	deltaBytes := expandBitsToBytes(delta, lam*8)
	opening := o.F.MayoForestOpen(vc.Forest, vc.HashedLeaves, deltaBytes)

	proof := make([]byte, 0, o.voleCommitSize()+o.voleCheckProofBytes()+wB+o.qsProofBytes()+o.openSize()+lam+16)
	proof = append(proof, vc.Commitment...)
	proof = append(proof, uTilde...)
	proof = append(proof, d...)
	proof = append(proof, qsProof...)
	proof = append(proof, opening...)
	proof = append(proof, delta...)
	proof = append(proof, ivPre...)

	return MayoProof{Bytes: proof, Commitment: vc.Commitment, UTilde: uTilde, D: d,
		QSProof: qsProof, Opening: opening, Delta: delta, IVPre: ivPre}
}
