package pomfrit

import "crypto/sha3"

// shake256Sum returns SHAKE256(concat(parts)) squeezed to outLen bytes (the
// mayo-c-sys shake256 used by the blind sign_1/verify hashing of m || proof1).
func shake256Sum(outLen int, parts ...[]byte) []byte {
	x := sha3.NewSHAKE256()
	for _, p := range parts {
		x.Write(p)
	}
	out := make([]byte, outLen)
	x.Read(out)
	return out
}

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

// MayoProveState is the vole_prove_1 output carried into vole_prove_2 (the
// VOLEMAYOProofState of the reference): the VOLE correlation, BAVC artifacts,
// the derived r (= u[:R_BYTES]), the commitment (proof1) and chal1.
type MayoProveState struct {
	VC    MayoVoleCommitResult
	IVPre []byte
	Chal1 []byte
	R     []byte
}

// Prove1 runs vole_prove_1: derive the VOLE seed/iv deterministically from
// SHAKE(0x03)/H4, commit the ggm_forest VOLE, and derive r and chal1.
func (o MayoOWF) Prove1(rAdditional []byte) MayoProveState {
	lam := o.lam()
	seedIVPre := o.shakeS(lam+16, 0x03)
	seed := seedIVPre[:lam]
	ivPre := seedIVPre[lam : lam+16]
	iv := o.shakeS(16, 0x04, ivPre)

	vc := o.F.MayoVoleCommit(seed, iv)
	r := append([]byte(nil), vc.U[:o.rBytes()]...)

	rAddHash := o.shakeS(32, -1, rAdditional)
	chal1 := o.shakeS(o.voleCheckChallengeBytes(), 0x09, rAddHash, vc.Check, vc.Commitment, iv)

	return MayoProveState{VC: vc, IVPre: ivPre, Chal1: chal1, R: r}
}

// Prove2 runs vole_prove_2 from a prove-1 state, the packed pk (expanded_pk ||
// h) and packed sk (packed_pk || r || witness_s), returning the full proof.
func (o MayoOWF) Prove2(st MayoProveState, packedPk, packedSk, rAdditional []byte) MayoProof {
	f := o.F.field()
	lam := o.lam()
	vc := st.VC

	rB := o.rBytes()
	wB := o.witnessBytes()
	sPart := packedSk[o.publicSize()+rB : o.publicSize()+wB]
	d := make([]byte, wB)
	for i := rB; i < wB; i++ {
		d[i] = vc.U[i] ^ sPart[i-rB]
	}

	uTilde, colHashes := o.F.VoleCheckSenderBlocks(vc.U, vc.V, st.Chal1)

	chal2Parts := [][]byte{rAdditional, st.Chal1, uTilde}
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

	expandedPk := packedPk[:o.expandedPkBytes()]
	h := packedPk[o.expandedPkBytes() : o.expandedPkBytes()+o.hBytes()]

	qs := NewQS2Prover(f, qsWit, macs, chal2)
	o.P.MayoConstraintProve(qs, expandedPk, h, chal2)
	qsProof, qsCheck := qs.Prove(o.F.WitnessBits)

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
	proof = append(proof, st.IVPre...)

	return MayoProof{Bytes: proof, Commitment: vc.Commitment, UTilde: uTilde, D: d,
		QSProof: qsProof, Opening: opening, Delta: delta, IVPre: st.IVPre}
}

// Prove runs vole_prove_1 + vole_prove_2 in one shot (used by the VOLE-only
// KAT). sk is the packed secret key (public || witness), pk the packed public
// key (expanded_pk || h).
func (o MayoOWF) Prove(sk, pk, rAdditional []byte) MayoProof {
	st := o.Prove1(rAdditional)
	return o.Prove2(st, pk, sk, rAdditional)
}

// proof1Size is the prefix of the proof available after prove_1 (the VOLE
// commitment), hashed into the blinded message. Reference proof1_size =
// VOLE_COMMIT_SIZE.
func (o MayoOWF) proof1Size() int { return o.voleCommitSize() }

// ProofSize returns the exact byte length of a proof for this instance
// (6895/15862/29615 for L1/L3/L5).
func (o MayoOWF) ProofSize() int {
	return o.voleCommitSize() + o.voleCheckProofBytes() + o.witnessBytes() +
		o.qsProofBytes() + o.openSize() + o.lam() + 16
}

// Sign1 is the blind-signature sign_1: run prove_1, form the blinded message
// t = h + r with h = SHAKE256(m || proof1), and return t, the carried state,
// and h. h uses SHAKE256 at every level (reference mayo-c-sys shake256).
func (o MayoOWF) Sign1(m, rAdditional []byte) (t []byte, st MayoProveState, h []byte) {
	st = o.Prove1(rAdditional)
	proof1 := st.VC.Commitment[:o.proof1Size()]
	h = shake256Sum(o.hBytes(), m, proof1)
	t = make([]byte, o.hBytes())
	for i := range t {
		t[i] = h[i] ^ st.R[i]
	}
	return t, st, h
}

// Sign3 is the blind-signature sign_3: assemble packed_pk = epk || h and
// packed_sk = packed_pk || r || bsig, then run prove_2. bsig is the MAYO
// preimage of t from sign_2 (mayo.SignWithoutHashing).
func (o MayoOWF) Sign3(epk, h, bsig []byte, st MayoProveState, rAdditional []byte) MayoProof {
	packedPk := append(append([]byte(nil), epk...), h...)
	packedSk := append(append(append([]byte(nil), packedPk...), st.R...), bsig...)
	return o.Prove2(st, packedPk, packedSk, rAdditional)
}

// BlindVerify is the blind-signature verify: recompute h = SHAKE256(m ||
// proof1) from the proof and check the VOLE proof against epk || h.
// Malformed proofs and wrong-sized keys are rejected, not panicked on.
func (o MayoOWF) BlindVerify(epk, m, proof, rAdditional []byte) bool {
	if len(proof) != o.ProofSize() || len(epk) != o.expandedPkBytes() {
		return false
	}
	proof1 := proof[:o.proof1Size()]
	h := shake256Sum(o.hBytes(), m, proof1)
	packedPk := append(append([]byte(nil), epk...), h...)
	return o.Verify(packedPk, rAdditional, proof)
}
