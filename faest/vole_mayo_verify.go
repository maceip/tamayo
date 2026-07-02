package faest

// One-More-MAYO VOLE verifier. Transpiled from pq_blind_signatures
// vole/optimized_bs/faest.inc (vole_verify) plus the reconstruct halves of
// vector_com.inc (ggm_forest_bavc::verify), vole_commit.inc (vole_reconstruct),
// small_vole.inc (vole_receiver, vole_receiver_apply_correction) and
// vole_check.hpp (vole_check_receiver). v1 MAYO: ggm_forest, no grinding,
// delta_bits == lambda.

// leafIdxFromDelta computes tree i's hidden leaf index from its expanded delta
// bytes: bit j selects level j (little-endian), matching ggm_forest open/verify.
func leafIdxFromDelta(deltaCols []byte, depth int) int {
	idx := 0
	for j := 0; j < depth; j++ {
		if deltaCols[j]&1 != 0 {
			idx |= 1 << j
		}
	}
	return idx
}

// expandSubtree expands a node at depth startDepth into its 2^levelsDown leaf
// descendants (natural order), using the same per-level AES-CTR tweaks as
// commit (children at depth d use tweak d*Tau + treeIdx).
func (m MayoForest) expandSubtree(key, iv []byte, treeIdx, startDepth, levelsDown int) [][]byte {
	lam := m.LambdaBytes
	level := [][]byte{append([]byte(nil), key...)}
	for step := 1; step <= levelsDown; step++ {
		childDepth := startDepth + step
		tweak := uint32(childDepth*m.Tau + treeIdx)
		next := make([][]byte, 0, len(level)*2)
		for _, parent := range level {
			buf := make([]byte, 2*lam)
			NewPRG(parent, iv, tweak).Read(buf)
			next = append(next, append([]byte(nil), buf[:lam]...), append([]byte(nil), buf[lam:]...))
		}
		level = next
	}
	return level
}

// MayoForestVerify reconstructs, per tree, all leaf VOLE keys except the hidden
// one (from the opening's co-path siblings) plus every leaf hash (the hidden
// leaf's hash comes from the opening tail), and recomputes the hash-of-hashes
// check. Transpiled from ggm_forest_bavc::verify. deltaBytes is the expanded
// per-tree Delta (lambda bytes). Returns per-tree natural-order vole keys (the
// hidden slot is a zero dummy), the hash-of-hashes check, and the per-tree
// hidden leaf indices.
func (m MayoForest) MayoForestVerify(iv, opening, deltaBytes []byte) (voleKeys [][][]byte, check []byte, leafIdx []int) {
	lam := m.LambdaBytes
	voleKeys = make([][][]byte, m.Tau)
	hashedLeaves := make([][]byte, m.Tau)
	leafIdx = make([]int, m.Tau)
	zero := make([]byte, lam)

	oOff, dOff := 0, 0
	for i := 0; i < m.Tau; i++ {
		depth := m.treeDepth(i)
		deltaCols := deltaBytes[dOff : dOff+depth]
		li := leafIdxFromDelta(deltaCols, depth)
		leafIdx[i] = li

		n := 1 << depth
		leaves := make([][]byte, n)
		for d := 1; d <= depth; d++ {
			sibIdx := (li >> (depth - d)) ^ 1
			sibKey := opening[oOff : oOff+lam]
			oOff += lam
			block := m.expandSubtree(sibKey, iv, i, d, depth-d)
			base := sibIdx << (depth - d)
			for x := 0; x < len(block); x++ {
				leaves[base+x] = block[x]
			}
		}
		hiddenHash := opening[oOff : oOff+2*lam]
		oOff += 2 * lam

		keys := make([][]byte, n)
		hl := make([]byte, n*2*lam)
		for idx := 0; idx < n; idx++ {
			if idx == li {
				keys[idx] = zero
				copy(hl[idx*2*lam:(idx+1)*2*lam], hiddenHash)
				continue
			}
			full := m.leafShake(leaves[idx], iv, i, depth)
			keys[idx] = append([]byte(nil), full[:lam]...)
			copy(hl[idx*2*lam:(idx+1)*2*lam], full[lam:3*lam])
		}
		voleKeys[i] = keys
		hashedLeaves[i] = hl
		dOff += depth
	}

	check = m.hashOfHashes(hashedLeaves)
	return voleKeys, check, leafIdx
}

// VoleReconstruct rebuilds the verifier VOLE tags q (lambda columns, column-
// major) from the opening and the BAVC corrections. Transpiled from
// vole_reconstruct. Returns q and the recomputed vole_commit check.
func (m MayoForest) VoleReconstruct(iv, opening, commitment, deltaBytes []byte) (q, check []byte) {
	voleKeys, chk, leafIdx := m.MayoForestVerify(iv, opening, deltaBytes)
	colBytes := m.colLenBytes()
	lambda := m.LambdaBytes * 8
	commitRowBytes := m.voleRows() / 8

	q = make([]byte, lambda*colBytes)
	colBase, dOff, cOff := 0, 0, 0
	for i := 0; i < m.Tau; i++ {
		k := m.treeDepth(i)
		n := 1 << k
		li := leafIdx[i]
		deltaCols := deltaBytes[dOff : dOff+k]

		keys := make([][]byte, n)
		for p := 0; p < n; p++ {
			keys[p] = voleKeys[i][volePermuteKeyIndex(p)^li]
		}
		tweak := uint32(0x80000000) + uint32(i)

		var correction []byte
		if i != 0 {
			correction = make([]byte, colBytes)
			copy(correction, commitment[cOff:cOff+commitRowBytes])
			cOff += commitRowBytes
		}
		qi := m.voleReceiver(k, keys, iv, tweak, correction, deltaCols)
		copy(q[colBase*colBytes:], qi)
		colBase += k
		dOff += k
	}
	return q, chk
}

// applyWitnessCorrection folds the witness correction d into q's witness rows,
// masked per column by the Delta bit. Transpiled from vole_receiver_apply_
// correction (row_blocks = WITNESS_BLOCKS, cols = delta_bits = lambda).
func (m MayoForest) applyWitnessCorrection(q, d, deltaBytes []byte) {
	colBytes := m.colLenBytes()
	lambda := m.LambdaBytes * 8
	witnessBlocks := (m.WitnessBits + 127) / 128
	rowBytes := witnessBlocks * voleBlockBytes
	dPad := make([]byte, rowBytes)
	copy(dPad, d)
	for col := 0; col < lambda; col++ {
		if deltaBytes[col] == 0 {
			continue
		}
		base := col * colBytes
		for x := 0; x < rowBytes; x++ {
			q[base+x] ^= dPad[x]
		}
	}
}

// voleCheckReceiver is vole_check_both(verifier=true): for each of the lambda q
// columns, hash the column, XOR u_tilde where the Delta bit is set, and return
// the ordered absorbed blocks. Transpiled from vole_check.hpp.
func (m MayoForest) voleCheckReceiver(q, challenge, uTilde, deltaBytes []byte) [][]byte {
	f := m.field()
	ch := m.parseVoleCheckChallenge(f, challenge)
	colBytes := m.colLenBytes()
	lambda := m.LambdaBytes * 8

	out := make([][]byte, lambda)
	for c := 0; c < lambda; c++ {
		h := m.hashColumn(f, ch, q[c*colBytes:(c+1)*colBytes])
		if deltaBytes[c] != 0 {
			for i := range h {
				h[i] ^= uTilde[i]
			}
		}
		out[c] = h
	}
	return out
}

// Verify checks a One-More-MAYO VOLE proof against (pk, r_additional).
// Transpiled from vole_verify. Returns true iff the proof's Delta equals the
// recomputed H_2^3(chall2 || qs_check || qs_proof).
func (o MayoOWF) Verify(pk, rAdditional, proof []byte) bool {
	f := o.F.field()
	lam := o.lam()
	wB := o.witnessBytes()

	// Parse the proof segments (v1 layout: no grinding counter).
	off := 0
	take := func(n int) []byte { s := proof[off : off+n]; off += n; return s }
	commitment := take(o.voleCommitSize())
	uTilde := take(o.voleCheckProofBytes())
	d := take(wB)
	qsProof := take(o.qsProofBytes())
	opening := take(o.openSize())
	delta := take(lam)
	ivPre := take(16)
	if off != len(proof) {
		return false
	}

	iv := o.shakeS(16, 0x04, ivPre)
	deltaBytes := expandBitsToBytes(delta, lam*8)

	q, voleCommitCheck := o.F.VoleReconstruct(iv, opening, commitment, deltaBytes)

	rAddHash := o.shakeS(32, -1, rAdditional)
	chal1 := o.shakeS(o.voleCheckChallengeBytes(), 0x09, rAddHash, voleCommitCheck, commitment, iv)

	qColHashes := o.F.voleCheckReceiver(q, chal1, uTilde, deltaBytes)
	chal2Parts := [][]byte{rAdditional, chal1, uTilde}
	chal2Parts = append(chal2Parts, qColHashes...)
	chal2Parts = append(chal2Parts, d)
	chal2 := o.shakeS(o.qsChallengeBytes(), 0x0a, chal2Parts...)

	o.F.applyWitnessCorrection(q, d, deltaBytes)
	macsBytes := o.F.TransposeToMacs(q, o.F.WitnessBits+lam*8)
	macs := make([][]uint64, len(macsBytes))
	for i := range macsBytes {
		macs[i] = f.FromBytes(macsBytes[i])
	}

	expandedPk := pk[:o.expandedPkBytes()]
	h := pk[o.expandedPkBytes() : o.expandedPkBytes()+o.hBytes()]

	deltaEl := f.FromBytes(delta)
	qs := NewQS2Verifier(f, macs, deltaEl, chal2)
	o.P.MayoConstraintVerify(qs, expandedPk, h, chal2)
	qsCheck := qs.Verify(o.F.WitnessBits, qsProof)

	deltaCheck := o.shakeS(lam, 0x0b, chal2, qsCheck, qsProof)
	return bytesEqualCT(delta, deltaCheck)
}

func bytesEqualCT(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
