package faest

// tweakOffset is the initial VOLE tweak value from the FAEST specification.
const tweakOffset uint32 = 1 << 31

// VoleCommitment is the output of VoleCommit: the BAVC commitment plus the VOLE
// correlation (u, v) and the per-instance corrections c.
type VoleCommitment struct {
	Com  []byte   // 2*lambda
	Keys [][]byte // BAVC keys (for Open)
	Coms [][]byte // BAVC leaf commitments (for Open)
	U    []byte   // lHat
	V    [][]byte // 8*lambda rows of lHat
	C    [][]byte // Tau-1 corrections of lHat
}

// VoleReconstruction is the output of VoleReconstruct: the recomputed
// commitment and the verifier's VOLE tags q.
type VoleReconstruction struct {
	Com []byte   // 2*lambda
	Q   [][]byte // 8*lambda rows of lHat
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// convertToVole turns the ni leaf seeds of one small-VOLE instance into the VOLE
// value u and, in place, the ki VOLE tags v. Each seed is PRG-expanded to lHat
// bytes; a stack-based tree reduction accumulates the per-level partial sums.
// Transpiled from faest-rs src/vole.rs (convert_to_vole).
func (b *Bavc) convertToVole(v, sd [][]byte, iv []byte, round, lHat int) []byte {
	twk := uint32(round) + tweakOffset
	ni := b.Tau.BavcMaxNodeIndex(round)

	rj := make([][]byte, b.Tau.VoleArrayLength(round))
	for i := range rj {
		rj[i] = make([]byte, lHat)
	}
	rightLeaf := make([]byte, lHat)

	next := 0
	for i := 0; i < ni/2; i++ {
		// Read the left leaf into rj[next] and the right leaf into rightLeaf.
		// Both targets are zero here (fresh, popped, or just cleared), so the
		// XOR-based PRG read equals an overwrite.
		clear(rj[next])
		NewPRG(sd[2*i], iv, twk).Read(rj[next])
		clear(rightLeaf)
		NewPRG(sd[2*i+1], iv, twk).Read(rightLeaf)

		// Level 0 accumulates every right leaf; the father is left xor right.
		xorInto(v[0], rightLeaf)
		xorInto(rj[next], rightLeaf)
		next++

		// Fold up every level whose last two nodes are now on the same level.
		for d := 0; d < len(v)-1; d++ {
			if (i+1)%(1<<(d+1)) != 0 {
				break
			}
			left := rj[next-2]
			right := rj[next-1]
			xorInto(v[d+1], right)
			xorInto(left, right)
			clear(right)
			next--
		}
	}

	return rj[0]
}

// VoleCommit commits to the L leaf seeds and derives the prover VOLE correlation
// (u, v) plus the Tau-1 corrections c. lHat is the correlation length in bytes
// (OWF LHatBytes). Transpiled from faest-rs src/vole.rs (volecommit).
func (b *Bavc) VoleCommit(r, iv []byte, lHat int) *VoleCommitment {
	commit := b.Commit(r, iv)

	rows := 8 * b.lam()
	v := make([][]byte, rows)
	for i := range v {
		v[i] = make([]byte, lHat)
	}

	k0 := b.Tau.BavcMaxNodeDepth(0)
	n0 := b.Tau.BavcMaxNodeIndex(0)
	u := b.convertToVole(v[0:k0], commit.Seeds[0:n0], iv, 0, lHat)

	c := make([][]byte, b.Tau.Tau-1)
	for i := range c {
		c[i] = make([]byte, lHat)
	}

	seedOff, vOff := n0, k0
	for i := 1; i < b.Tau.Tau; i++ {
		ni := b.Tau.BavcMaxNodeIndex(i)
		ki := b.Tau.BavcMaxNodeDepth(i)

		ui := b.convertToVole(v[vOff:vOff+ki], commit.Seeds[seedOff:seedOff+ni], iv, i, lHat)
		for x := 0; x < lHat; x++ {
			c[i-1][x] = ui[x] ^ u[x]
		}

		seedOff += ni
		vOff += ki
	}

	return &VoleCommitment{Com: commit.Com, Keys: commit.Keys, Coms: commit.Coms, U: u, V: v, C: c}
}

// VoleReconstruct rebuilds the verifier VOLE tags q from an opening and the
// corrections c, using the challenge chall to locate the Tau hidden leaves.
// Transpiled from faest-rs src/vole.rs (volereconstruct).
func (b *Bavc) VoleReconstruct(chall []byte, op *BavcOpening, c [][]byte, iv []byte, lHat int) (*VoleReconstruction, bool) {
	iDelta := b.Tau.DecodeChallenge(chall)

	rec, ok := b.Reconstruct(op, iDelta, iv)
	if !ok {
		return nil, false
	}

	rows := 8 * b.lam()
	q := make([][]byte, rows)
	for i := range q {
		q[i] = make([]byte, lHat)
	}

	zeroSeed := make([]byte, b.lam())
	sdiOff, qOff := 0, 0
	for i := 0; i < b.Tau.Tau; i++ {
		deltaI := int(iDelta[i])
		ni := b.Tau.BavcMaxNodeIndex(i)
		ki := b.Tau.BavcMaxNodeDepth(i)

		// Re-index the reconstructed seeds by j^delta_i so the hidden leaf lands
		// at position 0 (a zero seed); the rest map to their reconstruct order.
		seedsI := make([][]byte, ni)
		for jXor := 0; jXor < ni; jXor++ {
			if jXor == 0 {
				seedsI[jXor] = zeroSeed
				continue
			}
			j := jXor ^ deltaI
			idx := sdiOff + j
			if j >= deltaI {
				idx = sdiOff + j - 1
			}
			seedsI[jXor] = rec.Seeds[idx]
		}

		b.convertToVole(q[qOff:qOff+ki], seedsI, iv, i, lHat)

		// Apply the correction c_{i-1} to the columns selected by delta_i.
		if i != 0 {
			for j := 0; j < ki; j++ {
				if deltaI&(1<<j) != 0 {
					xorInto(q[qOff+j], c[i-1])
				}
			}
		}

		sdiOff += ni - 1
		qOff += ki
	}

	return &VoleReconstruction{Com: rec.Com, Q: q}, true
}
