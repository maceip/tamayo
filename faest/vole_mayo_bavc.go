package faest

import "crypto/sha3"

// GGM-forest batched all-but-one vector commitment for the optimized_bs MAYO
// path. Transpiled from pq_blind_signatures vole/faest-cpp-tmp/vector_com.inc
// (ggm_forest_bavc<S, TAU, DELTA_BITS=lambda, aes_ctr, shake, VOLE_WIDTH_SHIFT>)
// and vole_commit.inc (hash_hashed_leaves).
//
// This is a DISTINCT construction from the faest-rs Bavc in bavc.go: TAU
// separate GGM trees (not one tree), per-(level,tree) AES-CTR tweaks, shake
// leaf hashing, and a Gray-code leaf permutation for the small-VOLE columns.
// The chunked/SIMD expansion of the reference is flattened here to a plain
// node-by-node binary expansion; byte-exact vectors certify the equivalence.

// MayoForest is one v1 MAYO ggm_forest parameter set. minK/maxK and the tree
// counts are pure functions of (Tau, lambda) exactly as in
// VECTOR_COMMITMENT_CONSTANTS<TAU, DELTA_BITS=lambda>. WitnessBits =
// VOLEMAYO_WITNESS_SIZE_BITS (= 4*M + 4*K*N) fixes the VOLE row count.
type MayoForest struct {
	Tau         int
	LambdaBytes int
	WitnessBits int
	minK        int
	maxK        int
	numMaxK     int
	numMinK     int
}

// NewMayoForest builds the parameter set for the given tau, lambda (bytes) and
// witness-bit count.
func NewMayoForest(tau, lambdaBytes, witnessBits int) MayoForest {
	deltaBits := lambdaBytes * 8
	minK := deltaBits / tau
	maxK := (deltaBits + tau - 1) / tau
	numMaxK := deltaBits % tau
	numMinK := tau - numMaxK
	return MayoForest{Tau: tau, LambdaBytes: lambdaBytes, WitnessBits: witnessBits,
		minK: minK, maxK: maxK, numMaxK: numMaxK, numMinK: numMinK}
}

// The three v1 MAYO small parameter sets (mayo_{128,192,256}_s). WitnessBits
// from VOLEMAYO_WITNESS_SIZE_BITS: L1 4*78+4*10*86, L3 4*108+4*11*118,
// L5 4*142+4*12*154.
var (
	MayoForestL1 = NewMayoForest(9, 16, 3752)
	MayoForestL3 = NewMayoForest(14, 24, 5624)
	MayoForestL5 = NewMayoForest(19, 32, 7960)
)

// voleRows = QUICKSILVER_ROWS + VOLE_CHECK::HASH_BYTES*8, with QUICKSILVER_ROWS
// = WITNESS_BITS + (QS_DEGREE-1=1)*lambda and HASH_BYTES = lambda_bytes+2.
func (m MayoForest) voleRows() int {
	return m.WitnessBits + m.LambdaBytes*8 + (m.LambdaBytes+2)*8
}

// colLen = VOLE_COL_BLOCKS = ceil(voleRows / 128) (VOLE_BLOCK = 1).
func (m MayoForest) colLen() int { return (m.voleRows() + 127) / 128 }

func (m MayoForest) use256() bool { return m.LambdaBytes != 16 }
func (m MayoForest) hashLen() int { return 2 * m.LambdaBytes }

// treeDepth returns the depth (MAX_K/MIN_K) of tree i.
func (m MayoForest) treeDepth(i int) int {
	if i < m.numMaxK {
		return m.maxK
	}
	return m.minK
}

// commitLeaves is the total number of leaves over all trees.
func (m MayoForest) commitLeaves() int {
	return (m.numMinK << m.minK) + (m.numMaxK << m.maxK)
}

func (m MayoForest) newXOF() *sha3.SHAKE {
	if m.use256() {
		return sha3.NewSHAKE256()
	}
	return sha3.NewSHAKE128()
}

// expandTree expands tree i from its root into all depth+1 levels of GGM nodes
// in natural (left-to-right) order. levels[0] = {root}, levels[d] holds the 2^d
// nodes at depth d, and levels[depth] are the leaf seeds. Each parent yields two
// children via AES-CTR PRG(parent, iv, tweak = depth_of_children*Tau + treeIdx),
// left = first lambda bytes, right = next lambda.
func (m MayoForest) expandTree(root, iv []byte, treeIdx, depth int) [][][]byte {
	lam := m.LambdaBytes
	levels := make([][][]byte, depth+1)
	levels[0] = [][]byte{append([]byte(nil), root...)}
	for l := 1; l <= depth; l++ {
		tweak := uint32(l*m.Tau + treeIdx)
		next := make([][]byte, 0, len(levels[l-1])*2)
		for _, parent := range levels[l-1] {
			buf := make([]byte, 2*lam)
			NewPRG(parent, iv, tweak).Read(buf)
			next = append(next, append([]byte(nil), buf[:lam]...), append([]byte(nil), buf[lam:]...))
		}
		levels[l] = next
	}
	return levels
}

// leafShake implements shake_leaf_hash::hash for one GGM leaf node: SHAKE(node
// || iv || tweak_le32 || 0x00) squeezed to 3*lambda bytes. The first lambda
// bytes become the small-VOLE leaf key; the next 2*lambda are the leaf hash.
// tweak = (depth+1)*Tau + treeIdx.
func (m MayoForest) leafShake(node, iv []byte, treeIdx, depth int) []byte {
	lam := m.LambdaBytes
	tweak := uint32((depth+1)*m.Tau + treeIdx)
	x := m.newXOF()
	x.Write(node)
	x.Write(iv)
	x.Write([]byte{byte(tweak), byte(tweak >> 8), byte(tweak >> 16), byte(tweak >> 24)})
	x.Write([]byte{0})
	out := make([]byte, 3*lam)
	x.Read(out)
	return out
}

// MayoForestCommit expands all TAU trees from the seed and returns the per-tree
// natural-order small-VOLE leaf keys (first lambda bytes of each leaf's shake
// hash), the per-tree concatenated leaf hashes (the next 2*lambda), and the
// hash-of-hashes check (2*lambda). Transpiled from ggm_forest_bavc::commit +
// hash_hashed_leaves.
func (m MayoForest) MayoForestCommit(seed, iv []byte) (voleKeys [][][]byte, hashedLeaves [][]byte, check []byte, forest [][][][]byte) {
	lam := m.LambdaBytes

	// Roots: PRG(seed, iv, tweak=0) stretched to Tau blocks.
	rootBuf := make([]byte, m.Tau*lam)
	NewPRG(seed, iv, 0).Read(rootBuf)

	voleKeys = make([][][]byte, m.Tau)
	hashedLeaves = make([][]byte, m.Tau)
	forest = make([][][][]byte, m.Tau)
	for i := 0; i < m.Tau; i++ {
		depth := m.treeDepth(i)
		root := rootBuf[i*lam : (i+1)*lam]
		levels := m.expandTree(root, iv, i, depth)
		forest[i] = levels
		nodes := levels[depth]

		keys := make([][]byte, len(nodes))
		hl := make([]byte, 0, len(nodes)*m.hashLen())
		for idx, node := range nodes {
			full := m.leafShake(node, iv, i, depth)
			keys[idx] = append([]byte(nil), full[:lam]...)
			hl = append(hl, full[lam:3*lam]...)
		}
		voleKeys[i] = keys
		hashedLeaves[i] = hl
	}

	// hash_hashed_leaves: per-tree leaves_hash = SHAKE(tree_hashed || 0x01,
	// 2*lambda), absorbed in tree order into the outer hasher, then 0x01.
	outer := m.newXOF()
	for i := 0; i < m.Tau; i++ {
		x := m.newXOF()
		x.Write(hashedLeaves[i])
		x.Write([]byte{1})
		lh := make([]byte, 2*lam)
		x.Read(lh)
		outer.Write(lh)
	}
	outer.Write([]byte{1})
	check = make([]byte, 2*lam)
	outer.Read(check)
	return voleKeys, hashedLeaves, check, forest
}

// hashOfHashes runs hash_hashed_leaves over per-tree concatenated leaf hashes,
// producing the 2*lambda check. Shared by commit and reconstruct.
func (m MayoForest) hashOfHashes(hashedLeaves [][]byte) []byte {
	lam := m.LambdaBytes
	outer := m.newXOF()
	for i := 0; i < m.Tau; i++ {
		x := m.newXOF()
		x.Write(hashedLeaves[i])
		x.Write([]byte{1})
		lh := make([]byte, 2*lam)
		x.Read(lh)
		outer.Write(lh)
	}
	outer.Write([]byte{1})
	check := make([]byte, 2*lam)
	outer.Read(check)
	return check
}

// MayoForestOpen produces the all-but-Delta opening: for each tree, walk from
// the root along the Delta-selected path (LSB-first per level, delta byte
// 0/0xff) emitting the sibling node key at each level, then the hidden leaf's
// 2*lambda hash. Transpiled from ggm_forest_bavc::open. deltaBytes is the
// per-tree little-endian expanded Delta (delta_bits bytes total).
func (m MayoForest) MayoForestOpen(forest [][][][]byte, hashedLeaves [][]byte, deltaBytes []byte) []byte {
	lam := m.LambdaBytes
	var opening []byte
	dOff := 0
	for i := 0; i < m.Tau; i++ {
		depth := m.treeDepth(i)
		levels := forest[i]
		node := 0 // index within the current level
		leafIdx := 0
		for d := 1; d <= depth; d++ {
			hole := deltaBytes[dOff+depth-d] & 1
			leafIdx = 2*leafIdx + int(hole)
			// sibling of the node on the hidden path at level d
			sib := 2*node + (1 - int(hole))
			opening = append(opening, levels[d][sib]...)
			node = 2*node + int(hole)
		}
		opening = append(opening, hashedLeaves[i][leafIdx*2*lam:(leafIdx+1)*2*lam]...)
		dOff += depth
	}
	return opening
}
