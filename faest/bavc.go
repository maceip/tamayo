package faest

import "github.com/maceip/tamayo/field"

// Bavc is a FAEST batch all-but-one vector commitment over one GGM tree.
// Transpiled from faest-rs src/bavc.rs (the standard, non-EM Bavc). It composes
// construct_keys (the GGM tree, PRG-expanded), LeafCommit (per leaf), and the
// H0/H1 random oracles.
//
// ext is the degree-3 extension field of the security level (Big384/576/768);
// lambda = ext.Bytes/3 and the RO is SHAKE128 at lambda=128, SHAKE256 otherwise.
type Bavc struct {
	Tau Tau
	ext field.Big
}

// NewBavc pairs a Tau parameter set with its degree-3 extension field.
func NewBavc(t Tau, ext field.Big) *Bavc { return &Bavc{Tau: t, ext: ext} }

func (b *Bavc) lam() int     { return b.ext.Bytes / 3 }
func (b *Bavc) use256() bool { return b.lam() != 16 }

// BavcCommitment is the output of Commit: the top commitment h (2*lambda), the
// full GGM key set (2L-1 nodes), the L leaf commitments and the L leaf seeds,
// both in (instance, leaf) order.
type BavcCommitment struct {
	Com   []byte
	Keys  [][]byte
	Coms  [][]byte
	Seeds [][]byte
}

// BavcOpening is the output of Open: the Tau opened leaf commitments and the
// co-path (all-but-one) node keys.
type BavcOpening struct {
	Coms  [][]byte
	Nodes [][]byte
}

// BavcReconstruction is the output of Reconstruct: the recomputed commitment and
// the L-Tau revealed seeds.
type BavcReconstruction struct {
	Com   []byte
	Seeds [][]byte
}

// constructKeys builds the GGM tree: keys[0]=r, each internal node expands to its
// two children under PRG(node, iv, index). Transpiled from bavc.rs construct_keys.
func (b *Bavc) constructKeys(r, iv []byte) [][]byte {
	L := b.Tau.L
	keys := make([][]byte, 2*L-1)
	for i := range keys {
		keys[i] = make([]byte, b.lam())
	}
	copy(keys[0], r)
	for alpha := 0; alpha < L-1; alpha++ {
		prg := NewPRG(keys[alpha], iv, uint32(alpha))
		prg.Read(keys[2*alpha+1])
		prg.Read(keys[2*alpha+2])
	}
	return keys
}

// Commit produces the batch commitment to the L leaf seeds derived from r.
// Transpiled from bavc.rs Bavc::commit.
func (b *Bavc) Commit(r, iv []byte) *BavcCommitment {
	L, lam, u256 := b.Tau.L, b.lam(), b.use256()

	h0 := H0(u256)
	h0.Update(iv)
	h0r := h0.Finish()

	keys := b.constructKeys(r, iv)

	comHasher := H1(u256)
	seeds := make([][]byte, 0, L)
	coms := make([][]byte, 0, L)

	for i := 0; i < b.Tau.Tau; i++ {
		hi := H1(u256)
		uhashI := make([]byte, 3*lam)
		h0r.Read(uhashI)

		nI := b.Tau.BavcMaxNodeIndex(i)
		tweak := uint32(i + L - 1)
		for j := 0; j < nI; j++ {
			alpha := b.Tau.PosInTree(i, j)
			sd, com := LeafCommit(b.ext, keys[alpha], iv, tweak, uhashI)
			hi.Update(com)
			seeds = append(seeds, sd)
			coms = append(coms, com)
		}

		hd := make([]byte, 2*lam)
		hi.Finish().Read(hd)
		comHasher.Update(hd)
	}

	com := make([]byte, 2*lam)
	comHasher.Finish().Read(com)
	return &BavcCommitment{Com: com, Keys: keys, Coms: coms, Seeds: seeds}
}

// markNodes marks the paths from the Tau hidden leaves (iDelta) up to the root
// and returns the opening size, or ok=false if it exceeds Topen. Transpiled from
// bavc.rs mark_nodes.
func (b *Bavc) markNodes(s []bool, iDelta []uint16) (int, bool) {
	nH := 0
	for i := 0; i < b.Tau.Tau; i++ {
		alpha := b.Tau.PosInTree(i, int(iDelta[i]))
		s[alpha] = true
		nH++
		for alpha > 0 {
			parent := (alpha - 1) / 2
			old := s[parent]
			s[parent] = true
			if old {
				break
			}
			alpha = parent
			nH++
		}
	}
	if nH-2*b.Tau.Tau+1 > b.Tau.Topen {
		return 0, false
	}
	return nH, true
}

// constructNodes collects, for every internal node with exactly one marked
// child, the key of the unmarked sibling (the co-path). Transpiled from bavc.rs
// construct_nodes.
func (b *Bavc) constructNodes(keys [][]byte, s []bool) [][]byte {
	nodes := make([][]byte, 0)
	for i := b.Tau.L - 2; i >= 0; i-- {
		left, right := s[2*i+1], s[2*i+2]
		if left != right {
			alpha := 2*i + 1
			if left {
				alpha++
			}
			nodes = append(nodes, keys[alpha])
		}
	}
	return nodes
}

// Open produces the all-but-one opening for the hidden indices iDelta.
// Transpiled from bavc.rs Bavc::open.
func (b *Bavc) Open(keys, coms [][]byte, iDelta []uint16) (*BavcOpening, bool) {
	s := make([]bool, 2*b.Tau.L-1)
	if _, ok := b.markNodes(s, iDelta); !ok {
		return nil, false
	}
	nodes := b.constructNodes(keys, s)

	openComs := make([][]byte, b.Tau.Tau)
	for i := 0; i < b.Tau.Tau; i++ {
		openComs[i] = coms[b.Tau.BavcIndexOffset(i)+int(iDelta[i])]
	}
	return &BavcOpening{Coms: openComs, Nodes: nodes}, true
}

// reconstructKeys rebuilds every GGM key except the Tau hidden leaves, from the
// co-path nodes. Transpiled from bavc.rs reconstruct_keys.
func (b *Bavc) reconstructKeys(s []bool, nodes [][]byte, iDelta []uint16, iv []byte) ([][]byte, bool) {
	L := b.Tau.L
	for i := 0; i < b.Tau.Tau; i++ {
		s[b.Tau.PosInTree(i, int(iDelta[i]))] = true
	}

	keys := make([][]byte, 2*L-1)
	for i := range keys {
		keys[i] = make([]byte, b.lam())
	}

	di := 0
	for i := L - 2; i >= 0; i-- {
		left, right := s[2*i+1], s[2*i+2]
		if left || right {
			s[i] = true
		}
		if left != right {
			if di >= len(nodes) {
				return nil, false
			}
			alpha := 2*i + 1
			if left {
				alpha++
			}
			copy(keys[alpha], nodes[di])
			di++
		}
	}

	// Any leftover opening node must be all-zero padding.
	for ; di < len(nodes); di++ {
		for _, x := range nodes[di] {
			if x != 0 {
				return nil, false
			}
		}
	}

	// Expand every unmarked internal node down to its children.
	for i := 0; i < L-1; i++ {
		if !s[i] {
			prg := NewPRG(keys[i], iv, uint32(i))
			prg.Read(keys[2*i+1])
			prg.Read(keys[2*i+2])
		}
	}

	return keys, true
}

// Reconstruct recomputes the commitment from an opening, recovering all leaf
// seeds except the Tau hidden ones. Transpiled from bavc.rs Bavc::reconstruct.
func (b *Bavc) Reconstruct(op *BavcOpening, iDelta []uint16, iv []byte) (*BavcReconstruction, bool) {
	L, lam, u256 := b.Tau.L, b.lam(), b.use256()

	s := make([]bool, 2*L-1)
	keys, ok := b.reconstructKeys(s, op.Nodes, iDelta, iv)
	if !ok {
		return nil, false
	}

	h0 := H0(u256)
	h0.Update(iv)
	h0r := h0.Finish()

	comHasher := H1(u256)
	seeds := make([][]byte, 0, L-b.Tau.Tau)
	comIt := 0

	for i := 0; i < b.Tau.Tau; i++ {
		uhashI := make([]byte, 3*lam)
		h0r.Read(uhashI)

		hi := H1(u256)
		nI := b.Tau.BavcMaxNodeIndex(i)
		tweak := uint32(i + L - 1)
		for j := 0; j < nI; j++ {
			alpha := b.Tau.PosInTree(i, j)
			if !s[alpha] {
				sd, h := LeafCommit(b.ext, keys[alpha], iv, tweak, uhashI)
				seeds = append(seeds, sd)
				hi.Update(h)
			} else {
				if comIt >= len(op.Coms) {
					return nil, false
				}
				hi.Update(op.Coms[comIt])
				comIt++
			}
		}

		hd := make([]byte, 2*lam)
		hi.Finish().Read(hd)
		comHasher.Update(hd)
	}

	com := make([]byte, 2*lam)
	comHasher.Finish().Read(com)
	return &BavcReconstruction{Com: com, Seeds: seeds}, true
}
