package faest

import "github.com/maceip/tamayo/field"

// byteCommits is the prover-side commitment to an AES state: the actual witness
// bytes (keys) plus one VOLE tag field element per bit (tags). It produces
// degree-1 Commit polynomials via ByteCombine. Transpiled from faest-rs
// src/prover/{byte_commitments,aes}.rs.
type byteCommits struct {
	f    field.Big
	keys []byte
	tags [][]uint64
}

func (b byteCommits) getFieldCommit(i int) Commit {
	return CommitDeg1(b.f, b.f.ByteCombineBits(b.keys[i]), b.f.ByteCombine(b.tags[8*i:8*i+8]))
}

func (b byteCommits) getFieldCommitSq(i int) Commit {
	return CommitDeg1(b.f, b.f.ByteCombineBitsSq(b.keys[i]), b.f.ByteCombineSq(b.tags[8*i:8*i+8]))
}

func (b byteCommits) subBytes(startByte, n int) byteCommits {
	return byteCommits{f: b.f, keys: b.keys[startByte : startByte+n], tags: b.tags[startByte*8 : (startByte+n)*8]}
}

// committedStateToBytes converts a committed state to per-byte degree-1 commits.
func (b byteCommits) committedStateToBytes() []Commit {
	out := make([]Commit, len(b.keys))
	for i := range out {
		out[i] = b.getFieldCommit(i)
	}
	return out
}

// knownStateToBytes byte-combines the bits of a public state.
func knownStateToBytes(f field.Big, keys []byte) [][]uint64 {
	out := make([][]uint64, len(keys))
	for i, k := range keys {
		out[i] = f.ByteCombineBits(k)
	}
	return out
}

// addRoundKeyKnownCommitted XORs a public state (keys) with a committed key.
func addRoundKeyKnownCommitted(f field.Big, keys []byte, key byteCommits) byteCommits {
	k := make([]byte, len(keys))
	for i := range keys {
		k[i] = keys[i] ^ key.keys[i]
	}
	tags := make([][]uint64, len(key.tags))
	copy(tags, key.tags)
	return byteCommits{f: f, keys: k, tags: tags}
}

// addRoundKeyCommittedKnown XORs a committed state with a public key (tags kept).
func (b byteCommits) addRoundKeyCommittedKnown(rhs []byte) byteCommits {
	k := make([]byte, len(b.keys))
	for i := range b.keys {
		k[i] = b.keys[i] ^ rhs[i]
	}
	tags := make([][]uint64, len(b.tags))
	copy(tags, b.tags)
	return byteCommits{f: b.f, keys: k, tags: tags}
}

// addRoundKeyCommitted XORs keys and adds tags of two committed states.
func (b byteCommits) addRoundKeyCommitted(rhs byteCommits) byteCommits {
	k := make([]byte, len(b.keys))
	for i := range b.keys {
		k[i] = b.keys[i] ^ rhs.keys[i]
	}
	tags := make([][]uint64, len(b.tags))
	for i := range b.tags {
		tags[i] = b.f.Add(b.tags[i], rhs.tags[i])
	}
	return byteCommits{f: b.f, keys: k, tags: tags}
}

func (b byteCommits) addRoundKeyAssignCommitted(rhs byteCommits) {
	for i := range b.keys {
		b.keys[i] ^= rhs.keys[i]
	}
	for i := range b.tags {
		b.tags[i] = b.f.Add(b.tags[i], rhs.tags[i])
	}
}

// inverseShiftRows permutes a committed byte state.
func (b byteCommits) inverseShiftRows(nst int) byteCommits {
	k := make([]byte, len(b.keys))
	tags := make([][]uint64, len(b.tags))
	for r := 0; r < 4; r++ {
		for c := 0; c < nst; c++ {
			var i int
			if nst != 8 || r <= 1 {
				i = 4*((nst+c-r)%nst) + r
			} else {
				i = 4*((nst+c-r-1)%nst) + r
			}
			k[4*c+r] = b.keys[i]
			for j := 0; j < 8; j++ {
				tags[8*(4*c+r)+j] = b.tags[8*i+j]
			}
		}
	}
	return byteCommits{f: b.f, keys: k, tags: tags}
}

// bytewiseMixColumns applies MixColumns on a committed byte state (keys+tags).
func (b byteCommits) bytewiseMixColumns(nst int) byteCommits {
	f := b.f
	k := make([]byte, len(b.keys))
	tags := make([][]uint64, len(b.tags))
	for i := range tags {
		tags[i] = f.Zero()
	}
	for c := 0; c < nst; c++ {
		for r := 0; r < 4; r++ {
			aKey := b.keys[4*c+r]
			aTags := b.tags[32*c+8*r : 32*c+8*r+8]
			aKey7 := aKey & 0x80
			bKey := (aKey<<1 | aKey>>7) ^ (aKey7 >> 6) ^ (aKey7 >> 4) ^ (aKey7 >> 3)
			bTags := [][]uint64{
				aTags[7],
				f.Add(aTags[0], aTags[7]),
				aTags[1],
				f.Add(aTags[2], aTags[7]),
				f.Add(aTags[3], aTags[7]),
				aTags[4],
				aTags[5],
				aTags[6],
			}
			for j := 0; j < 2; j++ {
				off := (4 + r - j) % 4
				k[4*c+off] ^= bKey
				for t := 0; t < 8; t++ {
					tags[32*c+8*off+t] = f.Add(tags[32*c+8*off+t], bTags[t])
				}
			}
			for j := 1; j < 4; j++ {
				off := (r + j) % 4
				k[4*c+off] ^= aKey
				for t := 0; t < 8; t++ {
					tags[32*c+8*off+t] = f.Add(tags[32*c+8*off+t], aTags[t])
				}
			}
		}
	}
	return byteCommits{f: f, keys: k, tags: tags}
}

// inverseAffine applies the inverse S-box affine map on a committed byte state.
func (b byteCommits) inverseAffine() {
	for i := range b.keys {
		x := b.keys[i]
		b.keys[i] = (x>>7 | x<<1) ^ (x>>5 | x<<3) ^ (x>>2 | x<<6) ^ 0x5
	}
	f := b.f
	for base := 0; base < len(b.tags); base += 8 {
		var xi [8][]uint64
		for k := 0; k < 8; k++ {
			xi[k] = b.tags[base+k]
		}
		for bi := 0; bi < 8; bi++ {
			b.tags[base+bi] = f.Add(f.Add(xi[(bi+7)%8], xi[(bi+5)%8]), xi[(bi+2)%8])
		}
	}
}

// f256F2ConjugatesProve produces the 8 Frobenius conjugates of a committed byte
// as degree-1 commits.
func f256F2ConjugatesProve(f field.Big, key byte, tagsIn [][]uint64) []Commit {
	out := make([]Commit, 8)
	tags := make([][]uint64, 8)
	for i := 0; i < 8; i++ {
		tags[i] = append([]uint64(nil), tagsIn[i]...)
	}
	for i := 0; i < 8; i++ {
		out[i] = CommitDeg1(f, f.ByteCombineBits(key), f.ByteCombine(tags))
		key = byte(field.GF8(key).SquareBits())
		tags = f.SquareByte(tags)
	}
	return out
}

// invnormToConjugatesProve builds the 4 inverse-norm conjugate commits.
func invnormToConjugatesProve(f field.Big, xVal byte, xTag [][]uint64) []Commit {
	bsq := f.BetaSquares()
	bcube := f.BetaCubes()
	out := make([]Commit, 4)
	for j := 0; j < 4; j++ {
		key := f.FromBit(xVal)
		if (xVal>>1)&1 != 0 {
			key = f.Add(key, bsq[j])
		}
		if (xVal>>2)&1 != 0 {
			key = f.Add(key, bsq[j+1])
		}
		if (xVal>>3)&1 != 0 {
			key = f.Add(key, bcube[j])
		}
		tag := f.Add(f.Add(f.Add(xTag[0], f.Mul(bsq[j], xTag[1])), f.Mul(bsq[j+1], xTag[2])), f.Mul(bcube[j], xTag[3]))
		out[j] = CommitDeg1(f, key, tag)
	}
	return out
}

// sBoxAffineProve applies the S-box affine map to a bit-representation array of
// degree-2 commits, producing a byte-representation array.
func sBoxAffineProve(f field.Big, state []Commit, sq bool, nStBytes int) []Commit {
	sig := f.Sigma(sq)
	t := 0
	if sq {
		t = 1
	}
	out := make([]Commit, nStBytes)
	for i := 0; i < nStBytes; i++ {
		yi := state[i*8+t%8].MulScalar(sig[0])
		for si := 1; si < 8; si++ {
			yi = yi.Add(state[i*8+(si+t)%8].MulScalar(sig[si]))
		}
		yi = yi.AddKey(sig[8])
		out[i] = yi
	}
	return out
}

// shiftRowsCommits permutes an array of commits in place.
func shiftRowsCommits(state []Commit, nst int) {
	orig := make([]Commit, len(state))
	copy(orig, state)
	for r := 0; r < 4; r++ {
		off := 0
		if nst == 8 && r > 1 {
			off = 1
		}
		for c := 0; c < nst; c++ {
			state[4*c+r] = orig[4*((c+r+off)%nst)+r]
		}
	}
}

// mixColumnsCommits applies MixColumns to a byte-representation degree-2 array.
func mixColumnsCommits(f field.Big, state []Commit, sq bool) {
	v2 := f.ByteCombine2(sq)
	v3 := f.ByteCombine3(sq)
	for base := 0; base < len(state); base += 4 {
		t0, t1, t2, t3 := state[base], state[base+1], state[base+2], state[base+3]
		state[base+0] = t0.MulScalar(v2).Add(t1.MulScalar(v3)).Add(t2).Add(t3)
		state[base+1] = t1.MulScalar(v2).Add(t2.MulScalar(v3)).Add(t0).Add(t3)
		state[base+2] = t2.MulScalar(v2).Add(t3.MulScalar(v3)).Add(t0).Add(t1)
		state[base+3] = t0.MulScalar(v3).Add(t3.MulScalar(v2)).Add(t1).Add(t2)
	}
}

// addRoundKeyBytesCommits adds a committed round key (per-byte commits) to a
// byte-representation degree-2 state.
func addRoundKeyBytesCommits(state, key []Commit) {
	for i := range state {
		state[i] = state[i].Add(key[i])
	}
}
