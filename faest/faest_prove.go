package faest

import "github.com/maceip/tamayo/field"

// Prover-side FAEST OWF constraint circuit. Transpiled from faest-rs
// src/prover/{key_expansion,encryption,owf_constraints}.rs and the aes_prove
// half of src/zk_constraints.rs.

func squareCommits(a []Commit) []Commit {
	out := make([]Commit, len(a))
	for i := range a {
		out[i] = a[i].Square()
	}
	return out
}

func (o OWFParams) keyExpFwdProve(w byteCommits) byteCommits {
	f := w.f
	y := byteCommits{f: f, keys: make([]byte, 16*(o.R+1)), tags: make([][]uint64, o.R1Times128())}
	for i := range y.tags {
		y.tags[i] = f.Zero()
	}
	copy(y.keys[:o.LambdaBytes], w.keys[:o.LambdaBytes])
	copy(y.tags[:o.Lambda()], w.tags[:o.Lambda()])

	iWd := o.Lambda()
	for j := o.NK; j < 4*(o.R+1); j++ {
		if j%o.NK == 0 || (o.NK > 6 && j%o.NK == 4) {
			copy(y.keys[4*j:4*j+4], w.keys[iWd/8:iWd/8+4])
			for t := 0; t < 32; t++ {
				y.tags[32*j+t] = w.tags[iWd+t]
			}
			iWd += 32
		} else {
			for i := 0; i < 4; i++ {
				y.keys[4*j+i] = y.keys[4*(j-o.NK)+i] ^ y.keys[4*(j-1)+i]
				for i0 := 8 * i; i0 < 8*i+8; i0++ {
					y.tags[32*j+i0] = f.Add(y.tags[32*(j-o.NK)+i0], y.tags[32*(j-1)+i0])
				}
			}
		}
	}
	return y
}

func (o OWFParams) keyExpBkwdProve(x, xk byteCommits) byteCommits {
	f := x.f
	y := byteCommits{f: f, keys: make([]byte, o.SKe), tags: make([][]uint64, o.SKe*8)}
	for i := range y.tags {
		y.tags[i] = f.Zero()
	}

	iwd := 0
	rconEvery := 4 * (o.Lambda() / 128)
	for j := 0; j < o.SKe; j++ {
		xTilde := x.keys[j] ^ xk.keys[iwd/8+(j%4)]
		xt0 := make([][]uint64, 8)
		for i := 0; i < 8; i++ {
			xt0[i] = f.Add(x.tags[8*j+i], xk.tags[iwd+8*(j%4)+i])
		}
		if j%rconEvery == 0 {
			xTilde ^= rconTable[j/rconEvery]
		}
		y.keys[j] = (xTilde>>7 | xTilde<<1) ^ (xTilde>>5 | xTilde<<3) ^ (xTilde>>2 | xTilde<<6) ^ 0x5
		for i := 0; i < 8; i++ {
			y.tags[8*j+i] = f.Add(f.Add(xt0[(i+7)%8], xt0[(i+5)%8]), xt0[(i+2)%8])
		}
		if j%4 == 3 {
			if o.Lambda() != 256 {
				iwd += o.Lambda()
			} else {
				iwd += 128
			}
		}
	}
	return y
}

func (o OWFParams) keyExpCstrntsProve(zk *ZKProofHasher, w byteCommits) byteCommits {
	f := w.f
	k := o.keyExpFwdProve(w)
	wFlat := o.keyExpBkwdProve(w.subBytes(o.LambdaBytes, o.LKeMinusLambda()/8), k)

	iwd := 32 * (o.NK - 1)
	doRotWord := true
	for j := 0; j < o.SKe/4; j++ {
		for r := 0; r < 4; r++ {
			rp := r
			if doRotWord {
				rp = (4 + r - 3) % 4
			}
			kHat := k.getFieldCommit(iwd/8 + rp)
			kHatSq := k.getFieldCommitSq(iwd/8 + rp)
			wHat := wFlat.getFieldCommit(4*j + r)
			wHatSq := wFlat.getFieldCommitSq(4*j + r)
			_ = f
			zk.LiftAndProcess(kHat, kHatSq, wHat, wHatSq)

			if r == 3 {
				if o.Lambda() == 256 {
					doRotWord = !doRotWord
				}
				if o.Lambda() == 192 {
					iwd += 192
				} else {
					iwd += 128
				}
			}
		}
	}
	return k
}

func aesRoundProve(f field.Big, state, keyBytes []Commit, sq bool, nStBytes int) []Commit {
	st := sBoxAffineProve(f, state, sq, nStBytes)
	shiftRowsCommits(st, nStBytes/4)
	mixColumnsCommits(f, st, sq)
	addRoundKeyBytesCommits(st, keyBytes)
	return st
}

func (o OWFParams) encCstrntsEvenProve(zk *ZKProofHasher, state, w byteCommits) []Commit {
	f := state.f
	statePrime := make([]Commit, o.NStBits())
	for i := 0; i < o.NStBytes(); i++ {
		norm := (w.keys[i/2] >> ((i % 2) * 4)) & 0xf
		ys := invnormToConjugatesProve(f, norm, w.tags[4*i:4*i+4])
		stateConj := f256F2ConjugatesProve(f, state.keys[i], state.tags[8*i:8*i+8])

		statePrime[i*8+0] = ys[0].Mul(stateConj[4])
		cnstr := statePrime[i*8+0].Mul(stateConj[1]).Add(stateConj[0])
		zk.Update(cnstr)

		for j := 1; j < 8; j++ {
			statePrime[i*8+j] = stateConj[(j+4)%8].Mul(ys[j%4])
		}
	}
	return statePrime
}

func (o OWFParams) encCstrntsOddProve(zk *ZKProofHasher, sTilde byteCommits, st0, st1 []Commit) {
	s := sTilde.inverseShiftRows(o.NSt)
	s.inverseAffine()
	for byteI := 0; byteI < o.NStBytes(); byteI++ {
		si := s.getFieldCommit(byteI)
		siSq := s.getFieldCommitSq(byteI)
		zk.OddRoundCstrnts(si, siSq, st0[byteI], st1[byteI])
	}
}

func (o OWFParams) encCstrntsProve(zk *ZKProofHasher, inputKeys, outputKeys []byte, w byteCommits, extendedKey []byteCommits) {
	f := w.f
	state := addRoundKeyKnownCommitted(f, inputKeys, extendedKey[0])

	for r := 0; r < o.R/2; r++ {
		statePrime := o.encCstrntsEvenProve(zk, state, w.subBytes(3*o.NStBytes()*r/2, o.NStBytes()/2))

		roundKey := extendedKey[2*r+1].committedStateToBytes()
		roundKeySq := squareCommits(roundKey)

		st0 := aesRoundProve(f, statePrime, roundKey, false, o.NStBytes())
		st1 := aesRoundProve(f, statePrime, roundKeySq, true, o.NStBytes())

		if r != o.R/2-1 {
			sTilde := w.subBytes(o.NStBytes()/2+3*o.NStBytes()*r/2, o.NStBytes())
			o.encCstrntsOddProve(zk, sTilde, st0, st1)
			state = sTilde.bytewiseMixColumns(o.NSt)
			state.addRoundKeyAssignCommitted(extendedKey[2*r+2])
		} else {
			sTilde := addRoundKeyKnownCommitted(f, outputKeys, extendedKey[2*r+2])
			o.encCstrntsOddProve(zk, sTilde, st0, st1)
		}
	}
}

func (o OWFParams) owfConstraintsProve(zk *ZKProofHasher, w byteCommits, pk *PublicKey) {
	f := w.f

	// First constraint (::5): the product of the two low witness bits.
	k0 := w.keys[0] & 1
	k1 := (w.keys[0] >> 1) & 1
	tag2 := f.Zero()
	if k1 != 0 {
		tag2 = f.Add(tag2, w.tags[0])
	}
	if k0 != 0 {
		tag2 = f.Add(tag2, w.tags[1])
	}
	zk.Update(commitDeg3(f, f.FromBit(k0&k1), f.Zero(), f.Mul(w.tags[0], w.tags[1]), tag2))

	owfInput := append([]byte(nil), pk.OwfInput...)
	k := o.keyExpCstrntsProve(zk, w.subBytes(0, o.LKe/8))

	extendedKey := make([]byteCommits, o.R+1)
	for i := 0; i <= o.R; i++ {
		extendedKey[i] = k.subBytes(i*o.NStBytes(), o.NStBytes())
	}

	for b := 0; b < o.Beta; b++ {
		wTilde := w.subBytes(o.LKe/8+b*o.LEnc/8, o.LEnc/8)
		owfOutput := pk.OwfOutput[o.InputSize*b : o.InputSize*(b+1)]
		o.encCstrntsProve(zk, owfInput, owfOutput, wTilde, extendedKey)
		owfInput[0] ^= 1
	}
}

// AesProve runs the prover OWF constraint circuit and returns the three
// QuickSilver proof values. Transpiled from zk_constraints.rs aes_prove.
func (o OWFParams) AesProve(f field.Big, w, u []byte, v [][]byte, pk *PublicKey, chall2 []byte) (a0, a1, a2 []uint64) {
	zk := NewZKProofHasher(f, chall2)
	vField := o.reshapeAndToField(f, v)

	u0 := f.SumPolyBits(u[:o.LambdaBytes])
	u1 := f.SumPolyBits(u[o.LambdaBytes : 2*o.LambdaBytes])
	v0 := f.SumPoly(vField[o.L() : o.L()+o.Lambda()])
	v1 := f.SumPoly(vField[o.L()+o.Lambda():])

	wc := byteCommits{f: f, keys: w, tags: vField[:o.L()]}
	o.owfConstraintsProve(zk, wc, pk)

	return zk.Finalize(v0, f.Add(u0, v1), u1)
}
