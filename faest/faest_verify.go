package faest

import "github.com/maceip/tamayo/field"

// PublicKey is a FAEST OWF public key: the OWF input and output.
type PublicKey struct {
	OwfInput  []byte
	OwfOutput []byte
}

// Verifier-side FAEST OWF constraint circuit. Transpiled from faest-rs
// src/verifier/{key_expansion,encryption,owf_constraints}.rs and the aes_verify
// half of src/zk_constraints.rs. The prover half lives in faest_prove.go.

func inverseAffineByte(f field.Big, yTag, xTag [][]uint64, delta []uint64) {
	for i := 0; i < 8; i++ {
		yTag[i] = f.Add(f.Add(xTag[(i+7)%8], xTag[(i+5)%8]), xTag[(i+2)%8])
	}
	yTag[0] = f.Add(yTag[0], delta)
	yTag[2] = f.Add(yTag[2], delta)
}

func (o OWFParams) keyExpFwd(w voleCommits) voleCommits {
	f := w.f
	y := make([][]uint64, o.R1Times128())
	for i := range y {
		y[i] = f.Zero()
	}
	copy(y[:o.Lambda()], w.scalars[:o.Lambda()])

	iWd := o.Lambda()
	for j := o.NK; j < 4*(o.R+1); j++ {
		if j%o.NK == 0 || (o.NK > 6 && j%o.NK == 4) {
			for i := 0; i < 32; i++ {
				y[32*j+i] = w.scalars[iWd+i]
			}
			iWd += 32
		} else {
			for i := 0; i < 32; i++ {
				y[32*j+i] = f.Add(y[32*(j-o.NK)+i], y[32*(j-1)+i])
			}
		}
	}
	return voleCommits{f: f, scalars: y, delta: w.delta}
}

func (o OWFParams) keyExpBkwd(x, xk voleCommits) voleCommits {
	f := x.f
	y := make([][]uint64, o.SKe*8)
	for i := range y {
		y[i] = f.Zero()
	}

	iwd := 0
	rconEvery := 4 * (o.Lambda() / 128)
	for j := 0; j < o.SKe; j++ {
		xt := make([][]uint64, 8)
		for i := 0; i < 8; i++ {
			xi := f.Add(x.scalars[8*j+i], xk.scalars[iwd+8*(j%4)+i])
			if j%rconEvery == 0 && (rconTable[j/rconEvery]>>i)&1 != 0 {
				xi = f.Add(xi, x.delta)
			}
			xt[i] = xi
		}
		inverseAffineByte(f, y[8*j:8*j+8], xt, x.delta)
		if j%4 == 3 {
			if o.Lambda() != 256 {
				iwd += o.Lambda()
			} else {
				iwd += 128
			}
		}
	}
	return voleCommits{f: f, scalars: y, delta: x.delta}
}

func (o OWFParams) keyExpCstrnts(zk *ZKVerifyHasher, w voleCommits) voleCommits {
	f := w.f
	k := o.keyExpFwd(w)
	wFlat := o.keyExpBkwd(w.sub(o.Lambda(), o.LKeMinusLambda()), k)

	iwd := 32 * (o.NK - 1)
	doRotWord := true
	for j := 0; j < o.SKe/4; j++ {
		for r := 0; r < 4; r++ {
			rp := r
			if doRotWord {
				rp = (4 + r - 3) % 4
			}
			kHat := f.ByteCombine(k.scalars[iwd+8*rp : iwd+8*rp+8])
			kHatSq := f.ByteCombineSq(k.scalars[iwd+8*rp : iwd+8*rp+8])
			wHat := f.ByteCombine(wFlat.scalars[32*j+8*r : 32*j+8*r+8])
			wHatSq := f.ByteCombineSq(wFlat.scalars[32*j+8*r : 32*j+8*r+8])
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

func f256F2Conjugates(f field.Big, state [][]uint64) [][]uint64 {
	out := make([][]uint64, len(state))
	for base := 0; base < len(state); base += 8 {
		x0 := make([][]uint64, 8)
		for k := 0; k < 8; k++ {
			x0[k] = append([]uint64(nil), state[base+k]...)
		}
		for j := 0; j < 7; j++ {
			out[base+j] = f.ByteCombine(x0)
			x0 = f.SquareByte(x0)
		}
		out[base+7] = f.ByteCombine(x0)
	}
	return out
}

func invnormToConjugates(f field.Big, x [][]uint64) [][]uint64 {
	bsq := f.BetaSquares()
	bcube := f.BetaCubes()
	out := make([][]uint64, 4)
	for j := 0; j < 4; j++ {
		out[j] = f.Add(f.Add(f.Add(x[0], f.Mul(bsq[j], x[1])), f.Mul(bsq[j+1], x[2])), f.Mul(bcube[j], x[3]))
	}
	return out
}

func (o OWFParams) aesRoundVerify(state voleCommits, keyBytes [][]uint64, sq bool) voleCommits {
	st := state.sBoxAffine(sq)
	st.shiftRows()
	st.mixColumns(sq)
	st.addRoundKeyBytes(keyBytes, sq)
	return st
}

func (o OWFParams) encCstrntsEven(zk *ZKVerifyHasher, state, w voleCommits) voleCommits {
	f := state.f
	stateConj := f256F2Conjugates(f, state.scalars)
	statePrime := make([][]uint64, o.NStBits())
	for i := 0; i < o.NStBytes(); i++ {
		ys := invnormToConjugates(f, w.scalars[4*i:4*i+4])
		zk.InvNormConstraints(stateConj[8*i:8*i+8], ys[0])
		for j := 0; j < 8; j++ {
			statePrime[i*8+j] = f.Mul(stateConj[8*i+(j+4)%8], ys[j%4])
		}
	}
	return voleCommits{f: f, scalars: statePrime, delta: state.delta}
}

func (o OWFParams) encCstrntsOdd(zk *ZKVerifyHasher, sTilde, st0, st1 voleCommits) {
	s := sTilde.inverseShiftRows()
	s.inverseAffine()
	for byteI := 0; byteI < o.NStBytes(); byteI++ {
		si := s.getFieldCommit(byteI)
		siSq := s.getFieldCommitSq(byteI)
		zk.OddRoundCstrnts(si, siSq, st0.scalars[byteI], st1.scalars[byteI])
	}
}

func (o OWFParams) encCstrnts(zk *ZKVerifyHasher, input, output, w voleCommits, extendedKey []voleCommits) {
	f := input.f
	state := input.addRoundKey(extendedKey[0])

	for r := 0; r < o.R/2; r++ {
		statePrime := o.encCstrntsEven(zk, state, w.sub(3*o.NStBits()*r/2, o.NStBits()/2))

		roundKey := extendedKey[2*r+1].stateToBytes()
		roundKeySq := squareEach(f, roundKey)

		st0 := o.aesRoundVerify(statePrime, roundKey, false)
		st1 := o.aesRoundVerify(statePrime, roundKeySq, true)

		if r != o.R/2-1 {
			sTilde := w.sub(o.NStBits()/2+3*o.NStBits()*r/2, o.NStBits())
			o.encCstrntsOdd(zk, sTilde, st0, st1)
			state = sTilde.bytewiseMixColumns()
			state.addRoundKeyAssign(extendedKey[2*r+2])
		} else {
			sTilde := output.addRoundKey(extendedKey[2*r+2])
			o.encCstrntsOdd(zk, sTilde, st0, st1)
		}
	}
}

func (o OWFParams) owfConstraintsVerify(zk *ZKVerifyHasher, w voleCommits, delta []uint64, pk *PublicKey) {
	f := w.f
	zk.MulAndUpdate(w.scalars[0], w.scalars[1])

	// EM path not yet implemented; AES (non-EM) FAEST below.
	owfInput := vcFromConstant(f, pk.OwfInput[:o.NStBytes()], delta)
	k := o.keyExpCstrnts(zk, w.sub(0, o.LKe))

	extendedKey := make([]voleCommits, o.R+1)
	for i := 0; i <= o.R; i++ {
		extendedKey[i] = k.sub(i*o.NStBits(), o.NStBits())
	}

	for b := 0; b < o.Beta; b++ {
		wTilde := w.sub(o.LKe+b*o.LEnc, o.LEnc)
		owfOutput := vcFromConstant(f, pk.OwfOutput[o.InputSize*b:o.InputSize*(b+1)], delta)
		o.encCstrnts(zk, owfInput, owfOutput, wTilde, extendedKey)
		owfInput.scalars[0] = f.Add(owfInput.scalars[0], delta)
	}
}

// reshapeAndToField transposes the lambda x LHatBytes VOLE-tag matrix into field
// elements (8 per byte-column). Transpiled from zk_constraints.rs
// reshape_and_to_field.
func (o OWFParams) reshapeAndToField(f field.Big, m [][]byte) [][]uint64 {
	lam := o.Lambda()
	cols := o.LBytes + 2*o.LambdaBytes
	out := make([][]uint64, cols*8)
	for col := 0; col < cols; col++ {
		ret := make([][]byte, 8)
		for i := range ret {
			ret[i] = make([]byte, o.LambdaBytes)
		}
		for row := 0; row < lam; row++ {
			b := m[row][col]
			for i := 0; i < 8; i++ {
				ret[i][row/8] |= ((b >> i) & 1) << (row % 8)
			}
		}
		for i := 0; i < 8; i++ {
			out[col*8+i] = f.FromBytes(ret[i])
		}
	}
	return out
}

// AesVerify recomputes the QuickSilver value from a FAEST signature's VOLE tags
// q, witness diff d, and the prover's a1_tilde/a2_tilde. Transpiled from
// zk_constraints.rs aes_verify.
func (o OWFParams) AesVerify(f field.Big, q [][]byte, d []byte, pk *PublicKey, chall2, chall3, a1Tilde, a2Tilde []byte) []uint64 {
	delta := f.FromBytes(chall3)
	qf := o.reshapeAndToField(f, q)

	for i := 0; i < o.L(); i++ {
		if (d[i/8]>>(i%8))&1 != 0 {
			qf[i] = f.Add(qf[i], delta)
		}
	}
	w := voleCommits{f: f, scalars: qf[:o.L()], delta: delta}

	q0 := f.SumPoly(qf[o.L() : o.L()+o.Lambda()])
	q1 := f.SumPoly(qf[o.L()+o.Lambda() : o.L()+2*o.Lambda()])
	qStar := f.Add(f.Mul(delta, q1), q0)

	zk := NewZKVerifyHasher(f, chall2, delta)
	o.owfConstraintsVerify(zk, w, delta, pk)
	qTilde := zk.Finalize(qStar)

	res := f.Add(qTilde, f.Mul(delta, f.FromBytes(a1Tilde)))
	res = f.Add(res, f.Mul(f.Square(delta), f.FromBytes(a2Tilde)))
	return res
}
