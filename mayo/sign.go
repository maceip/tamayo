package mayo

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"

	"github.com/maceip/tamayo/gf16"
)

// Signature generation. Transpiled from pq-mayo src/sign.rs (expand_sk,
// transpose_16x16_nibbles, decode_packed_nibbles, compute_a,
// mayo_sign_signature_with_expanded_sk). compute_rhs is shared from verify.go.

var errSignFault = errors.New("mayo: signature fault check failed")

// expandSK expands a compact secret key into P1‖L (L = (P1+P1ᵀ)·O + P2), a copy
// of the public P2, and the oil subspace O.
func expandSK(p *Params, csk []byte) (p1L, p2 []uint64, o []byte) {
	v := p.V()
	oo := p.O
	seedSK := csk[:p.SKSeedBytes]

	s := make([]byte, p.PKSeedBytes+p.OBytes)
	h := sha3.NewSHAKE256()
	h.Write(seedSK)
	h.Read(s)

	o = make([]byte, v*oo)
	decode(s[p.PKSeedBytes:], o, v*oo)

	pp := expandP1P2(p, s[:p.PKSeedBytes])
	p1Limbs := p.P1Limbs()
	p2 = append([]uint64(nil), pp[p1Limbs:]...)   // save public P2 before overwrite
	p1p1tTimesO(p, pp[:p1Limbs], o, pp[p1Limbs:]) // L replaces P2 in pp
	return pp, p2, o
}

// transpose16x16Nibbles transposes a 16x16 matrix of nibbles packed in 16 u64s.
func transpose16x16Nibbles(m []uint64) {
	const (
		evenNibbles = 0x0f0f0f0f0f0f0f0f
		evenBytes   = 0x00ff00ff00ff00ff
		even2Bytes  = 0x0000ffff0000ffff
		evenHalf    = 0x00000000ffffffff
	)
	for i := 0; i < 16; i += 2 {
		t := ((m[i] >> 4) ^ m[i+1]) & evenNibbles
		m[i] ^= t << 4
		m[i+1] ^= t
	}
	for i := 0; i < 16; i += 4 {
		t0 := ((m[i] >> 8) ^ m[i+2]) & evenBytes
		t1 := ((m[i+1] >> 8) ^ m[i+3]) & evenBytes
		m[i] ^= t0 << 8
		m[i+1] ^= t1 << 8
		m[i+2] ^= t0
		m[i+3] ^= t1
	}
	for i := 0; i < 4; i++ {
		t0 := ((m[i] >> 16) ^ m[i+4]) & even2Bytes
		t1 := ((m[i+8] >> 16) ^ m[i+12]) & even2Bytes
		m[i] ^= t0 << 16
		m[i+8] ^= t1 << 16
		m[i+4] ^= t0
		m[i+12] ^= t1
	}
	for i := 0; i < 8; i++ {
		t := ((m[i] >> 32) ^ m[i+8]) & evenHalf
		m[i] ^= t << 32
		m[i+8] ^= t
	}
}

// decodePackedNibbles decodes up to length nibbles from packed bytes.
func decodePackedNibbles(input, output []byte, length int) {
	outIdx := 0
	i := 0
	for outIdx < length && i < len(input) {
		output[outIdx] = input[i] & 0xf
		outIdx++
		if outIdx < length {
			output[outIdx] = input[i] >> 4
			outIdx++
		}
		i++
	}
}

// computeA builds the linearized system matrix A (aOut, m×ACols plain GF(16))
// from the M matrices (vtl). a is scratch of length aWidth*ceil(m/8).
func computeA(p *Params, vtl, a []uint64, aOut []byte) {
	mvl := p.MVecLimbs
	m := p.M
	o := p.O
	k := p.K
	aCols := p.ACols()
	fTail := p.FTail

	mOver8 := (m + 7) / 8
	aWidth := ((o*k + 15) / 16) * 16
	aTotal := aWidth * mOver8

	for i := 0; i < aTotal; i++ {
		a[i] = 0
	}

	if m%16 != 0 {
		var mask uint64 = 1
		mask <<= uint((m % 16) * 4)
		mask -= 1
		for i := 0; i < o*k; i++ {
			vtl[i*mvl+mvl-1] &= mask
		}
	}

	bitsToShift := 0
	wordsToShift := 0
	for i := 0; i < k; i++ {
		for j := k - 1; j >= i; j-- {
			mjBase := j * mvl * o
			for c := 0; c < o; c++ {
				for kk := 0; kk < mvl; kk++ {
					src := vtl[mjBase+kk+c*mvl]
					dstIdx := o*i + c + (kk+wordsToShift)*aWidth
					a[dstIdx] ^= src << uint(bitsToShift)
					if bitsToShift > 0 {
						dstIdx2 := o*i + c + (kk+wordsToShift+1)*aWidth
						if dstIdx2 < aTotal {
							a[dstIdx2] ^= src >> uint(64-bitsToShift)
						}
					}
				}
			}
			if i != j {
				miBase := i * mvl * o
				for c := 0; c < o; c++ {
					for kk := 0; kk < mvl; kk++ {
						src := vtl[miBase+kk+c*mvl]
						dstIdx := o*j + c + (kk+wordsToShift)*aWidth
						a[dstIdx] ^= src << uint(bitsToShift)
						if bitsToShift > 0 {
							dstIdx2 := o*j + c + (kk+wordsToShift+1)*aWidth
							if dstIdx2 < aTotal {
								a[dstIdx2] ^= src >> uint(64-bitsToShift)
							}
						}
					}
				}
			}
			bitsToShift += 4
			if bitsToShift == 64 {
				wordsToShift++
				bitsToShift = 0
			}
		}
	}

	// Transpose 16x16 nibble blocks.
	totalTranspose := aWidth * ((m + (k+1)*k/2 + 15) / 16)
	for c := 0; c < totalTranspose; c += 16 {
		transpose16x16Nibbles(a[c : c+16])
	}

	// Reduce mod f(X).
	var tab [fTailLen * 4]byte
	for i := 0; i < fTailLen; i++ {
		tab[4*i] = gf16.Mul(fTail[i], 1)
		tab[4*i+1] = gf16.Mul(fTail[i], 2)
		tab[4*i+2] = gf16.Mul(fTail[i], 4)
		tab[4*i+3] = gf16.Mul(fTail[i], 8)
	}
	const lowBit = 0x1111111111111111
	for c := 0; c < aWidth; c += 16 {
		for rr := m; rr < m+(k+1)*k/2; rr++ {
			pos := (rr/16)*aWidth + c + (rr % 16)
			val := a[pos]
			t0 := val & lowBit
			t1 := (val >> 1) & lowBit
			t2 := (val >> 2) & lowBit
			t3 := (val >> 3) & lowBit
			for tt := 0; tt < fTailLen; tt++ {
				targetR := rr + tt - m
				targetPos := (targetR/16)*aWidth + c + (targetR % 16)
				a[targetPos] ^= t0*uint64(tab[4*tt]) ^ t1*uint64(tab[4*tt+1]) ^
					t2*uint64(tab[4*tt+2]) ^ t3*uint64(tab[4*tt+3])
			}
		}
	}

	// Extract A from the transposed packed form.
	for rr := 0; rr < m; rr += 16 {
		c := 0
		for c < aCols-1 {
			for i := 0; i < 16; i++ {
				if rr+i >= m {
					break
				}
				srcPos := rr*aWidth/16 + c + i
				decodeLen := 16
				if aCols-1-c < 16 {
					decodeLen = aCols - 1 - c
				}
				var srcBytes [8]byte
				binary.LittleEndian.PutUint64(srcBytes[:], a[srcPos])
				decodePackedNibbles(srcBytes[:], aOut[(rr+i)*aCols+c:], decodeLen)
			}
			c += 16
		}
	}
}

// signSignature produces a MAYO signature into sig, drawing the salt randomizer
// (SaltBytes) from randomizer. Returns nil on success.
func signSignature(p *Params, sig, msg, csk, randomizer []byte) error {
	pp, p2, o := expandSK(p, csk)
	return signWithExpandedSK(p, sig, msg, csk, pp, p2, o, randomizer)
}

func signWithExpandedSK(p *Params, sig, msg, csk []byte, pp, p2 []uint64, oMat, randomizer []byte) error {
	m := p.M
	n := p.N
	oo := p.O
	k := p.K
	v := p.V()
	mvl := p.MVecLimbs
	mBytes := p.MBytes
	vBytes := p.VBytes
	rBytes := p.RBytes
	sigBytes := p.SigBytes
	aCols := p.ACols()
	digestBytes := p.DigestBytes
	skSeedBytes := p.SKSeedBytes
	saltBytes := p.SaltBytes

	seedSK := csk[:skSeedBytes]
	p1 := pp[:p.P1Limbs()]
	l := pp[p.P1Limbs():]

	// digest = SHAKE256(msg); tmp = digest || randomizer
	tmp := make([]byte, digestBytes+saltBytes)
	h := sha3.NewSHAKE256()
	h.Write(msg)
	h.Read(tmp[:digestBytes])
	copy(tmp[digestBytes:digestBytes+saltBytes], randomizer[:saltBytes])

	// salt = SHAKE256(digest || randomizer || seed_sk)
	salt := make([]byte, saltBytes)
	hs := sha3.NewSHAKE256()
	hs.Write(tmp[:digestBytes+saltBytes])
	hs.Write(seedSK)
	hs.Read(salt)

	// t = SHAKE256(digest || salt)
	tenc := make([]byte, mBytes)
	t := make([]byte, m)
	copy(tmp[digestBytes:digestBytes+saltBytes], salt)
	ht := sha3.NewSHAKE256()
	ht.Write(tmp[:digestBytes+saltBytes])
	ht.Read(tenc)
	decode(tenc, t, m)

	x := make([]byte, aCols)
	s := make([]byte, k*n)
	vdec := make([]byte, v*k)
	vAndR := make([]byte, k*vBytes+rBytes)
	mtmp := make([]uint64, k*oo*mvl)
	vpv := make([]uint64, k*k*mvl)
	pv := make([]uint64, v*k*mvl)
	y := make([]byte, m)
	aRowSize := ((m + 7) / 8) * 8
	aMatrix := make([]byte, aRowSize*aCols)
	aWidth := ((oo*k + 15) / 16) * 16
	aScratch := make([]uint64, aWidth*((m+7)/8))

	for ctr := 0; ctr <= 255; ctr++ {
		hv := sha3.NewSHAKE256()
		hv.Write(tmp[:digestBytes+saltBytes])
		hv.Write(seedSK)
		hv.Write([]byte{byte(ctr)})
		hv.Read(vAndR)

		for i := 0; i < k; i++ {
			decode(vAndR[i*vBytes:], vdec[i*v:], v)
		}
		for i := range mtmp {
			mtmp[i] = 0
		}
		for i := range vpv {
			vpv[i] = 0
		}
		computeMAndVpv(p, vdec, l, p1, mtmp, vpv, pv)
		for i := range y {
			y[i] = 0
		}
		computeRHS(p, vpv, t, y)
		for i := range aMatrix {
			aMatrix[i] = 0
		}
		computeA(p, mtmp, aScratch, aMatrix)
		for i := 0; i < m; i++ {
			aMatrix[(1+i)*aCols-1] = 0
		}
		for i := range x {
			x[i] = 0
		}
		decode(vAndR[k*vBytes:], x, k*oo)

		if sampleSolution(p, aMatrix, y, x) {
			break
		}
	}

	// s[i] = v[i] + O · x[i]
	for i := 0; i < k; i++ {
		vi := vdec[i*v : (i+1)*v]
		xi := x[i*oo : (i+1)*oo]
		si := s[i*n : (i+1)*n]
		for row := 0; row < v; row++ {
			acc := vi[row]
			for col := 0; col < oo; col++ {
				acc = gf16.Add(acc, gf16.Mul(oMat[row*oo+col], xi[col]))
			}
			si[row] = acc
		}
		copy(si[v:n], xi)
	}

	encode(s, sig, n*k)
	copy(sig[sigBytes-saltBytes:sigBytes], salt)

	// Fault-attack countermeasure: verify against an independently recomputed
	// public map before releasing the signature.
	p2Work := append([]uint64(nil), p2...)
	p3 := make([]uint64, oo*oo*mvl)
	computeP3(p, p1, p2Work, oMat, p3)
	p3Upper := make([]uint64, p.P3Limbs())
	mUpper(mvl, p3, p3Upper, oo)
	if !mayoVerifySplit(p, msg, sig, p1, p2, p3Upper) {
		return errSignFault
	}
	return nil
}
