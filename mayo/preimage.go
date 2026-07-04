package mayo

import (
	"crypto/sha3"

	"github.com/maceip/tamayo/gf16"
)

// SignWithoutHashing is the MAYO preimage sampler used by One-More-MAYO's
// blind sign_2. Transpiled from pq_blind_signatures mayo-c-sys
// mayo_without_hashing.c (mayo_sign_signature_without_hashing): the standard
// MAYO signer with the message->digest->salt->t hashing chain removed. The
// target t is supplied directly (m_bytes, nibble-encoded), the vinegar is
// V = SHAKE256(t || seed_sk || ctr) with NO salt, and the output is encode(s)
// of length sig_bytes - salt_bytes (no salt appended).
//
// It returns a preimage s (the blinded MAYO signature) with eval_public_map(s)
// == decode(t), i.e. the vole witness s-part for the ZK proof.
//
// t is attacker-controlled in the blind protocol (the user supplies it), so a
// wrong-sized t or csk returns nil instead of panicking.
func (p *Params) SignWithoutHashing(t, csk []byte) []byte {
	if len(t) != p.MBytes || len(csk) != p.CSKBytes {
		return nil
	}
	m := p.M
	n := p.N
	oo := p.O
	k := p.K
	v := p.V()
	mvl := p.MVecLimbs
	mBytes := p.MBytes
	vBytes := p.VBytes
	rBytes := p.RBytes
	aCols := p.ACols()
	skSeedBytes := p.SKSeedBytes

	pp, _, oMat := expandSK(p, csk)
	p1 := pp[:p.P1Limbs()]
	l := pp[p.P1Limbs():]
	seedSK := csk[:skSeedBytes]

	tDec := make([]byte, m)
	decode(t, tDec, m)

	// tmp = t (m_bytes) || seed_sk || ctr(1 byte)
	tmp := make([]byte, mBytes+skSeedBytes+1)
	copy(tmp, t[:mBytes])
	copy(tmp[mBytes:], seedSK)
	ctrIdx := mBytes + skSeedBytes

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

	found := false
	for ctr := 0; ctr <= 255; ctr++ {
		tmp[ctrIdx] = byte(ctr)
		hv := sha3.NewSHAKE256()
		hv.Write(tmp)
		hv.Read(vAndR)

		for i := 0; i < k; i++ {
			decode(vAndR[i*vBytes:], vdec[i*v:], v)
		}
		clear(mtmp)
		clear(vpv)
		computeMAndVpv(p, vdec, l, p1, mtmp, vpv, pv)
		clear(y)
		computeRHS(p, vpv, tDec, y)
		clear(aMatrix)
		computeA(p, mtmp, aScratch, aMatrix)
		for i := 0; i < m; i++ {
			aMatrix[(1+i)*aCols-1] = 0
		}
		clear(x)
		decode(vAndR[k*vBytes:], x, k*oo)

		if sampleSolution(p, aMatrix, y, x) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	// s[i] = v[i] + O · x[i]; s[i][v:n] = x[i]
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

	sigLen := (n*k + 1) / 2 // sig_bytes - salt_bytes = ceil(n*k/2)
	sig := make([]byte, sigLen)
	encode(s, sig, n*k)
	return sig
}
