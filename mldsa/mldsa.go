package mldsa

import (
	"crypto/subtle"
	"errors"
)

// vecMulHat returns a fresh vector with every element of v multiplied
// pointwise (NTT domain) by c.
func vecMulHat(v vec, c *poly) vec {
	w := newVec(len(v))
	for i := range v {
		t := v[i]
		t.mulHat(c)
		w[i] = t
	}
	return w
}

// KeyGen is ML-DSA.KeyGen_internal (FIPS 204 algorithm 6): expand the
// 32-byte seed xi into an encoded key pair.
func (p *Params) KeyGen(xi []byte) (pk, sk []byte, err error) {
	if len(xi) != seedB {
		return nil, nil, errors.New("mldsa: seed must be 32 bytes")
	}
	ext := shake256(128, xi, []byte{byte(p.K), byte(p.L)})
	rho, rhoPrime, key := ext[:32], ext[32:96], ext[96:128]

	a := p.expandA(rho)
	s1, s2 := p.expandS(rhoPrime)

	t := mulMatVecHat(a, s1.copyOf().ntt()).invNTT().add(s2)
	t1 := newVec(p.K)
	t0 := newVec(p.K)
	for i := range t {
		for j := range t[i] {
			r1, r0 := power2Round(t[i][j])
			t1[i][j] = r1
			r0 += (r0 >> 31) & q
			t0[i][j] = r0
		}
	}

	pk = p.pkEncode(rho, t1)
	tr := shake256(64, pk)
	sk = p.skEncode(rho, key, tr, s1, s2, t0)
	return pk, sk, nil
}

// signMu is the FIPS 204 algorithm 7 rejection loop, starting from the
// 64-byte message representative mu.
func (p *Params) signMu(sk, mu, rnd []byte) []byte {
	rho, key, _, s1, s2, t0 := p.skDecode(sk)
	s1Hat := s1.ntt()
	s2Hat := s2.ntt()
	t0Hat := t0.ntt()
	a := p.expandA(rho)

	rhoPP := shake256(64, key, rnd, mu)

	for kappa := 0; ; kappa += p.L {
		y := p.expandMask(rhoPP, kappa)
		w := mulMatVecHat(a, y.copyOf().ntt()).invNTT()
		w1 := p.highBitsVec(w)

		cTilde := shake256(p.Lambda/4, mu, p.w1Encode(w1))
		c := p.sampleInBall(cTilde)
		cHat := c
		cHat.ntt()

		z := y.add(vecMulHat(s1Hat, &cHat).invNTT())
		r := w.sub(vecMulHat(s2Hat, &cHat).invNTT())
		if z.normExceeds(p.Gamma1-p.Beta) || p.lowBitsVec(r).normExceeds(p.Gamma2-p.Beta) {
			continue
		}

		ct0 := vecMulHat(t0Hat, &cHat).invNTT()
		if ct0.normExceeds(p.Gamma2) {
			continue
		}
		h := newVec(p.K)
		weight := 0
		for i := range h {
			for j := range h[i] {
				negCt0 := subQ(0, ct0[i][j])
				h[i][j] = makeHint(p, negCt0, addQ(r[i][j], ct0[i][j]))
				weight += int(h[i][j])
			}
		}
		if weight > p.Omega {
			continue
		}
		return p.sigEncode(cTilde, z, h)
	}
}

// verifyMu is the FIPS 204 algorithm 8 check, starting from mu.
func (p *Params) verifyMu(pk, mu, sig []byte) bool {
	rho, t1 := p.pkDecode(pk)
	cTilde, z, h := p.sigDecode(sig)
	if h == nil || z.normExceeds(p.Gamma1-p.Beta) {
		return false
	}

	a := p.expandA(rho)
	c := p.sampleInBall(cTilde)
	cHat := c
	cHat.ntt()

	wApprox := mulMatVecHat(a, z.ntt()).sub(vecMulHat(t1.scaleD2().ntt(), &cHat)).invNTT()
	w1 := newVec(p.K)
	for i := range w1 {
		for j := range w1[i] {
			w1[i][j] = useHint(p, h[i][j], wApprox[i][j])
		}
	}
	expected := shake256(p.Lambda/4, mu, p.w1Encode(w1))
	return subtle.ConstantTimeCompare(cTilde, expected) == 1
}

// SignInternal is ML-DSA.Sign_internal (FIPS 204 algorithm 7). mPrime is the
// formatted message; rnd is the 32-byte signer randomness (all zero for the
// deterministic variant). The caller-supplied-randomness contract matches
// the rest of this module: rnd must be fresh CSPRNG output in production.
func (p *Params) SignInternal(sk, mPrime, rnd []byte) ([]byte, error) {
	if len(sk) != p.PrivateKeySize {
		return nil, errors.New("mldsa: bad private key size")
	}
	if len(rnd) != seedB {
		return nil, errors.New("mldsa: rnd must be 32 bytes")
	}
	tr := sk[64:128]
	mu := shake256(64, tr, mPrime)
	return p.signMu(sk, mu, rnd), nil
}

// VerifyInternal is ML-DSA.Verify_internal (FIPS 204 algorithm 8). Malformed
// inputs of any length return false rather than panicking.
func (p *Params) VerifyInternal(pk, mPrime, sig []byte) bool {
	if len(pk) != p.PublicKeySize || len(sig) != p.SignatureSize {
		return false
	}
	tr := shake256(64, pk)
	mu := shake256(64, tr, mPrime)
	return p.verifyMu(pk, mu, sig)
}

// formatMsg builds the pure (non-pre-hash) ML-DSA message: the domain
// separator 0, the context length, the context, and the message (FIPS 204
// algorithms 2/3).
func formatMsg(msg, ctx []byte) ([]byte, error) {
	if len(ctx) > 255 {
		return nil, errors.New("mldsa: context longer than 255 bytes")
	}
	m := make([]byte, 0, 2+len(ctx)+len(msg))
	m = append(m, 0, byte(len(ctx)))
	m = append(m, ctx...)
	return append(m, msg...), nil
}

// Sign is pure ML-DSA.Sign (FIPS 204 algorithm 2) with caller-supplied
// 32-byte randomness rnd; pass 32 zero bytes for the deterministic variant.
func (p *Params) Sign(sk, msg, ctx, rnd []byte) ([]byte, error) {
	m, err := formatMsg(msg, ctx)
	if err != nil {
		return nil, err
	}
	return p.SignInternal(sk, m, rnd)
}

// Verify is pure ML-DSA.Verify (FIPS 204 algorithm 3).
func (p *Params) Verify(pk, msg, sig, ctx []byte) bool {
	m, err := formatMsg(msg, ctx)
	if err != nil {
		return false
	}
	return p.VerifyInternal(pk, m, sig)
}

// SignMu is Sign_internal with an externally computed message representative
// mu = H(tr || M', 64) (the FIPS 204 "external mu" variant).
func (p *Params) SignMu(sk, mu, rnd []byte) ([]byte, error) {
	if len(sk) != p.PrivateKeySize {
		return nil, errors.New("mldsa: bad private key size")
	}
	if len(mu) != 64 {
		return nil, errors.New("mldsa: mu must be 64 bytes")
	}
	if len(rnd) != seedB {
		return nil, errors.New("mldsa: rnd must be 32 bytes")
	}
	return p.signMu(sk, mu, rnd), nil
}

// VerifyMu is Verify_internal with an externally computed mu.
func (p *Params) VerifyMu(pk, mu, sig []byte) bool {
	if len(pk) != p.PublicKeySize || len(mu) != 64 || len(sig) != p.SignatureSize {
		return false
	}
	return p.verifyMu(pk, mu, sig)
}
