package mayo

import (
	"crypto/sha3"
	"crypto/subtle"

	"github.com/maceip/tamayo/gf16"
)

// Signature verification. Transpiled from pq-mayo src/verify.rs
// (expand_public_key, eval_public_map, mayo_verify_split_with_scratch) and
// src/sign.rs (compute_rhs, shared with signing).

// computeRHS computes y = t XOR reduce_{f(X)}(vpv). vpv is modified in place.
// Transpiled from pq-mayo src/sign.rs: compute_rhs.
func computeRHS(p *Params, vpv []uint64, t []byte, y []byte) {
	mvl := p.MVecLimbs
	m := p.M
	k := p.K
	fTail := p.FTail
	topPos := ((m - 1) % 16) * 4

	if m%16 != 0 {
		var mask uint64 = 1
		mask <<= uint((m % 16) * 4)
		mask -= 1
		for i := 0; i < k*k; i++ {
			vpv[i*mvl+mvl-1] &= mask
		}
	}

	temp := make([]uint64, mvl)
	for i := k - 1; i >= 0; i-- {
		for j := i; j < k; j++ {
			// multiply temp by X (shift up one nibble across limbs)
			top := byte((temp[mvl-1] >> uint(topPos)) % 16)
			temp[mvl-1] <<= 4
			for kk := mvl - 2; kk >= 0; kk-- {
				temp[kk+1] ^= temp[kk] >> 60
				temp[kk] <<= 4
			}
			// reduce mod f(X) using the tail coefficients
			for jj := 0; jj < fTailLen; jj++ {
				product := gf16.Mul(top, fTail[jj])
				limbIdx := (jj / 2) / 8
				byteIdx := (jj / 2) % 8
				if jj%2 == 0 {
					temp[limbIdx] ^= uint64(product) << uint(byteIdx*8)
				} else {
					temp[limbIdx] ^= uint64(product) << uint(byteIdx*8+4)
				}
			}
			// add the symmetric vPv contribution
			idxIJ := (i*k + j) * mvl
			idxJI := (j*k + i) * mvl
			for kk := 0; kk < mvl; kk++ {
				var sym uint64
				if i != j {
					sym = vpv[idxJI+kk]
				}
				temp[kk] ^= vpv[idxIJ+kk] ^ sym
			}
		}
	}

	for i := 0; i < m; i += 2 {
		limbIdx := (i / 2) / 8
		byteIdx := (i / 2) % 8
		byteVal := byte((temp[limbIdx] >> uint(byteIdx*8)) & 0xFF)
		y[i] = t[i] ^ (byteVal & 0xF)
		if i+1 < m {
			y[i+1] = t[i+1] ^ (byteVal >> 4)
		}
	}
}

// expandPublicKey expands cpk into (P1‖P2) and P3 (bitsliced m-vectors).
func expandPublicKey(p *Params, cpk []byte) (pk, p3 []uint64) {
	pk = expandP1P2(p, cpk[:p.PKSeedBytes])
	p3 = make([]uint64, p.P3Limbs())
	unpackMVecs(cpk[p.PKSeedBytes:], p3, p.P3Limbs()/p.MVecLimbs, p.M)
	return
}

// evalPublicMap computes eval = reduce(S·P·Sᵀ), i.e. the public map at s.
func evalPublicMap(p *Params, s []byte, p1, p2, p3 []uint64, eval []byte) {
	k := p.K
	mvl := p.MVecLimbs
	sps := make([]uint64, k*k*mvl)
	mCalculatePsSps(p, p1, p2, p3, s, sps)
	zero := make([]byte, p.M)
	computeRHS(p, sps, zero, eval)
}

// mayoVerify reports whether sig is a valid MAYO signature on msg under cpk.
func mayoVerify(p *Params, msg, sig, cpk []byte) bool {
	pk, p3 := expandPublicKey(p, cpk)
	p1 := pk[:p.P1Limbs()]
	p2 := pk[p.P1Limbs() : p.P1Limbs()+p.P2Limbs()]
	return mayoVerifySplit(p, msg, sig, p1, p2, p3)
}

func mayoVerifySplit(p *Params, msg, sig []byte, p1, p2, p3 []uint64) bool {
	m := p.M
	n := p.N
	k := p.K
	digestBytes := p.DigestBytes
	saltBytes := p.SaltBytes
	sigBytes := p.SigBytes

	// digest = SHAKE256(msg)
	tmp := make([]byte, digestBytes+saltBytes)
	h := sha3.NewSHAKE256()
	h.Write(msg)
	h.Read(tmp[:digestBytes])

	// t = SHAKE256(digest || salt), salt taken from the signature
	copy(tmp[digestBytes:digestBytes+saltBytes], sig[sigBytes-saltBytes:sigBytes])
	tenc := make([]byte, p.MBytes)
	h2 := sha3.NewSHAKE256()
	h2.Write(tmp[:digestBytes+saltBytes])
	h2.Read(tenc)
	t := make([]byte, m)
	decode(tenc, t, m)

	// decode s from the signature
	s := make([]byte, k*n)
	decode(sig, s, k*n)

	// evaluate the public map and compare in constant time
	y := make([]byte, m)
	evalPublicMap(p, s, p1, p2, p3, y)
	return subtle.ConstantTimeCompare(y, t) == 1
}
