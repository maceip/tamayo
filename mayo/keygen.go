package mayo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
)

// Key generation. Transpiled from pq-mayo src/keygen.rs (expand_p1_p2,
// mayo_keypair_compact). The reference's AES-128-Ctr32BE keystream is produced
// here with stdlib crypto/cipher CTR over a zero IV: both increment a
// big-endian counter from zero and are byte-identical for the (< 2^32) block
// counts MAYO uses.

// expandP1P2 expands P1 and P2 from the 16-byte public-key seed using
// AES-128-CTR, returning P1_LIMBS+P2_LIMBS bitsliced u64 limbs.
func expandP1P2(p *Params, seedPK []byte) []uint64 {
	totalLimbs := p.P1Limbs() + p.P2Limbs()
	numVecs := totalLimbs / p.MVecLimbs
	packedSize := p.M / 2

	block, err := aes.NewCipher(seedPK[:16])
	if err != nil {
		panic(err)
	}
	iv := make([]byte, 16)
	stream := cipher.NewCTR(block, iv)

	buf := make([]byte, numVecs*packedSize)
	stream.XORKeyStream(buf, buf) // buf is zero, so this yields the keystream

	result := make([]uint64, totalLimbs)
	unpackMVecs(buf, result, numVecs, p.M)
	return result
}

// keypairCompact derives a compact keypair from a secret seed. seedSK must be
// p.SKSeedBytes long; cpk must be p.CPKBytes and csk p.CSKBytes.
func keypairCompact(p *Params, seedSK, cpk, csk []byte) {
	copy(csk[:p.SKSeedBytes], seedSK)

	// S = SHAKE256(seed_sk) -> pk_seed || O_bytes
	s := make([]byte, p.PKSeedBytes+p.OBytes)
	h := sha3.NewSHAKE256()
	h.Write(seedSK)
	h.Read(s)
	seedPK := s[:p.PKSeedBytes]

	v := p.V()
	oo := p.O
	o := make([]byte, v*oo)
	decode(s[p.PKSeedBytes:], o, v*oo)

	pp := expandP1P2(p, seedPK)
	p1Limbs := p.P1Limbs()
	p1 := pp[:p1Limbs]
	p2 := pp[p1Limbs:]

	p3 := make([]uint64, oo*oo*p.MVecLimbs)
	computeP3(p, p1, p2, o, p3)

	copy(cpk[:p.PKSeedBytes], seedPK)
	p3Upper := make([]uint64, p.P3Limbs())
	mUpper(p.MVecLimbs, p3, p3Upper, oo)
	packMVecs(p3Upper, cpk[p.PKSeedBytes:], p.P3Limbs()/p.MVecLimbs, p.M)
}
