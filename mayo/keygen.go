package mayo

import (
	"crypto/aes"
	"crypto/sha3"
)

// Key generation. Transpiled from pq-mayo src/keygen.rs (expand_p1_p2,
// mayo_keypair_compact). The reference's AES-128-Ctr keystream over a zero IV is
// produced here with stdlib crypto/aes ECB over a big-endian block counter from
// zero — byte-identical to crypto/cipher.NewCTR for the (< 2^32) block counts
// MAYO uses, but without importing crypto/cipher, whose AES-CTR fast path pulls
// a FIPS self-test that stalls bare-metal TamaGo at init.

// expandP1P2 expands P1 and P2 from the 16-byte public-key seed using
// AES-128-CTR, returning P1_LIMBS+P2_LIMBS bitsliced u64 limbs.
func expandP1P2(p *Params, seedPK []byte) []uint64 {
	totalLimbs := p.P1Limbs() + p.P2Limbs()
	numVecs := totalLimbs / p.MVecLimbs
	packedSize := p.M / 2

	buf := make([]byte, numVecs*packedSize)
	aesCTRZeroIV(seedPK[:16], buf)

	result := make([]uint64, totalLimbs)
	unpackMVecs(buf, result, numVecs, p.M)
	return result
}

// aesCTRZeroIV fills dst with the AES-128-CTR keystream under key, IV = 0, i.e.
// dst[16i:16i+16] = AES_key(be128(i)), matching crypto/cipher.NewCTR(block, 0)
// applied to a zero buffer. The counter is the full 128-bit IV incremented big
// endian, as in the reference.
func aesCTRZeroIV(key, dst []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var ctr [16]byte
	var ks [16]byte
	for off := 0; off < len(dst); off += 16 {
		block.Encrypt(ks[:], ctr[:])
		copy(dst[off:], ks[:])
		for i := 15; i >= 0; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
	}
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
