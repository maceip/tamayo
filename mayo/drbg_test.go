package mayo

import "crypto/aes"

// drbg is the NIST AES-256 CTR-DRBG (no derivation function) used by the PQC
// KAT harness (rng.c: randombytes_init / randombytes / AES256_CTR_DRBG_Update).
// Test-only: it reproduces the exact randomness stream behind the .rsp vectors.
type drbg struct {
	key [32]byte
	v   [16]byte
}

func incV(v *[16]byte) {
	for j := 15; j >= 0; j-- {
		v[j]++
		if v[j] != 0 {
			break
		}
	}
}

func (d *drbg) update(provided []byte) {
	blk, _ := aes.NewCipher(d.key[:])
	var temp [48]byte
	for i := 0; i < 3; i++ {
		incV(&d.v)
		blk.Encrypt(temp[i*16:(i+1)*16], d.v[:])
	}
	if provided != nil {
		for i := 0; i < 48; i++ {
			temp[i] ^= provided[i]
		}
	}
	copy(d.key[:], temp[:32])
	copy(d.v[:], temp[32:48])
}

// newDRBG seeds the DRBG with a 48-byte entropy string (no personalization).
func newDRBG(seed []byte) *drbg {
	d := &drbg{}
	var sm [48]byte
	copy(sm[:], seed)
	d.update(sm[:])
	return d
}

// randombytes fills x with the next DRBG output (one randombytes() call).
func (d *drbg) randombytes(x []byte) {
	blk, _ := aes.NewCipher(d.key[:])
	var block [16]byte
	i, xlen := 0, len(x)
	for xlen > 0 {
		incV(&d.v)
		blk.Encrypt(block[:], d.v[:])
		if xlen > 15 {
			copy(x[i:i+16], block[:])
			i += 16
			xlen -= 16
		} else {
			copy(x[i:i+xlen], block[:xlen])
			xlen = 0
		}
	}
	d.update(nil)
}
