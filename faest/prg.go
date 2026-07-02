package faest

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// PRG is the FAEST pseudo-random generator: AES in counter mode with a 32-bit
// little-endian counter held in the last four IV bytes, offset by a tweak.
// Transpiled from faest-rs src/prg.rs (PseudoRandomGenerator, Ctr32LE,
// add_tweak). The AES variant (128/192/256) is selected by the key length.
type PRG struct {
	block  cipher.Block
	tail   [12]byte // fixed IV bytes [4:16] (nonce chunks 1..3)
	ctr    uint32   // 32-bit LE counter in the first 4 bytes (nonce[0] + block index)
	buf    [16]byte
	bufPos int // 16 == keystream buffer empty
}

// NewPRG creates a PRG keyed by key (16/24/32 bytes) and seeded by iv (16
// bytes). Per Ctr32LE, the counter is the first 4 bytes read little-endian; the
// remaining 12 bytes are the fixed nonce. add_tweak adds tweak (mod 2^32) to the
// little-endian word at iv[12:16] before use.
func NewPRG(key, iv []byte, tweak uint32) *PRG {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var ivt [16]byte
	copy(ivt[:], iv)
	binary.LittleEndian.PutUint32(ivt[12:16], binary.LittleEndian.Uint32(ivt[12:16])+tweak)

	p := &PRG{block: block, bufPos: 16}
	p.ctr = binary.LittleEndian.Uint32(ivt[0:4])
	copy(p.tail[:], ivt[4:16])
	return p
}

// Read XORs the next keystream bytes into dst (matching apply_keystream); when
// dst is all-zero this yields the raw keystream. The stream is continuous across
// calls.
func (p *PRG) Read(dst []byte) {
	for i := range dst {
		if p.bufPos == 16 {
			var cb [16]byte
			binary.LittleEndian.PutUint32(cb[0:4], p.ctr)
			copy(cb[4:16], p.tail[:])
			p.block.Encrypt(p.buf[:], cb[:])
			p.ctr++
			p.bufPos = 0
		}
		dst[i] ^= p.buf[p.bufPos]
		p.bufPos++
	}
}
