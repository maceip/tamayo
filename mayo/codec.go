package mayo

import "encoding/binary"

// Nibble-packed GF(16) encoding/decoding and bitsliced m-vector (un)packing.
// Transpiled function-by-function from pq-mayo src/codec.rs
// (decode, encode, unpack_m_vecs, pack_m_vecs).

// decode unpacks length nibbles from input (two per byte, low nibble first)
// into one GF(16) element per output byte.
func decode(input, output []byte, length int) {
	outIdx := 0
	i := 0
	for i < length/2 {
		output[outIdx] = input[i] & 0xf
		output[outIdx+1] = input[i] >> 4
		outIdx += 2
		i++
	}
	if length%2 == 1 {
		output[outIdx] = input[i] & 0x0f
	}
}

// encode packs length GF(16) elements (one per input byte) into nibbles
// (two per output byte, low nibble first).
func encode(input, output []byte, length int) {
	inIdx := 0
	i := 0
	for i < length/2 {
		output[i] = input[inIdx] | (input[inIdx+1] << 4)
		inIdx += 2
		i++
	}
	if length%2 == 1 {
		output[i] = input[inIdx]
	}
}

// unpackMVecs converts vecs packed byte vectors (m/2 bytes each) into bitsliced
// u64 m-vectors (ceil(m/16) limbs each), little-endian.
func unpackMVecs(input []byte, output []uint64, vecs, m int) {
	mVecLimbs := (m + 15) / 16
	packedSize := m / 2

	for i := 0; i < vecs; i++ {
		src := input[i*packedSize : (i+1)*packedSize]
		dst := output[i*mVecLimbs : (i+1)*mVecLimbs]
		for j := range dst {
			dst[j] = 0
		}
		for j := 0; j < mVecLimbs; j++ {
			var buf [8]byte
			lo := j * 8
			hi := lo + 8
			if hi > packedSize {
				hi = packedSize
			}
			if lo < hi {
				copy(buf[:], src[lo:hi])
			}
			dst[j] = binary.LittleEndian.Uint64(buf[:])
		}
	}
}

// packMVecs converts vecs bitsliced u64 m-vectors back into packed byte vectors.
func packMVecs(input []uint64, output []byte, vecs, m int) {
	mVecLimbs := (m + 15) / 16
	packedSize := m / 2

	for i := 0; i < vecs; i++ {
		src := input[i*mVecLimbs : (i+1)*mVecLimbs]
		for j := 0; j < packedSize; j++ {
			limbIdx := j / 8
			byteIdx := j % 8
			output[i*packedSize+j] = byte(src[limbIdx] >> (byteIdx * 8))
		}
	}
}
