package mayo

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, length := range []int{0, 1, 2, 3, 4, 5, 39, 55, 78} {
		nibs := make([]byte, length)
		for i := range nibs {
			nibs[i] = byte(r.Intn(16))
		}
		packed := make([]byte, (length+1)/2)
		encode(nibs, packed, length)
		back := make([]byte, length)
		decode(packed, back, length)
		if !bytes.Equal(nibs, back) {
			t.Fatalf("encode/decode round trip mismatch at length %d: %v vs %v", length, nibs, back)
		}
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	const m = 78 // Mayo1
	const vecs = 3
	packedSize := m / 2
	packed := make([]byte, vecs*packedSize)
	for i := range packed {
		packed[i] = byte(r.Intn(256))
	}
	mVecLimbs := (m + 15) / 16
	u := make([]uint64, vecs*mVecLimbs)
	unpackMVecs(packed, u, vecs, m)
	back := make([]byte, vecs*packedSize)
	packMVecs(u, back, vecs, m)
	if !bytes.Equal(packed, back) {
		t.Fatalf("pack/unpack round trip mismatch")
	}
}
