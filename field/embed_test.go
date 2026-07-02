package field

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type byteCombineSet struct {
	Lambda   int        `json:"lambda"`
	Database [][]string `json:"database"`
}

type byteCombineBitsSet struct {
	Lambda   int             `json:"lambda"`
	Database [][]interface{} `json:"database"`
}

func embedFieldFor(l int) Big {
	switch l {
	case 128:
		return Big128
	case 192:
		return Big192
	default:
		return Big256
	}
}

// TestByteCombineKAT validates ByteCombine (and the ALPHA basis) against
// faest-rs vectors (LargeFieldByteCombine.json): byte_combine([x0..x7]) = result.
func TestByteCombineKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/LargeFieldByteCombine.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var sets []byteCombineSet
	if err := json.Unmarshal(raw, &sets); err != nil {
		t.Fatalf("parse: %v", err)
	}
	total := 0
	for _, set := range sets {
		f := embedFieldFor(set.Lambda)
		for i, tc := range set.Database {
			if len(tc) != 9 {
				t.Fatalf("l=%d case %d: want 9 elems, got %d", set.Lambda, i, len(tc))
			}
			x := make([][]uint64, 8)
			for j := 0; j < 8; j++ {
				b, _ := hex.DecodeString(tc[j])
				x[j] = f.FromBytes(b)
			}
			wantB, _ := hex.DecodeString(tc[8])
			got := f.ByteCombine(x)
			if !bytes.Equal(f.ToBytes(got), wantB) {
				t.Fatalf("l=%d case %d: byte_combine mismatch", set.Lambda, i)
			}
			total++
		}
	}
	t.Logf("verified %d byte-combine vectors", total)
}

// TestByteCombineBitsKAT validates ByteCombineBits against faest-rs vectors
// (LargeFieldByteCombineBits.json): byte_combine_bits(b) = result.
func TestByteCombineBitsKAT(t *testing.T) {
	raw, err := os.ReadFile("testdata/LargeFieldByteCombineBits.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var sets []byteCombineBitsSet
	if err := json.Unmarshal(raw, &sets); err != nil {
		t.Fatalf("parse: %v", err)
	}
	total := 0
	for _, set := range sets {
		f := embedFieldFor(set.Lambda)
		for i, tc := range set.Database {
			b := byte(tc[0].(float64))
			wantB, _ := hex.DecodeString(tc[1].(string))
			got := f.ByteCombineBits(b)
			if !bytes.Equal(f.ToBytes(got), wantB) {
				t.Fatalf("l=%d case %d (b=%d): byte_combine_bits mismatch", set.Lambda, i, b)
			}
			total++
		}
	}
	t.Logf("verified %d byte-combine-bits vectors", total)
}

// TestSumPoly checks the fold logic of SumPoly/SumPolyBits against the closed
// form sum_i v[i]*2^i and their mutual consistency.
func TestSumPoly(t *testing.T) {
	f := Big128
	// sum_poly([v0,v1,v2]) == v0 + 2*v1 + 4*v2.
	v0 := f.FromBytes([]byte{0x11, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	v1 := f.FromBytes([]byte{0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	v2 := f.FromBytes([]byte{0x33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	got := f.SumPoly([][]uint64{v0, v1, v2})
	want := f.Add(f.Add(v0, f.Double(v1)), f.Double(f.Double(v2)))
	if !bytes.Equal(f.ToBytes(got), f.ToBytes(want)) {
		t.Fatal("sum_poly closed-form mismatch")
	}

	// sum_poly_bits(b) == sum_poly(each bit as a field element).
	data := []byte{0b10110001, 0x2c}
	bits := make([][]uint64, len(data)*8)
	for i := range bits {
		bits[i] = f.FromBit(data[i/8] >> (i % 8))
	}
	if !bytes.Equal(f.ToBytes(f.SumPolyBits(data)), f.ToBytes(f.SumPoly(bits))) {
		t.Fatal("sum_poly_bits != sum_poly over bits")
	}
}

// TestSquareBits checks the closed-form GF8.SquareBits against bit-serial Square
// over all 256 bytes.
func TestSquareBits(t *testing.T) {
	for x := 0; x < 256; x++ {
		if GF8(x).SquareBits() != GF8(x).Square() {
			t.Fatalf("SquareBits(%d) != Square", x)
		}
	}
}

// TestGF4Embed validates the GF(16)->GF(2^lambda) embedding constants: the
// embedded generator powers must satisfy x^2 = x*x and x^3 = x^2*x in the field.
// This also confirms the .shape constants use the same field as this engine.
func TestGF4Embed(t *testing.T) {
	for _, f := range []Big{Big128, Big192, Big256} {
		e := f.GF4Embed()
		if !bytes.Equal(f.ToBytes(e[1]), f.ToBytes(f.Mul(e[0], e[0]))) {
			t.Fatalf("%d-bit: x^2 != x*x", f.Bytes*8)
		}
		if !bytes.Equal(f.ToBytes(e[2]), f.ToBytes(f.Mul(e[1], e[0]))) {
			t.Fatalf("%d-bit: x^3 != x^2*x", f.Bytes*8)
		}
	}
}

// TestByteCombineSquared checks the squaring homomorphism of the embedding:
// byte_combine_bits_sq(b) == byte_combine_bits(b)^2, and that SquareByte on the
// bit embedding matches, for every byte and field.
func TestByteCombineSquared(t *testing.T) {
	for _, f := range []Big{Big128, Big192, Big256} {
		for b := 0; b < 256; b++ {
			want := f.Square(f.ByteCombineBits(byte(b)))

			if !bytes.Equal(f.ToBytes(f.ByteCombineBitsSq(byte(b))), f.ToBytes(want)) {
				t.Fatalf("%d-bit: byte_combine_bits_sq(%d) != byte_combine_bits(b)^2", f.Bytes*8, b)
			}

			bits := make([][]uint64, 8)
			for i := range bits {
				bits[i] = f.FromBit(byte(b) >> i)
			}
			if !bytes.Equal(f.ToBytes(f.ByteCombineSq(bits)), f.ToBytes(want)) {
				t.Fatalf("%d-bit: byte_combine_sq(bits(%d)) != byte_combine_bits(b)^2", f.Bytes*8, b)
			}
		}
	}
}
