package gf16

import "testing"

// TestMulTable checks that the four table lanes equal b*{1,2,4,8} = Mul(b,·),
// cross-validating the packed table trick against the scalar Mul.
func TestMulTable(t *testing.T) {
	for b := 0; b < 16; b++ {
		tab := MulTable(byte(b))
		lanes := [4]byte{
			byte(tab & 0xf),
			byte((tab >> 8) & 0xf),
			byte((tab >> 16) & 0xf),
			byte((tab >> 24) & 0xf),
		}
		want := [4]byte{Mul(byte(b), 1), Mul(byte(b), 2), Mul(byte(b), 4), Mul(byte(b), 8)}
		if lanes != want {
			t.Fatalf("MulTable(%d) lanes=%v want %v", b, lanes, want)
		}
		if byte(tab&0xff) != Mul(byte(b), 1) {
			t.Fatalf("MulTable(%d) lane0 high nibble not clear", b)
		}
	}
}
