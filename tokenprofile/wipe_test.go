package tokenprofile

import (
	"bytes"
	"testing"

	"github.com/maceip/tamayo/mayo"
)

func TestWipe(t *testing.T) {
	b := bytes.Repeat([]byte{0xAB}, 64)
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %#x, want 0", i, v)
		}
	}
	Wipe(nil) // must not panic
}

func TestIssuerZeroize(t *testing.T) {
	issuer, err := NewIssuer(1, make([]byte, mayo.Mayo1.SKSeedBytes))
	if err != nil {
		t.Fatal(err)
	}
	issuer.Zeroize()
	allZero := true
	for _, v := range issuer.csk {
		if v != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Fatal("csk not wiped after Zeroize")
	}
}
