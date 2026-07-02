package pomfrit

import (
	"testing"

	"github.com/maceip/tamayo/mayo"
)

type benchLevel struct {
	name string
	owf  MayoOWF
	mp   *mayo.Params
}

func benchLevels() []benchLevel {
	return []benchLevel{
		{"L1", MayoOWFL1, &mayo.Mayo1},
		{"L3", MayoOWFL3, &mayo.Mayo3},
		{"L5", MayoOWFL5, &mayo.Mayo5},
	}
}

func benchSetup(b *testing.B, l benchLevel) (epk, csk []byte) {
	b.Helper()
	seed := make([]byte, l.mp.SKSeedBytes)
	cpk, csk, err := l.mp.CompactKeyGen(seed)
	if err != nil {
		b.Fatal(err)
	}
	epk, err = l.mp.ExpandPK(cpk)
	if err != nil {
		b.Fatal(err)
	}
	return epk, csk
}

// BenchmarkBlindSign measures the full user+signer path:
// sign_1 (blind) + sign_2 (MAYO preimage) + sign_3 (VOLEitH proof).
func BenchmarkBlindSign(b *testing.B) {
	msg := []byte("benchmark message")
	rAdd := make([]byte, 32)
	for _, l := range benchLevels() {
		epk, csk := benchSetup(b, l)
		b.Run(l.name, func(b *testing.B) {
			for b.Loop() {
				t, st, h := l.owf.Sign1(msg, rAdd)
				bsig := l.mp.SignWithoutHashing(t, csk)
				l.owf.Sign3(epk, h, bsig, st, rAdd)
			}
		})
	}
}

func BenchmarkBlindVerify(b *testing.B) {
	msg := []byte("benchmark message")
	rAdd := make([]byte, 32)
	for _, l := range benchLevels() {
		epk, csk := benchSetup(b, l)
		t, st, h := l.owf.Sign1(msg, rAdd)
		bsig := l.mp.SignWithoutHashing(t, csk)
		proof := l.owf.Sign3(epk, h, bsig, st, rAdd)
		b.Run(l.name, func(b *testing.B) {
			for b.Loop() {
				if !l.owf.BlindVerify(epk, msg, proof.Bytes, rAdd) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}
