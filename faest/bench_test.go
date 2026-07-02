package faest

import (
	"crypto/rand"
	"testing"
)

var benchSets = []FaestParams{FAEST128s, FAEST128f, FAEST192s, FAEST192f, FAEST256s, FAEST256f}

func BenchmarkKeyGen(b *testing.B) {
	for _, p := range benchSets {
		b.Run(p.Name, func(b *testing.B) {
			for b.Loop() {
				if _, _, err := p.KeyGen(rand.Reader); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	msg := []byte("benchmark message")
	for _, p := range benchSets {
		sk, _, err := p.KeyGen(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		rho := make([]byte, p.OWF.LambdaBytes)
		b.Run(p.Name, func(b *testing.B) {
			for b.Loop() {
				p.Sign(msg, sk, rho)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	msg := []byte("benchmark message")
	for _, p := range benchSets {
		sk, pk, err := p.KeyGen(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		rho := make([]byte, p.OWF.LambdaBytes)
		sig := p.Sign(msg, sk, rho)
		b.Run(p.Name, func(b *testing.B) {
			for b.Loop() {
				if !p.Verify(msg, pk, sig) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}
