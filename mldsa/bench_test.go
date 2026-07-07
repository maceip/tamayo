package mldsa

import "testing"

func benchParams(b *testing.B, p *Params) {
	seed := make([]byte, 32)
	rnd := make([]byte, 32)
	pk, sk, err := p.KeyGen(seed)
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte("benchmark message")
	sig, err := p.Sign(sk, msg, nil, rnd)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("KeyGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.KeyGen(seed)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Sign(sk, msg, nil, rnd)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Verify(pk, msg, sig, nil)
		}
	})
}

func BenchmarkMLDSA44(b *testing.B) { benchParams(b, MLDSA44) }
func BenchmarkMLDSA65(b *testing.B) { benchParams(b, MLDSA65) }
func BenchmarkMLDSA87(b *testing.B) { benchParams(b, MLDSA87) }
