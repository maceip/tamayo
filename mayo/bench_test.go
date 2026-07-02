package mayo

import "testing"

func benchParams(b *testing.B) []*Params {
	b.Helper()
	return []*Params{&Mayo1, &Mayo3, &Mayo5}
}

func BenchmarkKeyGen(b *testing.B) {
	for _, p := range benchParams(b) {
		seed := make([]byte, p.SKSeedBytes)
		b.Run(p.Name, func(b *testing.B) {
			for b.Loop() {
				if _, _, err := p.CompactKeyGen(seed); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	msg := []byte("benchmark message")
	for _, p := range benchParams(b) {
		seed := make([]byte, p.SKSeedBytes)
		_, csk, _ := p.CompactKeyGen(seed)
		randomizer := make([]byte, p.SaltBytes)
		b.Run(p.Name, func(b *testing.B) {
			for b.Loop() {
				if _, err := p.Sign(msg, csk, randomizer); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	msg := []byte("benchmark message")
	for _, p := range benchParams(b) {
		seed := make([]byte, p.SKSeedBytes)
		cpk, csk, _ := p.CompactKeyGen(seed)
		randomizer := make([]byte, p.SaltBytes)
		sig, _ := p.Sign(msg, csk, randomizer)
		b.Run(p.Name, func(b *testing.B) {
			for b.Loop() {
				if !p.Verify(msg, sig, cpk) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}
