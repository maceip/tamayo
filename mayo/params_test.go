package mayo

import "testing"

// ceilDiv2 returns ceil(x/2), the nibble-packed byte length of x GF(16) elements.
func ceilDiv2(x int) int { return (x + 1) / 2 }

// TestParamsDerivations re-derives every byte size from (n, m, o, k) and checks
// it against the constants, and checks the canonical sig/pk/sk sizes from the
// MAYO round 2 specification. If any constant is mistyped, this fails.
func TestParamsDerivations(t *testing.T) {
	for _, p := range []Params{Mayo1, Mayo2, Mayo3, Mayo5} {
		v := p.N - p.O
		if got := p.V(); got != v {
			t.Fatalf("%s: V()=%d want %d", p.Name, got, v)
		}
		if got, want := p.ACols(), p.K*p.O+1; got != want {
			t.Fatalf("%s: ACols()=%d want %d", p.Name, got, want)
		}
		if got, want := p.MBytes, ceilDiv2(p.M); got != want {
			t.Fatalf("%s: MBytes=%d want ceil(m/2)=%d", p.Name, got, want)
		}
		if got, want := p.VBytes, ceilDiv2(v); got != want {
			t.Fatalf("%s: VBytes=%d want ceil(v/2)=%d", p.Name, got, want)
		}
		if got, want := p.RBytes, ceilDiv2(p.K*p.O); got != want {
			t.Fatalf("%s: RBytes=%d want ceil(k*o/2)=%d", p.Name, got, want)
		}
		if got, want := p.OBytes, ceilDiv2(v*p.O); got != want {
			t.Fatalf("%s: OBytes=%d want ceil(v*o/2)=%d", p.Name, got, want)
		}
		if got, want := p.P1Bytes, v*(v+1)/2*p.M/2; got != want {
			t.Fatalf("%s: P1Bytes=%d want %d", p.Name, got, want)
		}
		if got, want := p.P2Bytes, v*p.O*p.M/2; got != want {
			t.Fatalf("%s: P2Bytes=%d want %d", p.Name, got, want)
		}
		if got, want := p.P3Bytes, p.O*(p.O+1)/2*p.M/2; got != want {
			t.Fatalf("%s: P3Bytes=%d want %d", p.Name, got, want)
		}
		if got, want := p.CPKBytes, p.P3Bytes+p.PKSeedBytes; got != want {
			t.Fatalf("%s: CPKBytes=%d want P3Bytes+PKSeed=%d", p.Name, got, want)
		}
		if got, want := p.SigBytes, ceilDiv2(p.N*p.K)+p.SaltBytes; got != want {
			t.Fatalf("%s: SigBytes=%d want ceil(n*k/2)+salt=%d", p.Name, got, want)
		}
		if got, want := p.CSKBytes, p.SKSeedBytes; got != want {
			t.Fatalf("%s: CSKBytes=%d want SKSeedBytes=%d", p.Name, got, want)
		}
	}
}

// TestParamsCanonicalSizes pins the published MAYO round 2 sizes.
func TestParamsCanonicalSizes(t *testing.T) {
	cases := []struct {
		p           Params
		sig, pk, sk int
	}{
		{Mayo1, 454, 1420, 24},
		{Mayo2, 216, 4368, 24},
		{Mayo3, 681, 2986, 32},
		{Mayo5, 964, 5554, 40},
	}
	for _, c := range cases {
		if c.p.SigBytes != c.sig || c.p.CPKBytes != c.pk || c.p.CSKBytes != c.sk {
			t.Fatalf("%s: got (sig=%d pk=%d sk=%d) want (%d %d %d)",
				c.p.Name, c.p.SigBytes, c.p.CPKBytes, c.p.CSKBytes, c.sig, c.pk, c.sk)
		}
	}
}
