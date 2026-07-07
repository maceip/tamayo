package mldsa_test

import (
	"fmt"

	"github.com/maceip/tamayo/mldsa"
)

// Example signs and verifies with ML-DSA-44. The seed and rnd are fixed for
// reproducibility; in production both must be fresh CSPRNG output (all-zero
// rnd selects the deterministic signing variant).
func Example() {
	p := mldsa.MLDSA44

	seed := make([]byte, 32)
	pk, sk, err := p.KeyGen(seed)
	if err != nil {
		panic(err)
	}

	msg := []byte("tamayo")
	rnd := make([]byte, 32)
	sig, err := p.Sign(sk, msg, nil, rnd)
	if err != nil {
		panic(err)
	}

	fmt.Println("verify:", p.Verify(pk, msg, sig, nil))
	fmt.Println("tampered:", p.Verify(pk, []byte("tamayp"), sig, nil))
	// Output:
	// verify: true
	// tampered: false
}
