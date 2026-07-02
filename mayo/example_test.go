package mayo_test

import (
	"fmt"

	"github.com/maceip/tamayo/mayo"
)

// Sign a message with MAYO-1 and verify it. Key generation and signing are
// deterministic in the seed and randomizer, mirroring the reference flow
// where the NIST DRBG supplies both.
func Example() {
	seed := make([]byte, mayo.Mayo1.SKSeedBytes)
	randomizer := make([]byte, mayo.Mayo1.SaltBytes)

	cpk, csk, err := mayo.Mayo1.CompactKeyGen(seed)
	if err != nil {
		panic(err)
	}

	msg := []byte("This is a message.")
	sig, err := mayo.Mayo1.Sign(msg, csk, randomizer)
	if err != nil {
		panic(err)
	}

	fmt.Println("signature valid:", mayo.Mayo1.Verify(msg, sig, cpk))
	fmt.Println("tampered rejected:", !mayo.Mayo1.Verify([]byte("Another message."), sig, cpk))
	// Output:
	// signature valid: true
	// tampered rejected: true
}
