package faest_test

import (
	"crypto/rand"
	"fmt"

	"github.com/maceip/tamayo/faest"
)

// Sign a message with FAEST-128s and verify it. rho is the signer's
// per-signature randomness (LambdaBytes); a fixed rho makes signing
// deterministic, as in the NIST KAT flow.
func Example() {
	sk, pk, err := faest.FAEST128s.KeyGen(rand.Reader)
	if err != nil {
		panic(err)
	}

	msg := []byte("This is a message.")
	rho := make([]byte, faest.FAEST128s.OWF.LambdaBytes)
	sig := faest.FAEST128s.Sign(msg, sk, rho)

	fmt.Println("signature valid:", faest.FAEST128s.Verify(msg, pk, sig))
	fmt.Println("tampered rejected:", !faest.FAEST128s.Verify([]byte("Another message."), pk, sig))
	// Output:
	// signature valid: true
	// tampered rejected: true
}
