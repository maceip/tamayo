package pomfrit_test

import (
	"fmt"

	"github.com/maceip/tamayo/mayo"
	"github.com/maceip/tamayo/pomfrit"
)

// The full One-More-MAYO blind signature at L1, playing all three roles:
// the user blinds the message (sign_1), the signer computes a MAYO preimage
// of the blinded message (sign_2), the user turns it into a
// VOLE-in-the-Head proof (sign_3), and the verifier checks the proof
// without ever seeing the signer's key or the blinding.
func Example() {
	o := pomfrit.MayoOWFL1
	mp := &mayo.Mayo1

	// Signer key material: compact keypair; verifiers use the expanded key.
	seed := make([]byte, mp.SKSeedBytes)
	cpk, csk, err := mp.CompactKeyGen(seed)
	if err != nil {
		panic(err)
	}
	epk, err := mp.ExpandPK(cpk)
	if err != nil {
		panic(err)
	}

	msg := []byte("This is a message.")
	rAdditional := make([]byte, 32) // session randomness bound into Fiat-Shamir

	// sign_1 (user): blind the message, t = h + r.
	t, st, h := o.Sign1(msg, rAdditional)

	// sign_2 (signer): MAYO preimage of the blinded message.
	bsig := mp.SignWithoutHashing(t, csk)

	// sign_3 (user): prove knowledge of a valid preimage without revealing it.
	proof := o.Sign3(epk, h, bsig, st, rAdditional)

	// verify: recompute h and run vole_verify.
	fmt.Println("blind signature valid:", o.BlindVerify(epk, msg, proof.Bytes, rAdditional))

	tampered := append([]byte(nil), proof.Bytes...)
	tampered[0] ^= 1
	fmt.Println("tampered rejected:", !o.BlindVerify(epk, msg, tampered, rAdditional))
	// Output:
	// blind signature valid: true
	// tampered rejected: true
}
