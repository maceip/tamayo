// Package faest implements the FAEST post-quantum signature over an
// AES/Rijndael one-way function, together with the VOLE-in-the-Head (VOLEitH)
// primitives it is built from (PRG, GGM/BAVC vector commitments, small-VOLE,
// universal hashing, QuickSilver). It is a pure-Go, cgo-free port targeting
// the TamaGo bare-metal runtime.
//
// Everything here is transpiled from the FAEST reference (faest.info,
// ait-crypto/faest-rs) and validated byte-for-byte against that reference's
// full NIST known-answer tests (100 vectors per parameter set, all six sets).
//
// The PoMFRIT One-More-MAYO blind signature — a different VOLEitH engine
// transpiled from the pq_blind_signatures optimized_bs C++ sources — lives in
// the sibling package pomfrit, which reuses this package's PRG and ZKHasher.
//
// See SOURCES.md and PLAN.md for per-construct provenance and the verification
// ledger.
//
// # Status
//
// Experimental and unaudited. Correctness rests on reference KATs, not a
// security review.
//
// # Even-Mansour boundary
//
// The six exported parameter sets are the standard AES ones; the six
// Even-Mansour (EM) sets are not implemented end to end. The EM building
// blocks that do exist — the Rijndael-192/256 cipher (rijndael.go), the EM
// witness extension (witness.go), and the OWF128EM/OWF192EM/OWF256EM
// parameters — are each transpiled from faest-rs and byte-exact against its
// vectors (rijndael_data.json, AesExtendedWitness.json), but the EM
// prove/verify constraint path was never ported, so no EM set is exported
// and no EM signature can be produced or checked (the constraint entry
// points panic on an EM OWF rather than silently computing the AES
// constraints). End-to-end EM sign vectors are already vendored in
// FaestProve.json (skipped by TestFaestSignKAT); completing FAEST-EM means
// porting the EM constraints from faest-rs, defining the six EM FaestParams
// sets, and regenerating the EM NIST KAT sets with tools/faest_kat_gen.
//
// # Public entry points
//
//	FAEST128s, FAEST128f, FAEST192s, FAEST192f, FAEST256s, FAEST256f  // FaestParams
//	(FaestParams).KeyGen           // sample a valid secret key + public key
//	(FaestParams).Sign             // sign a message
//	(FaestParams).Verify           // verify a signature
//	(FaestParams).PublicKeyFromSecret
package faest
