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
// # Even-Mansour sets
//
// All twelve parameter sets are implemented: the six standard AES sets and
// the six Even-Mansour (EM) sets (FAESTEM128s/f, 192s/f, 256s/f), verified
// byte-exact against the FAEST NIST KAT (100 vectors each). The EM one-way
// function is y = Rijndael_pk(x) XOR x with public round keys and the secret
// input x committed; relative to AES it skips the key-expansion constraints,
// derives its round keys from the public Rijndael schedule, and uses a
// 2*lambda PRG leaf commitment (NLeafCommit=2) instead of the 3*lambda
// universal-hash one. Rijndael-192/256 (NSt=6/8) is exercised by the wider
// EM states.
//
// # Public entry points
//
//	FAEST128s, FAEST128f, FAEST192s, FAEST192f, FAEST256s, FAEST256f  // AES FaestParams
//	FAESTEM128s, FAESTEM128f, FAESTEM192s, FAESTEM192f, FAESTEM256s, FAESTEM256f  // EM FaestParams
//	(FaestParams).KeyGen           // sample a valid secret key + public key
//	(FaestParams).Sign             // sign a message
//	(FaestParams).Verify           // verify a signature
//	(FaestParams).PublicKeyFromSecret
package faest
