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
// # Public entry points
//
//	FAEST128s, FAEST128f, FAEST192s, FAEST192f, FAEST256s, FAEST256f  // FaestParams
//	(FaestParams).KeyGen           // sample a valid secret key + public key
//	(FaestParams).Sign             // sign a message
//	(FaestParams).Verify           // verify a signature
//	(FaestParams).PublicKeyFromSecret
package faest
