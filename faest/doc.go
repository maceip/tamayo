// Package faest implements the VOLE-in-the-Head (VOLEitH) zero-knowledge proof
// system and, on top of it, two signatures: the FAEST post-quantum signature
// over an AES/Rijndael one-way function, and the PoMFRIT One-More-MAYO blind
// signature. It is a pure-Go, cgo-free port targeting the TamaGo bare-metal
// runtime.
//
// Two distinct reference engines live here, sharing the VOLEitH primitives
// (PRG, GGM/BAVC vector commitments, universal hashing, QuickSilver):
//
//   - The FAEST AES signature, transpiled from the FAEST reference
//     (faest.info, ait-crypto/faest-rs) and validated byte-for-byte against
//     that reference's NIST known-answer tests. Its files carry no prefix
//     (bavc.go, vole.go, zk_prove.go, faest_sign.go, ...).
//   - The One-More-MAYO VOLE proof and blind signature, transpiled from the
//     pq_blind_signatures optimized_bs C++ engine + MAYO-C and validated
//     byte-for-byte against dumpers compiled from those sources. Its files use
//     the vole_mayo_ prefix (plus quicksilver2.go, the degree-2 QuickSilver).
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
//
//	MayoOWFL1, MayoOWFL3, MayoOWFL5  // MayoOWF, the One-More-MAYO instances
//	(MayoOWF).Sign1 / Sign3 / BlindVerify   // blind signature (with mayo.SignWithoutHashing as sign_2)
//	(MayoOWF).Prove / Verify                // the underlying VOLE proof
package faest
