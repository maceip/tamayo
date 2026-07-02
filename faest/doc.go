// Package faest implements the VOLE-in-the-Head (VOLEitH) zero-knowledge proof
// system and the FAEST post-quantum signature over an AES/Rijndael one-way
// function: a pure-Go, cgo-free port targeting the TamaGo bare-metal runtime.
//
// It is transpiled from the FAEST reference (faest.info, ait-crypto/faest-rs)
// and validated byte-for-byte against that reference's NIST known-answer tests.
// See the repository README for provenance and status.
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
