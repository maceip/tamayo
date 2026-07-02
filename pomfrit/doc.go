// Package pomfrit implements the PoMFRIT One-More-MAYO blind signature (Baum,
// Beckmann, Beullens, Mukherjee, Rechberger — "Concretely Efficient Blind
// Signatures Based on VOLE-in-the-Head Proofs and the MAYO Trapdoor") in pure,
// cgo-free Go targeting the TamaGo bare-metal runtime.
//
// It is a faithful transpile of the pq_blind_signatures reference: the
// vole/optimized_bs C++ VOLE-in-the-Head engine (GGM-forest BAVC, small-VOLE,
// vole_check universal hashing, degree-2 QuickSilver, the MAYO-eval circuit,
// and the vole_prove/vole_verify Fiat-Shamir flow) glued to MAYO-C's salt-free
// preimage sampler (mayo.SignWithoutHashing in the sibling mayo package).
// Every layer is validated byte-for-byte against dumpers compiled from those
// reference sources; the AES-CTR PRG and the ZK Horner hash are reused from
// the sibling faest package.
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
//	MayoOWFL1, MayoOWFL3, MayoOWFL5  // MayoOWF, the three v1 MAYO instances
//	(MayoOWF).Sign1                  // user: blind the message, t = h + r
//	mayo.SignWithoutHashing          // signer: MAYO preimage of t (sign_2)
//	(MayoOWF).Sign3                  // user: VOLE-in-the-Head proof
//	(MayoOWF).BlindVerify            // verifier: recompute h, run vole_verify
//	(MayoOWF).Prove / Verify         // the underlying VOLE proof pair
package pomfrit
