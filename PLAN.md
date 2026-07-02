# Tamayo — build plan & honesty ledger

Goal: **PoMFRIT One-More-MAYO blind signature — working, verified byte-exact
against the reference, and running on TamaGo.** If it can't be done faithfully,
that is an acceptable outcome — but every gap and failure is surfaced *here*,
never hidden, never dressed up.

## The one rule

No hand-rolled crypto. Every construct is transpiled from the stipulated source
in [`SOURCES.md`](./SOURCES.md). "Verified" means **byte-exact against the
reference** (the reference's output reproduced in Go, and/or interop both ways) —
**not** prover↔verifier self-consistency. Self-consistency proves my two halves
agree with each other; it does not prove they implement the paper.

## References

- **Paper:** `~/POMFRIT.pdf` — Baum, Beckmann, Beullens, Mukherjee, Rechberger,
  *Concretely Efficient Blind Signatures Based on VOLE-in-the-Head Proofs and the
  MAYO Trapdoor*.
- **Authoritative byte-level reference:** the `pq_blind_signatures` tree
  (C++ VOLEitH `vole/optimized_bs` + MAYO-C, glued in Rust `blind-signatures`).
  Built and running on the EC2 box (`3.66.84.166`).
- **Rust PoMFRIT:** `~/tee-stack/eat-pass/pomfrit` and
  `~/tee-stack/eat-pass/third_party/pq_blind_signatures`.
- **Source table:** [`SOURCES.md`](./SOURCES.md).

## Status

### Verified foundation — DONE (in this repo, checked against reference KATs)

| Package | External check | Result |
|---|---|---|
| `gf16`, `field` | property + `LargeFieldMul` vectors | pass |
| `mayo` | official **NIST KAT** | 100/100 (L1/L3/L5) |
| `faest` engine + AES OWF | **faest-rs reference KATs** | byte-exact (600 vectors run; reduced vendored) |
| all packages | real `GOOS=tamago` build, tamago-go1.26.4 | 4 arches OK |
| `faest` on device | ran on TamaGo (riscv64 sifive_u, QEMU) | `verify=true` |

These are faithful ports of **existing published schemes** (MAYO, FAEST) — not
the novel contribution.

### Hand-rolled items to REPLACE with faithful transpilations

Currently these live only in the `tamago/crypto` working tree (NOT in this repo);
they are what I wrote myself instead of transpiling. Each must be rebuilt from the
stipulated source and verified byte-exact before it enters this repo.

| Item | What I did wrong | Correct source | Status |
|---|---|---|---|
| deg-2 QuickSilver (`zk_prove_deg2.go`) | built by analogy to the deg-3 hasher; comment falsely says "transpiled" | `optimized_bs/quicksilver.hpp` (`quicksilver_state`, `max_deg=2`, `prove`/`verify`/`add_constraint`) | TODO |
| MAYO-OWF sign/verify, `WGrind`, deg-2 star offsets (`mayo_sign.go`) | derived the offsets and `WGrind = λ−Σkᵢ` myself | `optimized_bs/faest.inc` `vole_prove_1` / `vole_prove_2` / `vole_verify` | TODO |
| blind Fiat-Shamir `Sign1/2/3` (`mayo_blind.go`) | composed the transcript; no source citation; e.g. SHAKE128 vs SHAKE256 at L1 | `faest.inc` + `blind_sig_optimized/{sign,verify}.rs` | TODO |
| MAYO preimage vinegar (`mayo/vole.go` `SamplePreimage`) | invented `SHAKE256(sk‖t‖ctr)` | MAYO-C `mayo_sign_without_hashing` / `sample_preimage` | TODO |
| MAYO-eval circuit (`mayo_circuit.go`) | genuinely transpiled from `owf_proof.inc`, but rides on the above | re-verify vs `owf_proof.inc` + `quicksilver.hpp` | TODO (re-verify) |

### Crown jewel: One-More-MAYO blind signature — NOT DONE

- [ ] Faithful transpile of the full path (no invented FS, no derived constants, no fallbacks).
- [ ] **Verified byte-exact against the reference** — reference proof verifies in Go, Go proof verifies in the reference (or byte-identical proof for a fixed seed).
- [ ] Runs on TamaGo (QEMU sifive_u): blind sign → verify, correct result.

**Honest status:** none of the three boxes above are checked. Earlier I reported
this working — that was prover↔verifier self-consistency only, which is not
verification. This file is the single source of truth for what is actually proven.

## Verification method (the check that was skipped before)

1. On the box, run the reference (`test_voleopti_bs` / the Rust `blind-signatures`)
   on a **fixed** seed and dump inputs + the resulting proof bytes.
2. Run the faithful Go path on the same fixed input.
3. Compare **byte-for-byte**. Match ⇒ faithful. Then confirm interop both ways.
4. Any mismatch is a failure and is recorded here, not worked around.
