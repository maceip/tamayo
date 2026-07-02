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
| deg-2 QuickSilver (`zk_prove_deg2.go`) | built by analogy to the deg-3 hasher; comment falsely says "transpiled" | `optimized_bs/quicksilver.hpp` (`quicksilver_state`, `max_deg=2`, `prove`/`verify`/`add_constraint`) | **DONE** — `faest/quicksilver2.go`; byte-exact vs reference: **yes** (see below) |
| MAYO-OWF sign/verify, `WGrind`, deg-2 star offsets (`mayo_sign.go`) | derived the offsets and `WGrind = λ−Σkᵢ` myself | `optimized_bs/faest.inc` `vole_prove_1` / `vole_prove_2` / `vole_verify` | **DONE** — `faest/vole_mayo_sign.go` + `vole_mayo_verify.go`; byte-exact vs reference: **yes** (see below) |
| blind Fiat-Shamir `Sign1/2/3` (`mayo_blind.go`) | composed the transcript; no source citation; e.g. SHAKE128 vs SHAKE256 at L1 | `faest.inc` + `blind_sig_optimized/{sign,verify}.rs` | TODO |
| MAYO preimage vinegar (`mayo/vole.go` `SamplePreimage`) | invented `SHAKE256(sk‖t‖ctr)` | MAYO-C `mayo_sign_without_hashing` / `sample_preimage` | TODO |
| MAYO-eval circuit (`mayo_circuit.go`) | genuinely transpiled from `owf_proof.inc`, but rides on the above | re-verify vs `owf_proof.inc` + `quicksilver.hpp` | **DONE** — `faest/vole_mayo_circuit.go`; byte-exact vs reference: **yes** (see below) |

#### deg-2 QuickSilver — verification record (2026-07-01)

- Transpiled `faest/quicksilver2.go` from `optimized_bs/quicksilver.hpp`
  (sha256 `9a9f1907…`, byte-identical to the copy staged in `faest-cpp-tmp/`
  on the reference box): `quicksilver_state<S, {prover,verifier}, max_deg=2>`,
  `add_constraint`, `prove`, `verify`, `combine_mac_masks`, `get_witness_bit`,
  `combine_8_bits`/`combine_4_bits`, and the gf2/gfsecpar add/mul/lift rules.
- Reference vectors: `tools/qs2_dump.cpp` compiled on the box against the
  reference headers, driving the C++ `quicksilver_state` directly on fixed
  splitmix64 inputs. 15 cases (L1/L3/L5 x {GF(2^8) mul, GF(16) mul, deg-1 XOR,
  inverse `x*y+1`, public-scalar mul}) vendored in
  `faest/testdata/quicksilver2.json` with all inputs and outputs.
- `TestQuickSilver2KAT`: Go prover reproduces the reference `proof` and
  `check` bytes exactly; Go verifier consumes the **reference** proof bytes
  and reproduces the reference `check` exactly (interop direction). 15/15.
- `GOOS=tamago` build (tamago-go1.26.4): amd64/arm/arm64/riscv64 all OK.
- Honest coverage note: the prover gf2xgf2 bit-product path (`QSP2Bit.MulBit`)
  is transpiled but not exercised by the vectors — the equivalent C++
  expression is an ambiguous overload in the reference and is not used by
  `owf_proof.inc` (the MAYO circuit works via `load_witness_4_bits_and_combine`
  and gfsecpar ops). It will be covered or deleted when the MAYO circuit is
  re-verified.
- The old hand-rolled `zk_prove_deg2.go` (tamago working tree) is superseded;
  it lacked the MAC-mask handling (`combine_mac_masks`, witness mask bits) and
  the proof/check layout entirely.

#### MAYO-OWF VOLE prove/verify + MAYO circuit — verification record (2026-07-02)

Finding that reframed the task: the reference MAYO path rides on the **`optimized_bs`
C++ VOLE-in-the-Head engine**, which is a *different* engine from the faest-rs one
already in this repo (that one is verified against faest-rs KATs but uses a
one-tree BAVC and TAU=11 at L1; the MAYO reference uses `ggm_forest` and TAU=9).
So this was not a small transcript port — the whole `optimized_bs` engine had to be
transpiled and each layer checked byte-exact. Two of the three named "sins" also
turned out to be findings, not constants: the **deg-2 star offsets** are computed
inside `qs.prove` (`combine_mac_masks`, already verified in the QuickSilver row),
and **WGrind** does not exist on this path — v1 MAYO has `use_grinding == false`
(ggm_forest always opens, `zero_bits_in_delta == 0`, `grinding_counter_size == 0`),
so my old `WGrind = λ−Σkᵢ` and grind loop were simply wrong.

Engine transpiled bottom-up, each layer byte-exact against a box dumper compiled
against the stipulated `optimized_bs` sources (SHAKE via `common/fips202.c`,
`transpose_secpar` via a naive bit-transpose shim — both certified faithful by the
green byte-exact checks):

- `faest/vole_mayo_bavc.go` — `ggm_forest` BAVC commit + open (AES-CTR tree PRG,
  per-(level,tree) tweaks, SHAKE leaf hash, `hash_hashed_leaves`). `check` and
  `opening` byte-exact (`TestMayoForestCommitCheck`, `TestMayoForestOpen`).
- `faest/vole_mayo_svole.go` — `small_vole` (Gray-code `xor_reduce`,
  `vole_permute_key_index`) + `vole_commit`/`vole_reconstruct`; sender `u`, full
  `v`, and corrections byte-exact (`TestMayoVoleCommitSender`).
- `faest/vole_mayo_check.go` — `vole_check` (`gfsecpar`+`gf64` universal hash,
  2x2 map, column mask) + `transpose_secpar`; proof, absorbed transcript, and
  macs byte-exact (`TestMayoVoleCheckSender`).
- `faest/vole_mayo_circuit.go` — MAYO-eval `enc_constraints` on the deg-2
  QuickSilver; qs proof/check byte-exact for L1/L3/L5 (`TestMayoCircuitKAT`).
  A real bug was caught here by byte-exactness: at λ=192 the reference strides
  its embedding randomness by `sizeof(poly<192>)` = 32 bytes (two 128-bit lanes,
  top 64 bits unused), not 24.
- `faest/vole_mayo_sign.go` / `vole_mayo_verify.go` — the `faest.inc`
  `vole_prove_1`/`vole_prove_2`/`vole_verify` transcript (H₃/H₄, chal1=H₂¹,
  chal2=H₂², delta=H₂³, `r_additional` blinding, no grinding).

Verified both directions with `tools/full_proof_dump.cpp` (runs the reference
`vole_prove_1→2→verify` end-to-end): `TestMayoProveKAT` reproduces the **entire
proof byte-for-byte** for L1/L3/L5 (6895/15862/29615 bytes); `TestMayoVerifyKAT`
has the Go verifier accept the **reference** proof (interop) and reject a tampered
one. `GOOS=tamago` build (tamago-go1.26.4) green on amd64/arm/arm64/riscv64.

Honest scope note: this is the One-More-MAYO **VOLE proof** (rows 2 + 5). The
blind Fiat-Shamir `Sign1/2/3` wrapper (row 3, `blind_sig_optimized`) and the MAYO
preimage vinegar (row 4) sit on top and are still TODO, so the crown jewel below
is not yet complete.

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
