# PoMFRIT on TamaGo — construct sourcing & build order

Goal: pure Go, **no cgo**, builds for `GOOS=tamago` on amd64/arm/arm64/riscv64.
Every PQ construct is gated on canonical KATs (MAYO round2, official FAEST), so a
porting source's maturity never affects correctness.

`How` column: **DROP-IN** = pure-Go dependency used as-is (Go stdlib only) ·
**RUST→GO** = port idiomatic Rust · **C→GO** = port the paper's C/C++ (no Go/Rust
exists) · **WRITE** = write from spec (small).

| Order | Construct | How | Source → Go | Validated by | Caveat / status |
|-------|-----------|-----|-------------|--------------|-----------------|
| L0.1 | SHAKE256 / SHA3 / Keccak-f[1600] | DROP-IN | stdlib `crypto/sha3` | tamago build + source-diff vs host | DONE — verified on tamago |
| L0.2 | AES-128 block + CTR (GGM PRG) | DROP-IN | stdlib `crypto/aes`+`crypto/cipher` | tamago build | DONE — verified; AES-NI needs only SSE (already enabled) |
| L0.3 | CSPRNG / randombytes | DROP-IN | stdlib `crypto/rand` | — | tamago wires `internal/rng` |
| L0.4 | bit/limb ops | DROP-IN | stdlib `math/bits` | — | — |
| L0.5 | CTR-DRBG (deterministic KAT replay) | WRITE | ~80 LOC over stdlib AES | NIST DRBG vectors | only needed to reproduce KATs |
| L1.6 | GF(16) = GF(2^4) | WRITE (ref pq-mayo / MAYO-C) | `crypto/gf16` | exhaustive + MAYO-C inverse table | DONE — built & green (3 arches) |
| L1.7 | GF(2^128/192/256) + poly over F_2^λ | RUST→GO | `ait-crypto/faest-rs` (fields) | FAEST KAT | CLMUL asm is a later optional fast path |
| L1.8 | GF(2^512) + F_2^128^4 deg-3 poly (RainHash) | C→GO | `.shape` rainhash_plain + paper §7 | `.shape` C++ KATs + tamago build | DONE — pure Go RainHash512, field ops, and S-box witness helper |
| L2.9 | GF(16) vec/mat ops + constant-time echelon solver | RUST→GO | pq-mayo `matrix_ops.rs`, `echelon.rs` | MAYO-C cross-check | IN PROGRESS (matrix ops first, solver next) |
| L2.10 | MAYO TrapGen / Eval / SPre | RUST→GO | pq-mayo (`keygen`/`sign`/`verify`/`sample`/`codec`/`params`/`bitsliced`) | MAYO round2 KAT (`pq-mayo/tests/KAT` ≡ `MAYO-C/KAT`) | pq-mayo unaudited → MAYO-C `generic` is the canonical cross-check |
| L3.11 | Fixed-key/CTR AES PRG for GGM | DROP-IN + wrap | stdlib `crypto/aes` | — | — |
| L3.12 | GGM tree / all-but-one vector commitment | RUST→GO | `ait-crypto/faest-rs` | FAEST KAT | refs: libtalos (C), `.shape` |
| L3.13 | small-VOLE + ConvertToVOLE + correction | RUST→GO | `ait-crypto/faest-rs` | FAEST KAT | — |
| L3.14 | VOLE consistency check + universal hash | RUST→GO | `ait-crypto/faest-rs` | FAEST KAT | — |
| L3.15 | QuickSilver (deg-2 → deg-16) over F_2^λ | RUST→GO | `ait-crypto/faest-rs` | FAEST KAT | QS-relation cross-refs are *interactive* (diet-mac-and-cheese Rust; JesseQ/emp-zk C++) — reference only |
| L3.16 | Fiat-Shamir transform + transcript | DROP-IN + write | stdlib `crypto/sha3`; structure from faest-rs | — | — |
| L3.17 | Circuit/gate layer (Add/cmul/drmul/Lift/Assert, ⟦·⟧) | RUST→GO | faest-rs + paper §4 / App. D | FAEST KAT | — |
| L4.18 | FAEST keygen/sign/verify (AES OWF) | RUST→GO | `ait-crypto/faest-rs` | official FAEST KAT | engine-validation milestone before custom circuits |
| L5.19 | MAYO-eval circuit T*(s)=t (+ random-lin-combo opt) | C→GO | `.shape/vole/optimized_bs/owf_proof.inc` | end-to-end verify | only source is `.shape` C++ |
| L5.20 | Keccak-deg16 circuit | C→GO | `.shape/vole/conservative_bs/owf_proof.inc` | end-to-end verify | only source is `.shape` C++ |
| L5.21 | RainHash circuit + RainHash512 | C→GO | `.shape/.../rainhash_plain` (+ IAIK/rainier) | end-to-end verify | DONE as isolated RainHash component — hash, witness layouts, relation checker, circuit primitives, L1 proof-chain parameter guard, and proof-chain QuickSilver wiring green; final PoMFRIT integration waits on MAYO circuit |
| L6.22 | PoMFRIT Sig1/2/3/Ver + commitment + 2-stage π1/π2 (Alg.1 + Alg.2) | RUST→GO | `.shape/blind-signatures*` (Rust) | paper test cases | One-More-MAYO (Alg.2) is the first end-to-end target |

Decisions accounted for:
- No construct relies on cgo or AVX2 (cgo disabled on tamago; AVX2 not enabled by tamago today).
- Vetoed: `cloudflare/circl` MAYO (PR #483) — stale/unmerged, wrong (nibbling) variant.
- Unusable as a dependency (cgo/FFI), reference-only: `clabby/sriracha-mayo`, `liboqs-go`, `libtalos_voleith`, the `.shape` FFI crates.
