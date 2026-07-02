# tools — reference-vector dumpers

these are **not** part of the go module — they are the c/c++ programs that
compile against the stipulated reference sources and emit the known-answer
vectors the go tests replay byte-for-byte, so "verified" always means "matches
the reference", never self-consistency

each dumper is built out-of-tree against a checkout of the reference and run to
produce a json (or raw) vector file that is then vendored under the matching
package's `testdata/`

| dumper | reference source | emits | consumed by |
|---|---|---|---|
| `qs2_dump.cpp` | `optimized_bs/quicksilver.hpp` (max_deg=2) | `pomfrit/testdata/quicksilver2.json` | `TestQuickSilver2KAT` |
| `vole_commit_dump.cpp` | `optimized_bs` vole_commit + vole_check + transpose | `pomfrit/testdata/vole_commit.json` | `TestMayoForestCommitCheck`, `TestMayoVoleCommitSender`, `TestMayoVoleCheckSender` |
| `bavc_open_dump.cpp` | `optimized_bs` ggm_forest_bavc::open | `pomfrit/testdata/bavc_open.json` | `TestMayoForestOpen` |
| `mayo_circuit_dump.cpp` | `optimized_bs/owf_proof.inc` enc_constraints | `pomfrit/testdata/mayo_circuit.json` | `TestMayoCircuitKAT` |
| `full_proof_dump.cpp` | `optimized_bs/faest.inc` vole_prove_1/2/verify | `pomfrit/testdata/full_proof.json` | `TestMayoProveKAT`, `TestMayoVerifyKAT` |
| `mayo_preimage_dump.c` | mayo-c `mayo_sign_without_hashing` | `mayo/testdata/mayo_preimage.json` | `TestSignWithoutHashingKAT` |
| `blind_loop_dump.cpp` (+ `mayo_bridge.c`) | `blind_sig_optimized` sign_1..3 + verify (vole engine + mayo-c) | `pomfrit/testdata/blind_loop.json` | `TestBlindLoopKAT` + `cmd/qemudemo` |
| `faest_kat_gen/` (rust) | faest-rs 0.3.0 + the nist aes-256 ctr-drbg harness | `faest/testdata/PQCsignKAT_faest_*.rsp.gz` (full 100-vector sets) | `TestFaestNISTKAT` |

`faest_kat_gen` replicates the nist `PQCgenKAT_sign` flow (entropy input
`00..2f`, per-vector reseed, `mlen = 33*(count+1)`) on top of the faest-rs
reference; vector 0 of every generated set was diffed byte-identical against
the reference-shipped `reduced_PQCsignKAT_faest_*.rsp` before vendoring
(`cd faest_kat_gen && cargo run --release`, output lands in `out/`)

## shims

the vole dumpers include the reference headers but replace two of them so they
build with plain g++ (no meson / xkcp subproject), each certified faithful by
the green byte-exact test:

- `ref_hash_shim.hpp` / `ref_hash_shim_oneshot.hpp` — back the reference
  `hash_state` with fips-202 shake (from `common/fips202.c` or mayo-c), which is
  bit-identical to xkcp and go `crypto/sha3`
- `ref_transpose_shim.hpp` — a naive gf(2) bit transpose in place of the avx2
  `transpose_secpar` template (same permutation, avoids an ooming template
  instantiation)

## building (example)

on an x86-64 host with the reference tree, e.g. `~/pq_blind_signatures/vole`:

```
g++ -O2 -std=c++23 -march=native \
  -I ~/pq_blind_signatures/vole/faest-cpp-tmp -I ~/pq_blind_signatures/vole/common \
  qs2_dump.cpp \
  ~/pq_blind_signatures/vole/faest-cpp-tmp/avx2/aes_impl.cpp \
  ~/pq_blind_signatures/vole/faest-cpp-tmp/polynomials_constants.cpp \
  fips202.o -o qs2_dump
./qs2_dump > ../pomfrit/testdata/quicksilver2.json
```

the exact per-dumper include and link lines are the ones recorded in the
commit history; the blind-loop dumper additionally links mayo-c
(`params.c arithmetic.c mayo_without_hashing.c common/*.c`) via `mayo_bridge.c`
