# tamayo

pure-go, cgo-free implementations of the **mayo** post-quantum signature, the
**faest** / vole-in-the-head proof system, and the **pomfrit one-more-mayo**
blind signature, targeting the [tamago](https://github.com/usbarmory/tamago)
bare-metal go runtime

the name is tamago + mayo (tamago means "egg"; mayonnaise is made from eggs)

> **warning** — experimental, not audited, not production-ready
>
> this is a from-scratch transpilation of published references with no
> independent security or side-channel review, so do not use it to protect
> anything — "verified" here means the output matches the stipulated reference
> byte-for-byte, nothing more

## what's here

| package | what it is | verified against |
|---|---|---|
| `gf16` | gf(16) arithmetic | exhaustive / property tests |
| `field` | gf(2^128/192/256) and their degree-3 extensions | `LargeFieldMul` reference vectors |
| `mayo` | mayo keygen / sign / verify, plus the salt-free preimage sampler (`SignWithoutHashing`) | mayo nist round-2 kat 100/100 (l1/l3/l5); preimage byte-exact vs mayo-c |
| `faest` | the faest aes signature and its vole-in-the-head engine (prg, ggm/bavc vector commitments, small-vole, universal hashing, quicksilver) | full faest nist kat 600/600 byte-exact (100 vectors x 6 sets) |
| `pomfrit` | the one-more-mayo blind signature and its own vole engine (ggm-forest bavc, small-vole, deg-2 quicksilver, mayo-eval circuit, fiat-shamir), reusing the faest prg and zk hash | byte-exact vs the c++/c reference both directions at l1/l3/l5 |
| `cmd/qemudemo` | the one-more-mayo blind loop running bare-metal on qemu sifive_u (riscv64) at l1, l3 and l5 | on-device byte-exact, see below |

no cryptographic primitive is hand-written — every construct is a transpilation
of a named source listed in [`SOURCES.md`](./SOURCES.md), and sha-3/shake is
go's `crypto/sha3` while aes is `crypto/aes`

## one-more-mayo blind signature

the crown jewel is the pomfrit one-more-mayo blind signature (baum, beckmann,
beullens, mukherjee, rechberger — *concretely efficient blind signatures based
on vole-in-the-head proofs and the mayo trapdoor*), built from a faithful
transpile of the `optimized_bs` c++ vole engine plus mayo-c, with every layer
checked byte-for-byte against a dumper compiled from the reference sources:

- `sign_1` blinds the message as `t = h + r` with `h = shake256(m || proof1)`
- `sign_2` is the mayo preimage of `t` (`mayo.SignWithoutHashing`)
- `sign_3` is the vole-in-the-head proof (`vole_prove_1` / `vole_prove_2`)
- `verify` recomputes `h` and runs `vole_verify`

`pomfrit.MayoOWFL1` / `MayoOWFL3` / `MayoOWFL5` reproduce the reference blinded
message, preimage and full proof byte-for-byte at all three levels, and the
go verifier accepts the reference proof (interop) and rejects tampering — the
verification ledger is [`PLAN.md`](./PLAN.md)

## on device

`cmd/qemudemo` boots on `qemu-system-riscv64 -machine sifive_u`, runs the
blind loop at all three security levels against embedded reference vectors,
and prints on the uart console

```
=== One-More-MAYO blind signature on TamaGo (sifive_u/riscv64), L1+L3+L5 ===
--- L1 (mayo_128_s) ---
[sign_1] blinding message ... t byte-exact vs reference: true
[sign_2] MAYO preimage ... bsig byte-exact vs reference: true
[sign_3] VOLE-in-the-Head proof ... proof byte-exact vs reference (6895 bytes): true
[verify] on-device blind verify (Go proof) ... verify=true
[verify] on-device blind verify (reference proof) ... verify=true
[verify] tampered proof rejected ... rejected=true
L1 (mayo_128_s): PASS
--- L3 (mayo_192_s) ---   ... PASS (proof 15862 bytes)
--- L5 (mayo_256_s) ---   ... PASS (proof 29615 bytes)
RESULT: PASS — One-More-MAYO blind sign+verify byte-exact on device (L1+L3+L5)
```

```
cd cmd/qemudemo && make qemu   # needs the tamago-go toolchain, qemu-system-riscv64, dtc, python3
```

the whole tree also cross-builds under `GOOS=tamago` with `tamago-go` for
amd64/arm/arm64/riscv64

## usage

each signature package ships a runnable `Example` in its `example_test.go`
(run by `go test`, rendered on pkg.go.dev) — the short version:

```go
// mayo (mp := &mayo.Mayo1)
cpk, csk, _ := mp.CompactKeyGen(seed)       // deterministic in the seed
sig, _ := mp.Sign(msg, csk, randomizer)     // randomizer supplies the salt
ok := mp.Verify(msg, sig, cpk)

// faest aes signature
sk, pk, _ := faest.FAEST128s.KeyGen(rand.Reader)
sig := faest.FAEST128s.Sign(msg, sk, rho)   // rho: per-signature randomness
ok := faest.FAEST128s.Verify(msg, pk, sig)

// one-more-mayo blind signature (o := pomfrit.MayoOWFL1)
epk, _ := mp.ExpandPK(cpk)                  // verifier-side expanded key
t, st, h := o.Sign1(msg, rAdditional)       // user: blind the message
bsig := mp.SignWithoutHashing(t, csk)       // signer: mayo preimage
proof := o.Sign3(epk, h, bsig, st, rAdditional)
ok = o.BlindVerify(epk, msg, proof.Bytes, rAdditional)
```

## test

```
go test ./...          # full byte-exact surface (600 faest + 300 mayo nist vectors, all reference replays)
go test -short ./...   # same tests, trimmed kat counts — what ci runs per push
```

runs the mayo nist kats, the full 600-vector faest nist kat replay (vendored
gzipped under `faest/testdata/`, regenerated from the faest-rs reference by
`tools/faest_kat_gen` and spot-checked byte-identical against the
reference-shipped vectors), the mayo preimage kat, and the one-more-mayo
byte-exact loop (prover, verifier, and full blind path at l1/l3/l5) — use
`go test -short` to run 5 vectors per faest set instead of 100

reference vectors were produced by the c++/c dumpers in `tools/`, compiled
against the stipulated sources and run to emit inputs and outputs that the go
tests replay byte-for-byte

ci runs build + vet + the `-short` suite on linux (amd64 + arm64) and macos,
cross-builds every package for all four `GOOS=tamago` architectures, and
replays the full kat suite on a weekly schedule

## benchmark

```
go test -bench . -run xxx ./mayo/ ./faest/ ./pomfrit/
```

covers keygen / sign / verify per parameter set (mayo, faest) and the full
blind sign + verify loop per level (pomfrit)

## provenance and license

transpiled from and validated against the sources in [`SOURCES.md`](./SOURCES.md):

- **faest** — [faest.info](https://faest.info), `ait-crypto/faest-rs` (© 2023 faest team; mit / apache-2.0)
- **mayo** — [PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C) (apache-2.0), cross-checked vs `pq-mayo`
- **one-more-mayo** — the `pq_blind_signatures` reference (c++ vole `optimized_bs` + mayo-c, glued in rust `blind-signatures`)

vendored test vectors under `*/testdata/` are the upstream nist kats and the
reference dumps, and retain their original licenses (see [`NOTICE`](./NOTICE))

this project is licensed under apache-2.0 ([`LICENSE`](./LICENSE)); the mayo and
faest names and specifications belong to their respective teams
