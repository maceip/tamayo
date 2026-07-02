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
| `faest` | vole-in-the-head engine (prg, ggm/bavc vector commitments, small-vole, universal hashing, quicksilver) and both the faest aes signature and the one-more-mayo blind signature | faest reference kats byte-exact; one-more-mayo byte-exact vs the c++/c reference both directions |
| `cmd/qemudemo` | the one-more-mayo blind loop running bare-metal on qemu sifive_u (riscv64) | on-device byte-exact, see below |

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

`faest.MayoOWFL1` / `MayoOWFL3` / `MayoOWFL5` reproduce the reference blinded
message, preimage and full proof byte-for-byte at all three levels, and the
go verifier accepts the reference proof (interop) and rejects tampering — the
verification ledger is [`PLAN.md`](./PLAN.md)

## on device

`cmd/qemudemo` boots on `qemu-system-riscv64 -machine sifive_u`, runs the l1
blind loop against an embedded reference vector, and prints on the uart console

```
=== One-More-MAYO blind signature on TamaGo (sifive_u/riscv64), L1 ===
[sign_1] blinding message ... t byte-exact vs reference: true
[sign_2] MAYO preimage ... bsig byte-exact vs reference: true
[sign_3] VOLE-in-the-Head proof ... proof byte-exact vs reference (6895 bytes): true
[verify] on-device blind verify (Go proof) ... verify=true
[verify] on-device blind verify (reference proof) ... verify=true
[verify] tampered proof rejected ... rejected=true
RESULT: PASS — One-More-MAYO blind sign+verify byte-exact on device
```

```
cd cmd/qemudemo && make qemu   # needs the tamago-go toolchain, qemu-system-riscv64, dtc
```

the whole tree also cross-builds under `GOOS=tamago` with `tamago-go` for
amd64/arm/arm64/riscv64; the on-device run above is l1, l3/l5 are byte-exact on
host but not yet booted on device

## usage

```go
import "github.com/maceip/tamayo/faest"

// faest aes signature
sk, pk, _ := faest.FAEST128s.KeyGen(rand.Reader)
sig := faest.FAEST128s.Sign(msg, sk, rho)   // rho: 16 bytes of randomness
ok := faest.FAEST128s.Verify(msg, pk, sig)

// one-more-mayo blind signature (o = faest.MayoOWFL1, mp = &mayo.Mayo1)
t, st, h := o.Sign1(msg, rAdditional)        // blinded message
bsig := mp.SignWithoutHashing(t, csk)        // mayo preimage (signer)
proof := o.Sign3(epk, h, bsig, st, rAdditional)
ok = o.BlindVerify(epk, msg, proof.Bytes, rAdditional)
```

## test

```
go test ./...
```

runs the mayo nist kats, the faest reference kats, the mayo preimage kat, and
the one-more-mayo byte-exact loop (prover, verifier, and full blind path at
l1/l3/l5) — the full 600-vector faest replay lives in `faest/nist_kat_test.go`
and this repo vendors a reduced subset, with the complete `.rsp` set droppable
into `faest/testdata/`

reference vectors were produced by the c++/c dumpers in `tools/`, compiled
against the stipulated sources and run to emit inputs and outputs that the go
tests replay byte-for-byte

## provenance and license

transpiled from and validated against the sources in [`SOURCES.md`](./SOURCES.md):

- **faest** — [faest.info](https://faest.info), `ait-crypto/faest-rs` (© 2023 faest team; mit / apache-2.0)
- **mayo** — [PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C) (apache-2.0), cross-checked vs `pq-mayo`
- **one-more-mayo** — the `pq_blind_signatures` reference (c++ vole `optimized_bs` + mayo-c, glued in rust `blind-signatures`)

vendored test vectors under `*/testdata/` are the upstream nist kats and the
reference dumps, and retain their original licenses (see [`NOTICE`](./NOTICE))

this project is licensed under apache-2.0 ([`LICENSE`](./LICENSE)); the mayo and
faest names and specifications belong to their respective teams
