# Tamayo

Pure-Go, **cgo-free** implementations of the **MAYO** post-quantum signature and the
**FAEST** / **VOLE-in-the-Head** proof system, targeting the
[TamaGo](https://github.com/usbarmory/tamago) bare-metal Go runtime.

The name is TamaGo + MAYO (TamaGo means "egg"; mayonnaise is made from eggs).

> [!WARNING]
> **Experimental. Not audited. Not production-ready.** This is a from-scratch
> transpilation of published references. It has had **no** independent security
> or side-channel review. "Verified" below means *matches the reference
> known-answer tests byte-for-byte* — nothing more. It **builds** under
> `GOOS=tamago` with the official `tamago-go` toolchain on all four targets
> (amd64/arm/arm64/riscv64), but has **not** been **run** on hardware or an
> emulator. Do not use it to protect anything.

## What's here

| Package | What it is | External verification |
|---|---|---|
| `gf16` | GF(16) arithmetic | exhaustive / property tests |
| `field` | GF(2^128/192/256) + degree-3 extensions | `LargeFieldMul` reference vectors |
| `mayo` | MAYO keygen / sign / verify (NIST round 2 params 1/3/5) | **MAYO NIST KAT, 100/100 per level** |
| `faest` | VOLE-in-the-Head engine (PRG, GGM/BAVC vector commitments, small-VOLE, universal hashing, QuickSilver) + the FAEST AES signature | **FAEST reference KATs, byte-exact** (full 600-vector run reproducible against `faest-rs`) |

Everything is a transpilation of a named reference — no cryptographic primitive is
hand-written. SHA-3/SHAKE is Go's `crypto/sha3`; AES is `crypto/aes`.

## Not here (yet)

The **PoMFRIT One-More-MAYO blind signature** is intentionally **not** in this
repository. An earlier version of its Fiat-Shamir transcript was composed
locally rather than transpiled and checked against the reference; it is being
redone as a faithful port of the `.shape` reference and verified against it
before publication.

## Usage

```go
import "github.com/maceip/tamayo/faest"

sk, pk, _ := faest.FAEST128s.KeyGen(rand.Reader)
sig := faest.FAEST128s.Sign(msg, sk, rho)   // rho: 16 bytes of randomness
ok  := faest.FAEST128s.Verify(msg, pk, sig)
```

```go
import "github.com/maceip/tamayo/mayo"
// MAYO keygen/sign/verify: see crypto/mayo (params mayo.Mayo1/3/5).
```

## Test

```
go test ./...
```

Runs the MAYO NIST KATs and the FAEST reference KATs. The full 600-vector FAEST
NIST replay lives in `faest/nist_kat_test.go`; this repo vendors a small subset,
and the complete `.rsp` set can be dropped into `faest/testdata/`.

## Provenance & license

Transpiled from and validated against:

- **FAEST** — [faest.info](https://faest.info), `ait-crypto/faest-rs` (© 2023 FAEST Team; MIT / Apache-2.0).
- **MAYO** — [PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C) (Apache-2.0), cross-checked vs `pq-mayo`.

Vendored test vectors under `*/testdata/PQCsignKAT_*.rsp` are the upstream NIST
KATs from those projects and retain their original licenses (see `NOTICE`).

This project is licensed under Apache-2.0 (`LICENSE`). MAYO and FAEST names and
specifications belong to their respective teams.
