# tamayo

pure-go, cgo-free implementations of the **mayo** post-quantum signature, the
**faest** / vole-in-the-head proof system, and the **pomfrit one-more-mayo**
blind signature, targeting the [tamago](https://github.com/usbarmory/tamago)
bare-metal go runtime - tamago + mayo (tamago means "egg")

interactive explainer: [maceip.github.io/tamayo](https://maceip.github.io/tamayo/)

> **warning** - experimental, unaudited, not production-ready; "verified"
> means byte-exact against the stipulated references, nothing more

token product boundaries and migration plan:
[`docs/token-roadmap.md`](./docs/token-roadmap.md)

## what's here

| package | what it is | verified against |
|---|---|---|
| `gf16` | gf(16) arithmetic | exhaustive / property tests |
| `field` | gf(2^128/192/256) + degree-3 extensions | reference vectors |
| `mayo` | mayo keygen / sign / verify + salt-free preimage sampler | nist round-2 kat 100/100 (l1/l3/l5); preimage byte-exact vs mayo-c |
| `faest` | the faest aes signature and its voleith engine | full nist kat 600/600 byte-exact (100 vectors x 6 sets) |
| `pomfrit` | the one-more-mayo blind signature and its vole engine (ggm-forest bavc, small-vole, deg-2 quicksilver, mayo-eval circuit) | byte-exact vs the c++/c reference, both directions, l1/l3/l5 |
| `tokenprofile` | burn-token and private-identity token layouts over PoMFRIT/MAYO | round-trip tests, challenge binding, origin-bound pseudonyms, Ed25519 and FAEST-128s holder proofs |
| `tokenauth` | compiled JSON mint authorization inputs for policy-controlled token rows | unknown-field rejection, origin checks, address checks, measurement checks |
| `emailtoken` | Google EVT and policy-bound email JWT profiles with KB-JWT presentation | issue/verify tests for address claims, holder key binding, nonce, audience, sd_hash |
| `tokenservice` | cgo-free issuer/verifier service APIs over the token packages | service-level tests for burn, Google EVT, and policy-bound email rows |
| `cmd/qemudemo` | the blind loop bare-metal on qemu sifive_u (riscv64) | on-device byte-exact at l1+l3+l5 |
| `spec/` | rfc-style profile draft: pomfrit blind issuance on the email verification protocol's rails (`alg: PoMFRIT-L1`, no `email` claim, `mailbox_verified: true`) + jose registration sketch | sizes byte-exact vs this repo |

no cryptographic primitive is hand-written - every construct is a transpile of
a named source in [`SOURCES.md`](./SOURCES.md); sha-3 and aes come from go's
`crypto/sha3` and `crypto/aes`

## one-more-mayo blind signature

the crown jewel (baum, beckmann, beullens, mukherjee, rechberger - *concretely
efficient blind signatures based on vole-in-the-head proofs and the mayo
trapdoor*): `sign_1` blinds the message as `t = h + r` with
`h = shake256(m || proof1)`, `sign_2` is the mayo preimage of `t`, `sign_3` is
the vole-in-the-head proof, `verify` recomputes `h` and runs `vole_verify` -
every layer checked byte-for-byte against dumpers compiled from the reference
sources; the ledger is [`PLAN.md`](./PLAN.md)

on device, `cmd/qemudemo` boots `qemu-system-riscv64 -machine sifive_u` and
runs the loop at all three levels against embedded reference vectors:

```
=== One-More-MAYO blind signature on TamaGo (sifive_u/riscv64), L1+L3+L5 ===
... t / bsig / proof byte-exact, verify + interop + tamper-reject per level ...
RESULT: PASS - One-More-MAYO blind sign+verify byte-exact on device (L1+L3+L5)
```

```
cd cmd/qemudemo && make qemu   # needs tamago-go, qemu-system-riscv64, dtc, python3
```

## usage

each package ships a runnable `Example` (run by `go test`, rendered on
pkg.go.dev) - the short version:

```go
// mayo (mp := &mayo.Mayo1)
cpk, csk, _ := mp.CompactKeyGen(seed)
sig, _ := mp.Sign(msg, csk, randomizer)
ok := mp.Verify(msg, sig, cpk)

// faest aes signature
sk, pk, _ := faest.FAEST128s.KeyGen(rand.Reader)
sig := faest.FAEST128s.Sign(msg, sk, rho)
ok := faest.FAEST128s.Verify(msg, pk, sig)

// one-more-mayo blind signature (o := pomfrit.MayoOWFL1)
epk, _ := mp.ExpandPK(cpk)
t, st, h := o.Sign1(msg, rAdditional)       // user: blind
bsig := mp.SignWithoutHashing(t, csk)       // signer: mayo preimage
proof := o.Sign3(epk, h, bsig, st, rAdditional)
ok = o.BlindVerify(epk, msg, proof.Bytes, rAdditional)
```

randomness contract: `randomizer` / `rho` / `rAdditional` must be fresh csprng
output in production; fixed values (as in tests) degrade mayo to hedged
deterministic signing

## test + benchmark

```
go test ./...          # full byte-exact surface; -short trims kat counts (what ci runs)
go test -bench . -run xxx ./mayo/ ./faest/ ./pomfrit/
```

ci: build + vet + short kats on linux amd64/arm64 + macos, `GOOS=tamago`
cross-builds (amd64/arm/arm64/riscv64), weekly full-kat replay - measured on
an apple m5 max (single core):

| scheme | set | keygen | sign | verify |
|---|---|---|---|---|
| mayo | MAYO_1 / 3 / 5 | 0.25 / 0.58 / 1.2 ms | 1.4 / 3.5 / 7.7 ms | 0.27 / 0.76 / 1.3 ms |
| faest | 128s / 192s / 256s | ~µs | 74 / 233 / 528 ms | 65 / 212 / 504 ms |
| faest | 128f / 192f / 256f | ~µs | 18 / 53 / 109 ms | 13 / 41 / 88 ms |
| pomfrit blind | L1 / L3 / L5 | n/a | 0.74 / 1.9 / 5.2 s | 0.63 / 1.5 / 3.8 s |

## security log

review pass 2026-07-02, full record in [`PLAN.md`](./PLAN.md):

- **detected + fixed** ([`870789b`]): `field.GF8.Mul` had data-dependent
  branches on faest's secret witness path (`invnorm`) - rewritten branch-free,
  kats confirm byte-identical
- **detected + fixed** ([`870789b`]): `faest.Verify`, `pomfrit.Verify` /
  `BlindVerify` and `mayo.SignWithoutHashing` panicked on malformed input -
  now length-check and reject
- **detected + fixed** ([`fdd8331`]): `crypto/cipher` aes-ctr pulled a fips
  self-test that stalled bare-metal init - mayo keygen drives `crypto/aes`
  directly, kat-green
- **accepted, documented** ([`870789b`]): no zeroization of key material
  (go's gc can copy buffers); caller-supplied randomness (see usage)

clean by construction: branch-free secret arithmetic (`gf16`, `field`, the
mayo echelon solver), constant-time comparisons everywhere secrets are
compared, no secret-indexed table lookups

[`870789b`]: https://github.com/maceip/tamayo/commit/870789b
[`fdd8331`]: https://github.com/maceip/tamayo/commit/fdd8331

## provenance and license

- **faest** - [faest.info](https://faest.info), `ait-crypto/faest-rs` (mit / apache-2.0)
- **mayo** - [PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C) (apache-2.0), cross-checked vs `pq-mayo`
- **one-more-mayo** - the `pq_blind_signatures` reference (c++ `optimized_bs` + mayo-c)

vendored `*/testdata/` vectors are upstream kats and reference dumps under
their original licenses ([`NOTICE`](./NOTICE)); this project is apache-2.0
([`LICENSE`](./LICENSE))
