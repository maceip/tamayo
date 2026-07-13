# tamayo

**let your agents fly.** a universal security framework for agents,
whether claude runs in a secure enclave with remote attestation or on
betsy's laptop: every privileged action presents a signed, single-use
pass instead of your identity. pure-go, cgo-free post-quantum crypto
and anonymous tokens, down to the
[tamago](https://github.com/usbarmory/tamago) bare-metal go runtime.
interactive explainer: [maceip.github.io/tamayo](https://maceip.github.io/tamayo/)

> **warning** - experimental, unaudited, not production-ready; "verified"
> means byte-exact against the stipulated references, nothing more

token boundaries and migration plan: [`docs/token-roadmap.md`](./docs/token-roadmap.md);
every known gap is indexed in [`docs/known-gaps.md`](./docs/known-gaps.md)

## where it runs

an agent rollout never lands on one kind of machine - the same quarter
puts agents on an intern's unmanaged laptop and next to the payment
service. the packages are identical at every tier; the only thing that
changes is the evidence a mint demands:

| tier | evidence policy can demand |
|---|---|
| unmanaged laptops (byod, contractors) | software witness, per-source budgets, short expiry |
| hardware-backed laptops (tpm / secure enclave) | hardware-held holder keys, device attestation at mint |
| ephemeral cloud (ci, scrapers, batch) | workload identity, one token per action, budget per job |
| confidential cloud (money, pii) | sev-snp / tdx quotes as mint inputs, named measurements + signers |
| critical, bare metal | tamago in a tee - no linux, libc, or shell; measure the whole binary |

the policy engine follows [cedar](https://www.cedarpolicy.com/)'s
approach: one small, analyzable json file that compiles or doesn't,
deny by default. a production policy that accepts dev-grade evidence,
or leaves a rate-limit bucket up to the caller, fails at
`tokenauth.Compile`. how we learned that the hard way:
[you can't vibe code authorization](https://maceip.github.io/tamayo/#sigbird)

## what's here

| package | what it is | verified against |
|---|---|---|
| `gf16`, `field` | gf(16), gf(2^128/192/256) + extensions | exhaustive/property tests, reference vectors |
| `mayo` | mayo keygen/sign/verify + salt-free preimage sampler | nist kat 100/100 (l1/l3/l5); preimage byte-exact vs mayo-c |
| `faest` | the faest aes + even-mansour signatures and their voleith engine | full nist kat 1200/1200 byte-exact (12 sets: 6 aes + 6 em) |
| `pomfrit` | the one-more-mayo blind signature and its vole engine | byte-exact vs the c++/c reference, both directions, l1/l3/l5 |
| `mldsa` | ml-dsa-44/65/87 (fips 204) | nist acvp byte-exact (480 vectors) |
| `tokenprofile` | burn + private-identity token layouts over pomfrit/mayo | round-trips, challenge binding, origin-bound pseudonyms, ed25519/faest-128s/ml-dsa-44 holder proofs |
| `tokenauth` | compiled json mint authorization + reference budget store | policy checks, budget reserve/deny/rollover |
| `emailtoken` | google evt + policy-bound email jwt with kb-jwt presentation; ml-dsa-44 pq profile | issue/verify + pq round trips |
| `tokenservice` | issuer/verifier service apis over the token packages | service-level tests, batch-binding enforcement |
| `transparency` | append-only issuer key log, faest-128f signed heads | verifies a reference-generated, reference-signed log byte-exact |
| `mailbox` | mailbox eligibility gate: canonical addresses, keyed buckets, binding-bound challenge codes | bucket hmacs pinned vs reference dumps |
| `logging` | zero-dep structured logging on stdlib `log/slog`: host text/json handlers + a compact, timestamp-free console handler for bare-metal tamago | level filtering, structured fields/groups, no-op default |
| `cmd/tamayo` | reference issuer/verifier binary (cli + http service) | end-to-end blind-sign, double-spend, policy-denial over http |
| `cmd/qemudemo` | the blind loop bare-metal on qemu sifive_u (riscv64) | on-device byte-exact at l1+l3+l5 |
| `spec/` | rfc-style draft: pomfrit blind issuance on evp rails | sizes byte-exact vs this repo |

no cryptographic primitive is hand-written - every construct is a transpile
of a named source in [`SOURCES.md`](./SOURCES.md); sha-3 and aes come from
go's `crypto/sha3` and `crypto/aes`

## use it

**as a library.** `go get github.com/maceip/tamayo@latest` - plain go
modules, nothing to publish anywhere; proxy.golang.org mirrors tags
automatically and docs render on pkg.go.dev. single dependency (tamago,
build-tag-gated to the bare-metal demo), so it cross-compiles with the
**stock** toolchain - verified for linux/macos/windows/freebsd on
amd64/arm64/riscv64, cgo on or off; tamago-go is needed only to target
`GOOS=tamago` itself.

**as a binary.** every push to main cuts a release (auto patch bump); each
platform archive - linux amd64/arm64, macos amd64/arm64, windows amd64 - is
**executed on a native github runner** (full blind mint→verify loop) before
it ships, with SHA256SUMS:

```
go install github.com/maceip/tamayo/cmd/tamayo@latest

tamayo keygen -out issuer.json          # one issuer key epoch (secret)
tamayo demo   -issuer issuer.json       # burn + private-identity loops, RESULT: PASS
tamayo mint-burn   -issuer issuer.json -challenge "origin challenge" -out token.b64
tamayo verify-burn -issuer issuer.json -token token.b64 -challenge "origin challenge"
tamayo example-policy > policy.json
tamayo serve -issuer issuer.json -policy policy.json   # 127.0.0.1:8787
```

`serve` exposes `/v1/issuer`, `/v1/blind-sign` (policy + budget gated,
binding-checked), `/v1/verify/burn` and `/v1/verify/private-identity`
(replay-checked). real cryptography, in-memory state - durable storage and
transport stay with product runtimes
([`docs/implementation-inventory.md`](./docs/implementation-inventory.md)).

## one-more-mayo blind signature

the crown jewel (baum, beckmann, beullens, mukherjee, rechberger): `sign_1`
blinds the message as `t = h + r` with `h = shake256(m || proof1)`, `sign_2`
is the mayo preimage of `t`, `sign_3` is the vole-in-the-head proof,
`verify` recomputes `h` and runs `vole_verify` - every layer checked
byte-for-byte against dumpers compiled from the reference sources
(ledger: [`PLAN.md`](./PLAN.md)). `cmd/qemudemo` runs the loop bare-metal at
all three levels and accepts byte-identical proofs on device:

```
cd cmd/qemudemo && make qemu   # needs tamago-go, qemu-system-riscv64, dtc, python3
```

## usage

the signature packages ship runnable `Example`s - the short version:

```go
// mayo (mp := &mayo.Mayo1)
cpk, csk, _ := mp.CompactKeyGen(seed)
sig, _ := mp.Sign(msg, csk, randomizer)
ok := mp.Verify(msg, sig, cpk)

// one-more-mayo blind signature (o := pomfrit.MayoOWFL1)
epk, _ := mp.ExpandPK(cpk)
t, st, h := o.Sign1(msg, rAdditional)       // user: blind
bsig := mp.SignWithoutHashing(t, csk)       // signer: mayo preimage
proof := o.Sign3(epk, h, bsig, st, rAdditional)
ok = o.BlindVerify(epk, msg, proof.Bytes, rAdditional)

// token layer: the same loop under a burn token
issuer, _ := tokenprofile.NewIssuer(1, nil)
input := tokenprofile.BurnInput(nonce, challengeDigest, issuer.TokenKeyID())
target, state := tokenprofile.PrepareBlind(input, additionalR)
sigs, _ := issuer.BlindSign([][]byte{target})
auth, _ := tokenprofile.FinalizeBlind(issuer.ExpandedPublicKey(), sigs[0], state)
```

randomness contract: `randomizer` / `rho` / `rAdditional` must be fresh
csprng output in production; fixed values (as in tests) degrade mayo to
hedged deterministic signing

## test + benchmark

```
go test ./...          # full byte-exact surface; -short is what ci runs
go test -bench . -run xxx ./mayo/ ./faest/ ./pomfrit/ ./mldsa/
```

apple m5 max, single core:

| scheme | set | keygen | sign | verify |
|---|---|---|---|---|
| mayo | MAYO_1 / 3 / 5 | 0.25 / 0.58 / 1.2 ms | 1.4 / 3.5 / 7.7 ms | 0.27 / 0.76 / 1.3 ms |
| faest | 128s / 192s / 256s | ~µs | 74 / 233 / 528 ms | 65 / 212 / 504 ms |
| faest | 128f / 192f / 256f | ~µs | 18 / 53 / 109 ms | 13 / 41 / 88 ms |
| pomfrit blind | L1 / L3 / L5 | n/a | 0.74 / 1.9 / 5.2 s | 0.63 / 1.5 / 3.8 s |

## security log

review pass 2026-07-02, full record in [`PLAN.md`](./PLAN.md): fixed
data-dependent branches on faest's secret witness path (`field.GF8.Mul`,
rewritten branch-free, kat-identical); fixed verifier panics on malformed
input (all verify paths length-check and reject); fixed a fips self-test in
`crypto/cipher` stalling bare-metal init. accepted + documented: no
zeroization of key material (go's gc can copy buffers), caller-supplied
randomness. clean by construction: branch-free secret arithmetic,
constant-time comparisons, no secret-indexed table lookups.

## provenance and license

- **faest** - [faest.info](https://faest.info), `ait-crypto/faest-rs` (mit / apache-2.0)
- **mayo** - [PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C) (apache-2.0), cross-checked vs `pq-mayo`
- **one-more-mayo** - the `pq_blind_signatures` reference (c++ `optimized_bs` + mayo-c)
- **ml-dsa** - nist fips 204, acvp vectors

vendored `*/testdata/` vectors are upstream kats and reference dumps under
their original licenses ([`NOTICE`](./NOTICE)); this project is apache-2.0
([`LICENSE`](./LICENSE))
