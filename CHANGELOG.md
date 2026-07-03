# changelog

## unreleased

- security review pass: `field.GF8.Mul` made branch-free (it sits on faest's
  secret witness path via invnorm); verify boundaries (`faest.Verify`,
  `pomfrit.Verify`/`BlindVerify`, `mayo.SignWithoutHashing`) now length-check
  and reject malformed input instead of panicking; `pomfrit.(MayoOWF).ProofSize`
  exported; security notes added to the readme

- exported mayo public api: `CompactKeyGen` / `KeyGen` / `Sign` / `Verify` /
  `ExpandPK` (thin wrappers over the kat-verified internals; `ExpandPK` is
  byte-exact vs mayo-c `mayo_expand_pk`)
- runnable `Example` functions for `mayo`, `faest` and `pomfrit` (run by
  `go test`, shown on pkg.go.dev)
- benchmarks for keygen / sign / verify in all three signature packages
- github actions ci: build + vet + short kats on linux/arm/macos, tamago
  cross-builds for all four architectures, and a scheduled full-kat replay

## 2026-07-02

- `pomfrit`: the one-more-mayo blind signature extracted into its own package
  (formerly the `vole_mayo_*` files inside `faest`)
- full faest nist kat coverage: 600/600 vectors byte-exact across all six
  parameter sets, regenerated from the faest-rs reference by
  `tools/faest_kat_gen` and vendored gzipped
- on-device coverage extended to all three levels: qemu sifive_u runs the
  blind loop at l1+l3+l5 to `RESULT: PASS`, with a generated per-build bios
  stage (`mkbios.py`) replacing the stale hardcoded-entry `bios.bin`

## 2026-07-01

- one-more-mayo blind signature end-to-end (sign_1/2/3 + verify), byte-exact
  against the c++/c reference in both directions at l1/l3/l5
- first on-device run: l1 blind loop on bare-metal tamago
  (qemu sifive_u, riscv64)
- deg-2 quicksilver, ggm-forest bavc, small-vole, vole_check, mayo-eval
  circuit and mayo preimage sampler transpiled and byte-exact verified
- initial import: pure-go mayo (nist kat 100/100) and faest vole-in-the-head
  for the tamago bare-metal runtime
