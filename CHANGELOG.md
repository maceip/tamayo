# changelog

## unreleased

- faest: the six Even-Mansour parameter sets (FAESTEM128s/f, 192s/f, 256s/f)
  are now fully implemented and verified byte-exact against the FAEST NIST
  KAT (100 vectors each, sk/pk/sm/verify — the KAT surface is now 1200/1200).
  The EM one-way function y = Rijndael_pk(x) XOR x uses public round keys
  from the Rijndael schedule (no key-expansion constraints), the committed
  secret input, and a 2*lambda PRG leaf commitment (NLeafCommit=2) vs the
  3*lambda universal-hash one for AES; Rijndael-192/256 (NSt=6/8) wide states
  are exercised. This was the last true crypto gap in known-gaps.md.

- key rotation: `serve -issuer a.json,b.json` keeps retired key epochs live
  for verification while the first file signs, `/v1/kt` publishes one record
  per epoch (oldest first), verify routes by token_key_id, and the spent set
  partitions by key version — a token minted under the old key still
  verifies across the rotation overlap (tested)
- mldsa: HashML-DSA (fips 204 §5.4 pre-hash) — `SignPreHash`/`VerifyPreHash`
  across all twelve approved hash functions (sha2, sha3, shake), verified
  byte-exact against the acvp preHash groups (now 360 siggen + 180 sigver);
  vendored vectors regenerated to include them
- tokenprofile: best-effort key zeroization — `Wipe`/`Issuer.Zeroize` and
  seed-buffer wiping in the cli (go's gc can still copy buffers, so this
  reduces rather than eliminates secret residency — a language limitation,
  documented, not unfinished work)
- docs/known-gaps.md rewritten to a strict definition — a gap is both sides
  built with a missing middle; future work (audit), language limits
  (zeroization), standards state (draft jose ids), and deployment-owned
  pieces (multi-replica storage) are listed separately, not as gaps. two
  real gaps remain: faest even-mansour (unconsumed) and the pages demo
  (blocked on the in-progress index.html)

- cmd/tamayo: durable state fallback — `serve -state-dir <dir>` appends
  every burn spend, presentation nonce, and budget reservation to an
  fsynced json-lines journal and replays it at startup, so a restart no
  longer opens a double-spend/replay window on a single node (proven by a
  restart-survival test); default stays in-memory, mailbox codes are
  intentionally not journaled (minutes-lived, re-request is the recovery),
  and multi-replica deployments still want shared stores behind the
  SpentStore/BudgetStore seams

- the reference port list is complete: `tokenauth/authorization.go` (the
  wire-compatible faest-128f-signed issuance-authorization envelope for a
  cross-process attester/issuer split, with `AttesterSigner` and full
  rejection coverage) and `tokenauth/sidecar.go` (faest-signed policy
  sidecars: `tamayo sign-policy` writes `<policy>.sig`, `serve -policy-pub`
  refuses any policy whose sidecar does not verify under a trusted operator
  key — tamper refusal verified live); nothing portable remains outside
  this repo

- three more reference ports: `tokenprofile/carriage.go` (rfc 9577
  privatetoken www-authenticate/authorization header codecs, wire-shaped
  like the reference), `tokenservice.SpentStore` + `MemorySpentStore`
  (epoch-partitioned double-spend seam, fail-closed, prunable — `cmd/tamayo
  serve` now uses it instead of an ad-hoc map), and `GET /v1/kt` on serve
  (the runtime's key epoch as a client-verifiable transparency log:
  verify-log + inclusion tested end to end); remaining from the port list:
  the signed issuance-authorization envelope and signed policy sidecars

- cmd/tamayo: the EVP rail — `serve -evp-issuer <id>` mounts the
  browser-facing email-verification issuer
  (`/.well-known/email-verification` discovery metadata, an EdDSA jwks, and
  the issuance endpoint verifying RFC 9421 http message signatures under
  the browser's ed25519 `hwk` key with the fixed covered-component set);
  mailbox-control codes are bound to the requesting browser key so a
  phished code cannot be redeemed under another holder, each evt charges
  the mailbox's per-window budget, and `-sendmail` delivers codes through
  an external command (dev default prints to stderr); `-tls-cert/-tls-key`
  serve the whole runtime over https for real-browser benchmarking;
  end-to-end tests drive a stand-in browser through discovery, signed
  issuance, cross-key/replay/tamper/stale rejections, and the budget limit
- docs: the token roadmap records that eligibility gates are pluggable by
  design (email is only the first; wallet/other-token gates must remain
  possible without schema change)

- tokenauth: the eligibility vocabulary is now "gate", replacing "bridge" —
  `GateKind`/`GateRule`/`AllowedGates`, policy json fields
  `gates`/`allowed_gates`/`gate_kind`, and `gate_*` check names. breaking
  for policy files written against the old field names (compile rejects
  unknown fields loudly). "gate" matches the mailbox/attestation gate
  terminology used across the stack; nothing architectural called a bridge
  ever existed in this repo
- continuous releases: every push to main auto-bumps the patch version and
  cuts a github release — each platform binary (linux amd64/arm64, macos
  amd64/arm64, windows amd64) is built on a native github-hosted runner,
  the packaged asset itself is executed there (keygen, the full blind
  mint→verify demo, a mint/verify round trip, and a wrong-challenge
  rejection) before upload, and SHA256SUMS covers the set; darwin/amd64 is
  exercised under rosetta on the arm runner

- new `mldsa` package: ml-dsa-44/65/87 (fips 204), pure go, cgo-free —
  keygen/sign/verify with the deterministic + hedged variants and the pure,
  internal, and external-mu interfaces (hashml-dsa pre-hash is out of scope);
  verified byte-exact against the nist acvp ml-dsa-fips204 vector sets (75
  keygen + 270 siggen + 135 sigver, all non-pre-hash groups, vendored gzipped
  with commit provenance in `mldsa/testdata/`); branch-free secret-path
  arithmetic (centered reduction, multiply-shift decompose) and
  malformed-input rejection probes matching the repo's hardening bar; unblocks
  the roadmap's "ml-dsa is parsed but not verified" row for private identity
  holder proofs
- `docs/known-gaps.md`: single index of every known gap, deferral, and
  boundary (faest-em, hashml-dsa, draft-stage pq jose identifiers, opt-in
  budget enforcement, product-side storage/transport, cross-repo cleanup,
  release tagging, pages demo lag) — if a gap is not in that table it is not
  a known gap; linked from the readme, and the nil-BudgetStore semantics are
  now documented in the tokenauth package doc
- new `transparency` package: the eat-pass key transparency log ported to go
  — append-only hash chain (leaf/head/sth domains byte-identical),
  faest-128f signed heads, and the three client checks (verify log,
  inclusion, consistency); wire compatibility proven by verifying a log
  generated and signed by the verbatim rust reference (`tools/kt_dump`
  compiles eat-pass's transparency.rs unmodified and certifies every dumped
  head with the reference's own verify_log before vendoring); closes the
  review finding that the mandatory-in-spec key transparency capability had
  no tamayo counterpart
- new `mailbox` package: the eat-pass mailbox-control eligibility gate
  ported to go — canonical email rules, keyed hmac rate-limit buckets
  (pinned byte-exact against reference-dumped values), and the single-use,
  binding-bound, attempt-limited challenge store; TEE-free by design, feeds
  `tokenauth` as an eligibility gate; smtp delivery and durable storage
  stay product work
- new `cmd/tamayo` reference binary (`go install
  github.com/maceip/tamayo/cmd/tamayo@latest`): `keygen` writes an issuer
  key-epoch file, `demo` runs the burn + private-identity blind loops end to
  end, `mint-burn`/`verify-burn` are the cli round trip, `example-policy`
  emits a compile-checked tokenauth policy, and `serve` is a reference http
  issuer/verifier (policy + budget gated `/v1/blind-sign` with the binding
  check, `/v1/verify/burn` with an in-memory spent set,
  `/v1/verify/private-identity` with per-origin nonce replay protection);
  covered by end-to-end httptest flows; all durable state remains product
  work per the inventory boundaries
- readme: "use it" section — library install (go modules straight from the
  repo; proxy.golang.org/pkg.go.dev pick tags up automatically, nothing to
  post to a registry), binary install, portability matrix (stock go,
  linux/macos/windows/freebsd amd64/arm64/riscv64, cgo on or off; tamago-go
  needed only for GOOS=tamago), and a token-layer usage snippet
- faest: the even-mansour boundary is now explicit instead of a buried
  comment — doc.go documents exactly which em building blocks exist and are
  byte-exact (rijndael-192/256, em witness extension, em owf params, vendored
  em sign vectors) versus the unported em constraint path, and the constraint
  entry points panic on an em owf instead of silently computing aes
  constraints on an em witness; completing faest-em (constraints port + em
  parameter sets + kat regeneration) is recorded there as future work
- tokenauth: the budget rate-limit path is now implemented and exercised —
  `MemoryBudgetStore` transpiles the eat-pass `InMemoryRateLimiter`
  (window-bucketed counters, fail-closed contract, prune housekeeping) and
  new tests drive `AuthorizeMint` through reserve/deny/window-rollover;
  previously `BudgetStore` was an interface with no implementation and every
  test passed nil
- tokenservice/tokenprofile: blind-row authorizations are now
  cryptographically bound to the presented batch — `tokenprofile.BindingOf`
  ports the eat-pass `binding_of` (sha-256 over `eat-pass/binding\0`, batch
  count, length-prefixed targets, wire-compatible) and
  `SignAuthorizedBlind` recomputes it and rejects a decision whose
  `binding_b64` does not match the blinded targets (previously only
  count/family/expiry were checked, so a decision could be replayed for
  different targets)
- emailtoken/tokenservice: pq email-signing profile for the policy-bound
  email row (roadmap cleanup item 5, specified in
  `docs/pq-email-profile.md`) — `PQSigner`/`PQVerifier` issue and verify the
  same `tamayo-policy-email+jwt` claims as an ml-dsa-44 jws
  (draft-ietf-cose-dilithium `alg`/`AKP` identifiers, honestly flagged as
  draft-stage), holder `cnf` keys may be okp/ed25519 or akp/ml-dsa-44 with
  kb-jwt support for both (`SignKBJWTMLDSA44`), deterministic by default
  with caller-supplied hedging, and the service grows the parallel
  `IssuePolicyEmailPQ`/`VerifyPolicyEmailPresentationPQ` rail behind the same
  `tokenauth` gate; the google evt row intentionally stays classical
- tokenprofile: the ml-dsa-44 private-identity holder proof is now verified
  (pure ml-dsa with empty context, matching the eat-pass pvt cnf-key
  convention) instead of returning "not implemented"; round-trip presentation
  test added alongside the ed25519 and faest-128s ones; token packages and
  `mldsa` added to the `GOOS=tamago` ci cross-build to enforce the roadmap's
  tamago-compatibility mandate
- pomfrit: deleted the unreachable deg-2 quicksilver gf2 helper surface
  (`QSP2Bit.MulBit`, `QSP2El.MulBit`, `QSP2El.AddBit`, `QSP2Bit.ToEl`,
  `QSP2Bit.Add`) per the PLAN.md ledger promise ("covered or deleted when the
  mayo circuit is re-verified"): the reference expression is an ambiguous c++
  overload the dumper cannot produce vectors for, and the mayo circuit was
  re-verified without it; full byte-exact suite green after the deletion

- `spec/draft-maceip-pomfrit-evp-profile-00.md`: rfc-style (kramdown-rfc)
  profile draft layering pomfrit blind issuance on the email verification
  protocol's discovery/transport rails — private verification token
  (`typ: pvt+jwt`, `alg: PoMFRIT-L1`, `email` omitted, `mailbox_verified:
  true`, epoch-scoped keys), issuer metadata + endpoint, jose `alg`/`kty`
  registration sketch; every size in the draft verified byte-exact against
  this repo (t=39, s=430, proof=6895 at l1); reconciled against eat-pass
  (rust pomfrit spend tokens on privacy pass rails, rfc 9577, token type
  0x4550): per-token `r_additional` carried as a 32-byte prefix of the jws
  signature value (eat-pass authenticator encoding), key transparency
  upgraded to MUST, epoch secret-key destruction at epoch close, and an
  implementation-status section positioning tamayo as eat-pass's pure-go,
  cgo-free path (its pomfrit core is ffi to the c++ reference, linux
  x86_64 only)
- github pages explainer at maceip.github.io/tamayo: a hand-rolled gen-1
  tamagotchi (bigger screen) whose B button hatches a d3-projected 3d egg
  into an auto-playing story of the pomfrit blind signature (pup / stamper /
  owl), with a C-button math overlay for the nerds; deployed by
  `.github/workflows/pages.yml`
- readme: concise security log citing commits, overall length cut by a third

- pomfrit/mayo hardening follow-up: `SignWithoutHashing` now rejects overlong
  blinded targets exactly as specified, `Sign3`/`Prove2` reject malformed
  packed inputs without panics, and proof packing uses exact-size buffers
  instead of nested appends

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
