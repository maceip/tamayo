# Known Gaps and Deferred Work

The single index of everything this repo knows it has *not* done. Every entry
is deliberate and has a nearer source of truth (linked); if a gap is not in
this table, it is not a known gap. The companion documents are
[`token-roadmap.md`](./token-roadmap.md) (what should exist and where),
[`implementation-inventory.md`](./implementation-inventory.md) (package
boundaries), and [`../PLAN.md`](../PLAN.md) (the PoMFRIT verification
ledger).

Conventions: **deferred** = scoped future work someone could pick up;
**boundary** = deliberately out of this repo, lives with product runtimes or
the Rust reference; **accepted** = known limitation we are not going to fix.

## Crypto layer

| gap | kind | detail / source of truth |
| --- | --- | --- |
| FAEST Even-Mansour sets | deferred | The EM constraint path was never ported, so no EM parameter set is exported; the constraint entry points panic on an EM OWF. The verified building blocks (Rijndael-192/256, EM witness extension, EM params) and end-to-end EM sign vectors are already vendored. Completing it = port the EM constraints from faest-rs, define the six EM `FaestParams`, regenerate EM NIST KATs with `tools/faest_kat_gen`. See the `faest` doc.go "Even-Mansour boundary". |
| HashML-DSA (pre-hash) | deferred | `mldsa` implements pure, internal, and external-mu ML-DSA only; the ACVP preHash groups are excluded from the vendored vectors. Add if a JOSE/COSE profile ever needs it. See `mldsa` package doc + SOURCES.md T.23. |
| Security audit | accepted (for now) | Everything is research-grade: "verified" means byte-exact against references, not reviewed. Constant-time discipline and the 2026-07-02 manual review are in PLAN.md; no external audit has happened. README warning. |
| Key-material zeroization | accepted | Go's GC can copy buffers, making wiping best-effort at most. PLAN.md security review, item 3. |
| ML-DSA-65/87 in the token layer | boundary | The primitives exist and are ACVP-verified; the token layer deliberately wires only ML-DSA-44 (holder proofs, PQ email profile). Raising levels is a profile decision, not a porting gap. |

## Token layer

| gap | kind | detail / source of truth |
| --- | --- | --- |
| PQ email JOSE identifiers are draft-stage | accepted (tracked) | `alg: ML-DSA-44` / `kty: AKP` follow draft-ietf-cose-dilithium, not final IANA registrations; the profile must be versioned if the draft names change, and row 3 stays "classical by default". [`pq-email-profile.md`](./pq-email-profile.md). |
| Budget enforcement is opt-in | accepted (documented) | `AuthorizeMint` with a nil `BudgetStore` skips the budget check ("enforcement happens elsewhere"); `MemoryBudgetStore` is single-process. Multi-replica issuers must implement `BudgetStore` over shared storage, fail-closed. `tokenauth` doc.go. |
| Spent-token + presentation-nonce storage | boundary | Burn double-spend sets and private-identity nonce stores are product work; the packages verify, products persist. Roadmap invariants; `cmd/tamayo serve` demonstrates with in-memory state only. |
| Runtime email proof + transport for email rows | boundary | Verified-email evidence collection, SMTP, JWKS distribution, HTTP hardening: product work. Roadmap row 3/4. |

## Supporting capabilities

| gap | kind | detail / source of truth |
| --- | --- | --- |
| Key-transparency log distribution | boundary | `transparency` owns format + verification; serving `/kt`, gossip, and durable log storage are product transport. Roadmap "Supporting Capabilities". |
| Log-signer seed derivation is stack-specific | accepted | A 32-byte seed derives different FAEST keys in Go (SHAKE256) vs Rust (ChaCha20); published keys, logs, and signatures are fully wire-compatible. `transparency.LogSigner` doc. |
| Mailbox mail delivery + durable challenges | boundary | `mailbox` owns canonicalization, buckets, and challenge semantics; SMTP and shared challenge storage are product work, provider-specific address folding is deployment policy. `mailbox` package doc. |

## Repo / ecosystem

| gap | kind | detail / source of truth |
| --- | --- | --- |
| Releases are patch-bump only | accepted | Every push to main auto-bumps the patch version and cuts a release with runner-tested binaries (`.github/workflows/release.yml`); minor/major bumps are a manual tag away (the auto-bump continues from the highest existing tag). |
| TEE attestation stays Rust-side | boundary | `eat-pass/gate` + unified-quote (EAT verification, quote collection) feed authorization as evidence; tamayo consumes, never reimplements. Roadmap "Repository Boundaries". |
| eat-pass is frozen, confidential-agent must thin | boundary (cross-repo) | Product repos still need to consume the tamayo packages and drop their duplicate token code. Roadmap cleanup items 1–4. |
| Pages explainer lags the code | deferred | maceip.github.io/tamayo tells the delegation story and the PoMFRIT math; it does not yet demo the runnable token layer (`cmd/tamayo`) or the burn/private-identity split. Blocked on the in-progress `docs/index.html` re-theme in the working tree. |
