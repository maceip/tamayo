# Known Gaps

A **gap** here means one thing: both sides of a capability are built and
something in the middle is missing or unwired. Future features, external
standards constraints, and deployment-owned pieces are *not* gaps — those are
listed separately at the bottom so this table stays honest. If it is not in
the Gaps table, it is not a gap.

Companion docs: [`token-roadmap.md`](./token-roadmap.md) (what should exist),
[`implementation-inventory.md`](./implementation-inventory.md) (package
boundaries), [`../PLAN.md`](../PLAN.md) (PoMFRIT verification ledger).

## Gaps

| gap | detail / source of truth |
| --- | --- |
| Pages explainer lags the code | The demo site tells the crypto + delegation story but does not yet demo the runnable token layer (`cmd/tamayo`, the live issuer) or the burn/private-identity split. Both sides exist; the demo just does not wire them. Blocked on the in-progress `docs/index.html` re-theme in the working tree — not touched to avoid clobbering unsaved work. |

## Recently closed

- **FAEST Even-Mansour** — all six EM sets (FAESTEM128s/f, 192s/f, 256s/f)
  implemented and verified byte-exact against the FAEST NIST KAT (100
  vectors each). Was the last true crypto gap.

- **Key rotation** — `serve -issuer a.json,b.json` keeps retired epochs live
  for verification while the first signs; `/v1/kt` publishes a record per
  epoch; verification routes by `token_key_id`; the spent set partitions by
  key version. Overlap-window verify tested.
- **HashML-DSA (pre-hash)** — `mldsa.SignPreHash`/`VerifyPreHash` (FIPS 204
  §5.4) across all twelve approved hash functions, verified byte-exact
  against the ACVP preHash groups (now 360 sigGen + 180 sigVer).
- **Key-material zeroization** — `tokenprofile.Wipe` / `Issuer.Zeroize` and
  seed-buffer wiping in the CLI. Best-effort (see note below), but done.
- **Durable single-node state** — `serve -state-dir` journals spends,
  nonces, and budgets and replays on start (restart-survival tested).
- **Key-transparency serving, RFC 9421/9577, signed authorization + policy
  sidecars, the EVP rail** — all shipped in `cmd/tamayo`.

## Not gaps (deliberate)

These were previously mislabeled as gaps. They are recorded for honesty but
are not missing middles:

- **No external security audit** — planned *future work*, not a gap.
  Verification today is byte-exact against references plus the internal
  review in PLAN.md. The audit happens when the project is feature-complete.
- **Zeroization is best-effort, not guaranteed** — a property of Go (the GC
  can copy a buffer before `Wipe` runs; there is no runtime hook to prevent
  it). We wipe what we hold; we cannot promise no copy ever existed. This is
  a language limitation, not unfinished work.
- **Budget enforcement is opt-in** — `AuthorizeMint` enforces the budget
  only when handed a `BudgetStore`; a nil store means "enforced elsewhere."
  This is intentional API design, and `MemoryBudgetStore` + `serve` exercise
  the real path. Not a missing middle.
- **Multi-replica shared storage** — deployment-owned. The single-node
  journal is shipped; running multiple issuer replicas needs a shared store
  behind the `SpentStore`/`BudgetStore` seams (Redis/DB), which is a
  deployment choice, not repo code.

## Standards / regulatory notes (not gaps)

- **PQ email JOSE identifiers are draft-stage** — `alg: ML-DSA-44` /
  `kty: AKP` track draft-ietf-cose-dilithium, not final IANA registrations;
  version the profile if the draft names change. This is an external
  standards state, not a defect. [`pq-email-profile.md`](./pq-email-profile.md).

## Boundaries (out of this repo by design)

- **TEE attestation verifiers** (unified-quote EAT, Azure/Android/iOS) feed
  authorization as evidence; tamayo consumes, never reimplements.
- **Email transport hardening** beyond the reference runtime (SMTP infra,
  JWKS distribution at scale).
