# Token Product Roadmap

This document is the source of truth for the token products that should exist
across the stack. `tamayo` owns the Go, cgo-free cryptographic primitives,
token-profile building blocks, and issuer/verifier service APIs. Product
runtimes should import these pieces; they should not invent parallel token
formats.

Current implementation locations are tracked in
[`implementation-inventory.md`](./implementation-inventory.md).

## Repository Boundaries

| repo | role | direction |
| --- | --- | --- |
| `tamayo` | Go/TamaGo crypto, token-profile primitives, and issuer/verifier service APIs | Keep and make authoritative. |
| `eat-pass` | Rust product/protocol prototype | Freeze for compatibility and demos; do not add new token functionality. |
| `confidential-agent` | Bootable agent/runtime using these primitives | Should consume token profiles, not own independent token formats. Current token-service code is a migration source, not the final boundary. |
| `unified-quote` / attested-build components | Runtime evidence and measurement language | Feed authorization policy before token minting. |

## Token Rows

| row | plain name | what the verifier learns | use | lifetime | TEE measurement authorization | post-quantum status | implementation status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Burn token | "This request was authorized once." No stable identifier. | One request, anti-abuse, one-shot access. | Burned on redemption. | First-class mint authorization input through `tokenauth`; service signing requires an allowed decision. | Yes: PoMFRIT over MAYO. | Landed in `tokenprofile` and `tokenservice`; product repos still need to consume it and own spend storage. |
| 2 | Private identity token | Stable pseudonym at one verifier, no email address. | Account continuity or repeat visitor without address disclosure. | Reusable at one verifier; replay is controlled by presentation nonces. | First-class mint authorization input through `tokenauth`; origin can be required by policy. | Yes for blind issuance. Holder proof is Ed25519 today; ML-DSA is parsed but not verified. | Landed in `tokenprofile`; verifier returns an origin-bound pseudonym. PQ holder proof remains open. |
| 3 | Policy-bound email token | Verified email address, plus policy-bound issuance context. | RPs that need the address and also want the same policy surface as the private tokens. | JWT-style expiry plus KB-JWT presentation. | First-class issuance authorization input through `tokenauth`; measurement requirements are compiled and tested. | Classical Ed25519 JWT today. A PQ signing profile is still open and must not be claimed yet. | Initial Go profile landed in `emailtoken` and `tokenservice`; runtime email proof and transport remain product work. |
| 4 | Google EVT | Verified email address only. | Interop and regression testing against Google's public email-verification-token format. | JWT-style expiry plus presentation nonce/key binding. | None by design. This row is intentionally not coupled to TEE measurement, policy, or PQ. | No: classical JOSE path. | Landed in `emailtoken` and `tokenservice` as a separate Google EVT path. |

## Invariants

- TEE measurement is not a token format. It is authorization evidence consumed
  before minting or issuing a token.
- Rows 1-3 must always have a code path where runtime measurement can be used
  as an authorization criterion. The low-level capability should not disappear
  even when a deployment chooses an email-only or test-only policy.
- Row 4 exists to keep an unmodified Google EVT implementation available for
  testing and interop. It should stay separate from the
  policy-bound and post-quantum rows.
- Burn tokens and private identity tokens share the blind-signature issuer
  family. The issuer should not learn token contents, target origin, or final
  presentation.
- The private identity token is not just a burn token with a longer lifetime:
  it gives a verifier same-user continuity through a pseudonym while still
  hiding the email address and issuer-visible identifier.
- Issuer and verifier service APIs live in `tokenservice`, but HTTP, storage,
  clocks, nonce stores, and runtime measurement collection stay with product
  runtimes.

## Cleanup Plan

1. Freeze `eat-pass` as the Rust reference/prototype. Keep tests and demos
   working, but stop adding new token functionality there.
2. Keep moving reusable token behavior into `tamayo` packages while preserving
   cgo-free and TamaGo-compatible boundaries.
3. Remove or thin the duplicate token-service implementation in
   `confidential-agent` after the Go profiles are available from `tamayo`.
4. Make `confidential-agent` a consumer: bootable runtime, agent workflow, and
   policy wiring only.
5. Specify and implement the PQ holder proof and any PQ email-signing profile
   before documenting those rows as fully post-quantum.
