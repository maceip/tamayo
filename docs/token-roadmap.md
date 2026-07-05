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
| 1 | Burn token | "This request was authorized once." No stable identifier. | One request, anti-abuse, one-shot access. | Burned on redemption. | Must be a first-class mint authorization input. A deployment can require an accepted runtime measurement before mint. | Yes: PoMFRIT over MAYO. | Implemented in `eat-pass`; partially reimplemented in `confidential-agent`; should move behind shared Go profile APIs. |
| 2 | Private identity token | Stable pseudonym at one verifier, no email address. | Account continuity or repeat visitor without address disclosure. | Reusable at one verifier; replay is controlled by presentation nonces. | Must be a first-class mint authorization input. A deployment can require an accepted runtime measurement before mint. | Yes for blind issuance. Holder proof must be PQ for the fully landed target. | Implemented in `eat-pass`; Go service currently has PoMFRIT token with Ed25519 holder proof and parsed-only ML-DSA. Needs Go parity. |
| 3 | Policy-bound email token | Verified email address, plus policy-bound issuance context. | RPs that need the address and also want the same policy surface as the private tokens. | JWT-style expiry. | Must be a first-class issuance authorization input. A deployment can require accepted runtime measurement before issuance. | Target is open: either classical email-token compatibility plus policy binding, or a PQ signing profile. Must be specified before claiming PQ. | Not fully landed. Pieces exist in `confidential-agent`; needs a clean Go profile, tests, and explicit TEE-measurement authorization coverage. |
| 4 | Google EVT | Verified email address only. | Interop and regression testing against Google's public email-verification-token shape. | JWT-style expiry plus presentation nonce/key binding. | None by design. This row is intentionally not coupled to TEE measurement, policy, or PQ. | No: classical JOSE path. | Implemented most fully in `eat-pass bridge`; should be ported as a Google EVT profile in Go without coupling it to private-token policy. |

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

## Cleanup Plan

1. Freeze `eat-pass` as the Rust reference/prototype. Keep tests and demos
   working, but stop adding new token functionality there.
2. Move or rewrite the reusable token profile code into `tamayo` packages.
   Keep `tamayo` cgo-free and TamaGo-compatible.
3. Add row-neutral issuer/verifier service APIs in `tamayo` that do not own
   HTTP, storage, networking, or runtime clock access.
4. Port the Google EVT issuer/verifier from `eat-pass bridge` into a Go
   profile, separate from private-token policy.
5. Add explicit tests for rows 1-3 proving that accepted runtime measurements
   can authorize minting or issuance.
6. Remove or thin the duplicate token-service implementation in
   `confidential-agent` after the Go profiles are available from `tamayo`.
7. Make `confidential-agent` a consumer: bootable runtime, agent workflow, and
   policy wiring only.
