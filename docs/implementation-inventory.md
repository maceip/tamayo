# Implementation Inventory

This inventory records where each token path exists today and what should
happen to it. The goal is to stop treating every checkout as an equal source of
truth.

## Ownership Labels

| label | meaning |
| --- | --- |
| authoritative | Future work should be implemented here. |
| reference | Keep for compatibility, tests, and examples; do not add new token features. |
| migration input | Use this code as source material while moving behavior into `tamayo`. |
| duplicate | Remove or thin after `tamayo` exposes the shared implementation. |

## Repositories

| repo | current token role | label | notes |
| --- | --- | --- | --- |
| `/Users/mac/tamayo` | MAYO, FAEST, PoMFRIT primitives, token-profile packages, and issuer/verifier service APIs. | authoritative | Add shared token code here. Keep cgo-free and TamaGo-compatible. |
| `/Users/mac/tee-stack/eat-pass` | Rust product prototype with burn tokens, private identity tokens, mail gate, and Google EVT bridge. | reference | Freeze feature work. Use as behavior reference while porting. |
| `/Users/mac/confidential-agent` | Bootable agent/runtime plus a second Go token service under `internal/tokenservice`. | migration input, then duplicate | Move reusable token behavior into `tamayo`; keep only runtime composition here. |
| `/Users/mac/tee-stack/unified-quote` and attestation repos | Runtime evidence and measurement verification language. | reference / dependency | Feed authorization policy before token minting. Do not mix token formats into these repos. |

## Token Rows

| row | current best implementation | important files | remaining work |
| --- | --- | --- | --- |
| Burn token | `tamayo/tokenprofile` and `tamayo/tokenservice`. | `tokenprofile/burn.go`, `tokenservice/service.go` | Product repos must consume the shared API and provide spent-token storage. |
| Private identity token | `tamayo/tokenprofile` and `tamayo/tokenservice`. | `tokenprofile/private_identity.go`, `tokenservice/service.go` | Replace the Ed25519 holder proof with a specified PQ holder proof, or keep documenting the holder proof limit. |
| Policy-bound email token | `tamayo/emailtoken`, `tamayo/tokenauth`, and `tamayo/tokenservice`. | `emailtoken/policy_email.go`, `tokenauth`, `tokenservice/service.go` | Product repos must provide verified email evidence, runtime measurement evidence, and transport. PQ signing remains unspecified. |
| Google EVT | `tamayo/emailtoken` and `tamayo/tokenservice`. | `emailtoken/evt.go`, `emailtoken/presentation.go`, `tokenservice/service.go` | Keep separate from policy-bound issuance; product repos can wrap it for interop tests. |

## Package Split

| package | owns | must not own |
| --- | --- | --- |
| `tokenprofile` | Token wire formats, parse/serialize, blind issuer helper, burn token verification, private identity token verification, presentation message construction. | HTTP, persistent storage, runtime measurement collection, network policy. |
| `tokenauth` | Compiled JSON authorization data structures: token family, runtime measurement, email/address proof claims, origin, mint binding, authorization decision. | Product-specific transport or evidence collection. |
| `emailtoken` | Google EVT JWT, policy-bound email JWT, JWKS, holder key binding, and KB-JWT presentation verification. | Blind token policy, TEE measurement collection, HTTP service. |
| `tokenservice` | Row-neutral issuer/verifier APIs that compose token profiles, authorization decisions, key lookup, and caller-provided time/nonce inputs. | HTTP, persistent storage, network traffic, filesystem access, runtime measurement collection. |
| product repos | Storage, HTTP routes, operator policy, measurement collection, runtime composition. | New token byte layouts or duplicate cryptographic token implementations. |

The package names are allowed to change during implementation, but these
boundaries are not.

## Migration Checks

- `tamayo` tests prove burn tokens and private identity tokens round-trip
  without importing `eat-pass` or `confidential-agent`.
- `tamayo` tests include measurement authorization for policy-controlled rows
  through `tokenauth`.
- `tamayo` tests prove Google EVT and policy-bound email tokens verify through
  separate service paths.
- `eat-pass` tests stay as the Rust reference while porting.
- `confidential-agent` should stop defining token byte formats after it consumes
  the `tamayo` packages.
