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

| row | current best implementation | important files | target |
| --- | --- | --- | --- |
| Burn token | `eat-pass` Rust; partial Go duplicate in `confidential-agent`. | `eat-pass/core/src/lib.rs`, `confidential-agent/internal/tokenservice/types.go` | `tamayo/tokenprofile` should expose the Go wire format, mint helper, parse, verify, and redeem inputs. |
| Private identity token | `eat-pass` Rust; partial Go duplicate in `confidential-agent`. | `eat-pass/core/src/pvt.rs`, `eat-pass/docs/pvt.md`, `confidential-agent/internal/tokenservice/types.go` | `tamayo/tokenprofile` should expose private identity token input, parse, blind verification, presentation message, and holder proof verification. |
| Policy-bound email token | Incomplete. Pieces exist in `confidential-agent`. | `confidential-agent/internal/tokenservice/jwt.go`, `confidential-agent/internal/policy` | Specify and implement in Go after the authorization interface is landed. Must support runtime measurement authorization. |
| Google EVT | Most complete in `eat-pass bridge`; simpler Go duplicate in `confidential-agent`. | `eat-pass/cli/src/bridge.rs`, `eat-pass/cli/tests/bridge_e2e.rs`, `confidential-agent/internal/tokenservice/jwt.go` | Port a clean Google EVT profile into `tamayo`, separate from policy-bound token paths. |

## Package Split

| package | owns | must not own |
| --- | --- | --- |
| `tokenprofile` | Token wire formats, parse/serialize, blind issuer helper, burn token verification, private identity token verification, presentation message construction. | HTTP, persistent storage, runtime measurement collection, network policy. |
| `tokenauth` | Shared authorization data structures: token family, runtime measurement, email/address proof claims, mint binding, authorization decision. | Product-specific policy engine or transport. |
| `emailtoken` | Google EVT JWT and key-binding profile. | Blind token policy, TEE measurement policy, HTTP service. |
| `tokenservice` | Row-neutral issuer/verifier APIs that compose token profiles, authorization decisions, key lookup, and caller-provided time/nonce inputs. | HTTP, persistent storage, network traffic, filesystem access, runtime measurement collection. |
| product repos | Storage, HTTP routes, operator policy, measurement collection, runtime composition. | New token byte layouts or duplicate cryptographic token implementations. |

The package names are allowed to change during implementation, but these
boundaries are not.

## Migration Checks

- `tamayo` tests must prove burn tokens and private identity tokens round-trip
  without importing `eat-pass` or `confidential-agent`.
- `tamayo` tests must include a measurement authorization object for rows 1-3,
  even where product policy chooses not to require it.
- `eat-pass` tests stay as the Rust reference while porting.
- `confidential-agent` should stop defining token byte formats after it consumes
  the `tamayo` packages.
