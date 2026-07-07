# Post-Quantum Email-Signing Profile (Policy-Bound Email Token)

This is the PQ signing profile required by the token roadmap's cleanup item 5
("specify and implement any PQ email-signing profile before documenting
address-bearing email rows as fully post-quantum"). It applies **only** to the
policy-bound email token (roadmap row 3). The Google EVT row (row 4) stays on
the classical JOSE path by design.

## What it is

The same `tamayo-policy-email+jwt` token as the classical profile — identical
claims, identical policy binding, identical KB-JWT presentation flow — signed
with **ML-DSA-44** (FIPS 204) instead of Ed25519.

| aspect | classical profile | PQ profile |
| --- | --- | --- |
| issuer signature | Ed25519, JWS `alg: EdDSA` | ML-DSA-44, JWS `alg: ML-DSA-44` |
| issuer key JWK | `kty: OKP`, `crv: Ed25519`, `x` | `kty: AKP`, `pub` |
| holder `cnf` key | OKP/Ed25519 only | OKP/Ed25519 **or** AKP/ML-DSA-44 |
| kid convention | `ed25519-<sha256[:8]>` | `ml-dsa-44-<sha256[:8]>` |
| token size (sig only) | 64 B (~86 B b64) | 2420 B (~3227 B b64) |
| implementation | `emailtoken.Signer` | `emailtoken.PQSigner` |
| service rail | `tokenservice.Issuer.IssuePolicyEmail` | `tokenservice.Issuer.IssuePolicyEmailPQ` |

A presentation is **fully post-quantum only when both** the issuer signature
is ML-DSA-44 **and** the holder `cnf` key is AKP/ML-DSA-44 (the KB-JWT is then
also an ML-DSA-44 JWS, via `emailtoken.SignKBJWTMLDSA44`). A PQ issuer
signature over an Ed25519 holder key is a hybrid: the address binding is PQ,
the presentation proof-of-possession is not.

## JOSE representation

Algorithm and key encodings follow **draft-ietf-cose-dilithium**: JWS `alg`
value `ML-DSA-44`, and the Algorithm Key Pair (`AKP`) JWK type with the raw
public key base64url-encoded in the `pub` parameter.

**Honesty note:** those identifiers are IETF *draft* registrations, not final
IANA entries. If the draft's names change before registration, this profile
must be versioned; consumers should pin issuer keys, not rely on `alg`
stability across deployments.

## Signing variants

`mldsa` implements both FIPS 204 signing variants. The profile defaults to
**deterministic** signing (`rnd` = 32 zero bytes); callers can supply 32
fresh CSPRNG bytes (`PolicyEmailIssueOptions.Rnd` /
`PolicyEmailIssueRequest.Rnd`) for **hedged** signing, which is what FIPS 204
recommends where side-channel exposure matters. This mirrors the module-wide
caller-supplied-randomness contract (see the README).

## What this does and does not claim

- The policy-bound email row **can** now be issued and presented on a fully
  post-quantum signature chain (`mldsa` is NIST ACVP-verified byte-exact).
- Row 3's default remains classical Ed25519; the roadmap table records the PQ
  status as "profile available", not "row is PQ by default".
- Transport, verified-email evidence, and JWKS distribution remain product
  work, exactly as for the classical profile.
