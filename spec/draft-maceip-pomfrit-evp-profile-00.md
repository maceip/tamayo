---
title: "Blind Issuance Profile for the Email Verification Protocol using PoMFRIT"
abbrev: "PoMFRIT-EVP Profile"
docname: draft-maceip-pomfrit-evp-profile-00
category: exp
ipr: trust200902
area: Security
workgroup: TBD
keyword:
  - blind signature
  - email verification
  - post-quantum
  - unlinkability
  - MAYO
  - VOLE-in-the-head
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - ins: "maceip"
    name: "maceip"
    email: mac@secure.build

normative:
  RFC2119:
  RFC8174:
  RFC7515:
  RFC7517:
  RFC7519:
  RFC9421:
  I-D.hardt-email-verification:
  I-D.ietf-oauth-selective-disclosure-jwt:
  POMFRIT:
    title: "Concretely Efficient Blind Signatures Based on VOLE-in-the-Head Proofs and the MAYO Trapdoor"
    author:
      - name: Carsten Baum
      - name: Marvin Beckmann
      - name: Ward Beullens
      - name: Shibam Mukherjee
      - name: Christian Rechberger
    date: 2026
    target: https://eprint.iacr.org/2026/109
  MAYO:
    title: "MAYO: Specification Document (NIST PQC Additional Signatures, Round 2)"
    author:
      - name: Ward Beullens
    target: https://pqmayo.org

informative:
  RFC9576:
  RFC9577:
  RFC9578:
  FAEST:
    title: "FAEST: Algorithm Specification"
    target: https://faest.info
  TAMAYO:
    title: "tamayo: pure-Go MAYO / FAEST / PoMFRIT for the TamaGo bare-metal runtime"
    target: https://github.com/maceip/tamayo
  EATPASS:
    title: "eat-pass: attestation-gated, unlinkable authorization tokens"
    target: https://github.com/maceip/eat-pass

--- abstract

This document profiles the Email Verification Protocol (EVP) for blind
issuance. It reuses EVP's issuer discovery, metadata, and transport rails
unchanged, and replaces the issuer-visible Email Verification Token (EVT)
with a Private Verification Token (PVT): a JWT assembled by the browser and
signed blindly by the issuer using the PoMFRIT one-more-MAYO blind signature
(JWS algorithm "PoMFRIT-L1"). The PVT omits the "email" claim and carries
"mailbox_verified: true", attesting that the holder controls a mailbox at
the issuer without revealing which one. The issuer cannot link an issued
token to a presented token; the linkage protection is statistical and
therefore holds against quantum adversaries. This profile is an extension of
EVP, not a replacement: it targets deployments where the relying party needs
a stable, abuse-resistant, account-backed pseudonym rather than a mailable
address. A registration sketch for the required JOSE and EVP metadata
parameters is included.

--- middle

# Introduction

The Email Verification Protocol {{I-D.hardt-email-verification}} lets a
browser obtain, from the user's email provider, a token proving control of
an email address — without a verification email round trip. The token (EVT)
contains the address itself, and the issuer sees exactly which relying party
context each token is minted for, at what time, containing which address.
The issuer is therefore a linkage point across every site where the user
proves their address.

For a large class of relying parties the address is not the point. What a
sign-up flow actually consumes is: (a) evidence that a real, account-holding
person is behind the request, and (b) a stable per-user identifier to hang
state off and to rate-limit. The mailable address is often unread and
operationally a liability. EVP delivers (a) and (b) but couples them to
disclosure of the address and to issuer-side linkability.

This profile decouples them. The browser authenticates to its email provider
exactly as in EVP, but instead of receiving a token the issuer wrote, the
browser writes the token itself and has the issuer sign it blindly. The
issuer learns only that an authenticated account holder requested a signing;
it never sees the token contents, and by the blindness of the signature
scheme it cannot correlate any later presentation with any issuance event.
The relying party still gets an issuer-backed, key-bound, replay-protected
credential — with a per-site pseudonym (the confirmation key) instead of an
address.

The blind signature used is PoMFRIT {{POMFRIT}}, built from the MAYO
multivariate signature {{MAYO}} and the VOLE-in-the-Head proof system used
by FAEST {{FAEST}}. Two properties motivate this choice over classical blind
signatures (e.g. blind RSA as used by Privacy Pass {{RFC9578}}):

1. Unforgeability is based on assumptions plausibly secure against quantum
   attackers (one-more unforgeability of the MAYO trapdoor).
2. Blindness is statistical: the blinding value is a one-time pad. Even a
   computationally unbounded issuer — including a future quantum one
   replaying recorded transcripts — cannot link issuance to presentation.
   Unlinkability is not subject to harvest-now-decrypt-later.

## Relationship to EVP

This document changes nothing in EVP sections on issuer discovery (DNS TXT
record, `.well-known/email-verification` metadata fetch), HTTP Message
Signatures {{RFC9421}}, cookie handling, `Sec-Fetch-Dest`, uniform error
responses, or the SD-JWT-compatible presentation format
{{I-D.ietf-oauth-selective-disclosure-jwt}}. An issuer supports this profile
by adding metadata parameters ({{metadata}}) and one endpoint
({{issuance}}). An issuer that does not is simply not selected for blind
issuance; the browser falls back to standard EVP. The two token types
coexist under one discovery record.

## What blind issuance changes about semantics

In EVP, the issuer attests the token contents ("this address is controlled
by the requester"). In this profile the issuer never sees the contents, so
it attests something narrower: "one token was issued to a browser holding an
authenticated session at this issuer, during this epoch". Everything the
token claims beyond that is authored by the holder and merely
integrity-bound to the issuance. {{semantics}} makes this precise and
constrains the claim set accordingly. Relying parties MUST NOT treat a PVT
as attesting an email address; that is what EVTs are for.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals.

PVT:
: Private Verification Token. A JWT assembled by the browser, blind-signed
  by the issuer, defined in {{pvt}}.

Epoch:
: A fixed time window during which the issuer signs with exactly one blind
  signing key. The anonymity set of a PVT is all PVTs issued under that key.

Blinded target:
: The value `t` sent to the issuer in place of a message digest;
  information-theoretically independent of the token contents.

# Protocol Overview

~~~
Browser                              Issuer                    Relying Party
   |                                    |                            |
   |-- DNS TXT + metadata fetch ------->|   (EVP Section 3, as-is)   |
   |<-- metadata incl. blind params ----|                            |
   |                                    |                            |
   |  fix token bytes m (header.payload)|                            |
   |  blind:  t = h XOR r               |                            |
   |-- POST blind_issuance_endpoint --->|   (RFC 9421-signed,        |
   |        { blinded_targets:[t..] }   |    cookies, as in EVP)     |
   |<-- { blind_signatures:[s..] } -----|   s = MAYO preimage of t   |
   |                                    |                            |
   |  unblind: pi = ZK proof            |                            |
   |  PVT = m . b64u(pi) . "~"          |                            |
   |            ... later, offline from the issuer ...               |
   |-- PVT ~ KB-JWT ------------------------------------------------>|
   |                                    |<-- fetch blind JWKS -------|
   |                                    |   (anonymous, cacheable)   |
   |                    verify KB, BlindVerify(pk, m, pi) ---------->|
~~~

Two structural differences from EVP:

- Issuance is naturally batched. The browser SHOULD request several tokens
  per authenticated top-up and store them, so that later spends require no
  issuer contact at all (and hence leak no timing to the issuer).
- The signing key is epoch-scoped ({{epochs}}). The token carries the epoch,
  not an `iat`; a fine-grained issuance timestamp would partition the
  anonymity set.

# Issuer Metadata {#metadata}

An issuer supporting this profile adds the following parameters to its
`.well-known/email-verification` document (EVP Section 3.2):

`blind_issuance_endpoint`:
: REQUIRED. URL of the blind issuance API ({{issuance}}).

`blind_signing_alg_values_supported`:
: REQUIRED. JSON array of supported blind signature algorithms. This profile
  defines "PoMFRIT-L1"; "PoMFRIT-L3" and "PoMFRIT-L5" are reserved
  ({{alg}}). The value "none" MUST NOT be used.

`blind_jwks_uri`:
: OPTIONAL. URL of a JWK Set containing the issuer's blind signing keys. If
  absent, blind keys appear in the main `jwks_uri` set; verifiers not
  supporting this profile will skip them per {{RFC7517}} Section 5. A
  separate URI is RECOMMENDED to keep legacy JWKS consumers undisturbed.

`blind_epoch_seconds`:
: REQUIRED. Duration of a signing epoch in seconds. See {{epochs}}.

`blind_max_tokens_per_epoch`:
: OPTIONAL. Maximum number of tokens the issuer will sign per account per
  epoch. Absent means issuer-discretionary rate limiting.

Example:

~~~json
{
  "issuance_endpoint": "https://accounts.issuer.example/ev/issuance",
  "jwks_uri": "https://accounts.issuer.example/ev/jwks",
  "signing_alg_values_supported": ["EdDSA"],
  "blind_issuance_endpoint": "https://accounts.issuer.example/ev/blind",
  "blind_jwks_uri": "https://accounts.issuer.example/ev/blind-jwks",
  "blind_signing_alg_values_supported": ["PoMFRIT-L1"],
  "blind_epoch_seconds": 604800,
  "blind_max_tokens_per_epoch": 64
}
~~~

# Blind Issuance {#issuance}

## Token fixing and blinding (browser)

Unlike EVP, the complete token bytes MUST be fixed before the issuer is
contacted, because the blinded target is derived from them:

1. Generate a fresh confirmation key pair for this token. Each PVT carries
   its own key; the key is the pseudonym ({{privacy}}).
2. Determine the issuer's current epoch identifier and blind signing `kid`
   from metadata and the blind JWK Set.
3. Construct the JOSE header and payload per {{pvt}} and form the JWS
   signing input `m = ASCII(BASE64URL(header) || "." || BASE64URL(payload))`
   {{RFC7515}}.
4. Generate fresh 32-byte session randomness `r_additional`, bound into the
   Fiat–Shamir transcript and later carried in the signature value
   ({{alg}}).
5. Run PoMFRIT `sign_1` on `m`: generate the proof commitment, derive
   `h = SHAKE256(m || commitment)` and the uniformly random pad `r`, and
   compute the blinded target `t = h XOR r`. Retain the prover state.

Steps 1–5 are repeated per token when batching. Prover state (which contains
the eventual zero-knowledge witness randomness) MUST be kept secret and MUST
be discarded if issuance fails.

## Issuance request

The browser POSTs to `blind_issuance_endpoint` exactly as an EVP issuance
request — same HTTP Message Signature construction, cookie inclusion, and
`Sec-Fetch-Dest: email-verification` — with this body:

~~~json
{ "blinded_targets": ["<b64u(t_1)>", "..."] }
~~~

There is no `email` parameter. The issuer's authorization question is not
"does this user control address X" but "is this an authenticated account
holder"; naming an address would only leak intent.

## Issuer processing

On receipt the issuer:

1. Verifies the request per EVP Request Verification (message signature,
   `created` freshness, `Sec-Fetch-Dest`), unchanged.
2. Verifies the cookies represent a logged-in user controlling at least one
   mailbox it serves. WebAuthn fallback applies as in EVP.
3. Enforces its per-account, per-epoch token budget. Each element of
   `blinded_targets` counts as one issuance interaction against the budget
   (this is what the one-more unforgeability bound counts; see
   {{security}}).
4. For each target `t`, computes the MAYO preimage
   `s = MAYO.SignWithoutHashing(t, csk)` under the current epoch's compact
   secret key. The target is attacker-controlled bytes of fixed length;
   malformed lengths MUST be rejected with the uniform error behavior of EVP
   Section 9.

Response:

~~~json
{
  "kid": "2026-w27",
  "epoch": "2026-w27",
  "blind_signatures": ["<b64u(s_1)>", "..."]
}
~~~

Error responses reuse EVP's error codes and MUST be uniform across "no such
account", "not logged in", and "budget exhausted" to the extent EVP requires
uniformity, plus `budget_exhausted` MAY be distinguished for legitimate
clients since it reveals nothing about third parties.

## Unblinding and assembly (browser)

For each returned `s`, the browser runs PoMFRIT `sign_3` with the retained
prover state: verify that `s` is a valid preimage of `t` under the issuer's
epoch public key, then produce the zero-knowledge proof `pi` of knowledge of
`(s, r)` such that `P*(s) = h XOR r`, where `P*` is the issuer's public MAYO
map and `h` is recomputable from `m` by anyone. The proof — not `s`, not
`r` — together with the session randomness forms the signature value:

~~~
PVT = BASE64URL(header) "." BASE64URL(payload) "."
      BASE64URL(r_additional || pi) "~"
~~~

The trailing `~` preserves SD-JWT surface compatibility as in EVP Section
5.1.3. A PVT parses with any JWS/SD-JWT library; only the signature
verification step differs.

# The Private Verification Token {#pvt}

## Header

- `alg` (REQUIRED): "PoMFRIT-L1" (or another value from
  `blind_signing_alg_values_supported`).
- `kid` (REQUIRED): the epoch signing key identifier.
- `typ` (REQUIRED): "pvt+jwt".

## Payload

- `iss` (REQUIRED): the issuer identifier.
- `epoch` (REQUIRED): the epoch identifier, matching the signing key's
  epoch. Coarse by construction.
- `cnf` (REQUIRED): confirmation claim with the browser's fresh public key
  in `jwk` form, as in EVP.
- `mailbox_verified` (REQUIRED): boolean, MUST be `true`.

The following MUST NOT appear: `email`, `iat`, `sub`, `jti`, or any claim
carrying holder-chosen variable content. `iat` is excluded because a
timestamp partitions the epoch anonymity set; `epoch` is the only permitted
freshness signal. Verifiers MUST reject a PVT containing prohibited claims.

Example:

~~~json
{
  "iss": "issuer.example",
  "epoch": "2026-w27",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }
  },
  "mailbox_verified": true
}
~~~

## What a PVT attests — and what it does not {#semantics}

The issuer signs blind. The cryptographic content of a valid PVT is exactly:

> The party that assembled this token engaged in one blind-issuance
> interaction with `iss` during `epoch`, at which time it held an
> authenticated session as a mailbox-controlling account holder; and the
> token bytes have not been altered since (one-more unforgeability binds
> `m` to the interaction: a holder completing L issuance interactions can
> produce valid proofs for at most L distinct messages).

`mailbox_verified: true` is defined as shorthand for the above. It is
holder-written, but it cannot be counterfeit: writing it requires spending
an issuance interaction that only an authenticated account holder can
obtain. It says nothing about *which* mailbox, and the claim-set restriction
above exists precisely because any other holder-written claim would carry no
issuer attestation while appearing issuer-signed to a naive verifier.

# Presentation and Key Binding

Presentation is EVP Section 6, verbatim, with the PVT in place of the EVT:
the browser signs a Key Binding JWT (`typ: "kb+jwt"`) with the token's
confirmation key over `aud`, `nonce`, `iat`, and `sd_hash` (the SHA-256 of
the PVT including the trailing `~`), and delivers `PVT~KB-JWT`.

Browser spending policy is normative for the privacy properties:

- A PVT, once presented to an origin, is bound to that origin: the browser
  MUST present the same PVT (fresh KB-JWT each time) for subsequent
  verifications at that origin, giving the relying party a stable pseudonym.
- A PVT presented to one origin MUST NOT be presented to any other origin.
  Two origins comparing notes on token bytes or `cnf` keys would otherwise
  link the user. Cross-origin unlinkability comes from one-token-per-origin,
  not from the signature (the proof is bound to fixed token bytes; it is not
  re-randomizable per presentation).
- The browser SHOULD maintain a small stock of unspent PVTs per account and
  top up in batches, decorrelating issuance from spending in time.

# Verification (relying party)

1. Parse `PVT~KB-JWT` with SD-JWT conventions; verify the KB-JWT per EVP
   Section 6.5 (`aud`, `nonce` freshness, `iat` window, `sd_hash`, signature
   under `cnf.jwk`).
2. Check `typ` is `pvt+jwt`, `alg` is a supported PoMFRIT algorithm, and the
   payload claim set conforms to {{pvt}}.
3. Fetch issuer metadata for `iss` (cacheable, no DNS step needed since
   `iss` is explicit) and the blind JWK Set; select the key matching `kid`.
4. Check `epoch` is the issuer's current epoch or the immediately preceding
   one within the acceptance grace period ({{epochs}}).
5. Split the JWS signature value into `r_additional` (first 32 bytes) and
   `pi`. Expand the compact MAYO public key and run PoMFRIT verification:
   recompute `h = SHAKE256(m || commitment)` from the JWS signing input and
   the proof's commitment prefix, and verify the VOLE-in-the-head proof
   against the expanded public map, `h`, and `r_additional`. Reject on any
   length mismatch.

Replay across presentations at the same relying party is prevented by the
KB-JWT nonce exactly as in EVP. There is no double-spend ledger: reuse of a
PVT at one origin is the intended stable-pseudonym behavior, and reuse
across origins is a browser-policy violation that harms only the user's own
unlinkability, not the relying party.

# Epochs and Key Management {#epochs}

- The issuer MUST use exactly one PoMFRIT signing key per epoch and MUST NOT
  issue under more than one key concurrently. Multiple concurrent keys are a
  key-partitioning attack: which key signed a token is visible to the
  relying party and partitions the anonymity set.
- Epoch duration is a privacy/agility trade-off: the anonymity set of a
  token is the number of tokens the issuer signed that epoch. Weekly
  (`blind_epoch_seconds: 604800`) is RECOMMENDED as a floor for consumer
  issuers.
- Relying parties SHOULD accept the current and immediately previous epoch,
  and MUST NOT accept older ones; this bounds the utility of hoarded tokens
  and of any key compromised after rotation.
- The issuer MUST destroy (zeroize) an epoch's secret key when the epoch
  closes. Verification requires only the public key, so the acceptance
  grace period is unaffected. Sealing the epoch means a later compromise of
  the issuer cannot retroactively mint tokens for past epochs, and the
  total token supply of a closed epoch is fixed forever.
- Blind JWK Sets SHOULD be served with cache lifetimes covering the epoch
  and SHOULD be fetchable without credentials, so relying-party fetches are
  anonymous and amortized. Issuers MUST publish epoch keys in an
  append-only, publicly auditable log (key transparency) so that a targeted
  per-user key cannot be served covertly; browsers and relying parties
  SHOULD pin the log key and verify inclusion, and SHOULD verify log
  consistency across key rotations.

# The PoMFRIT-L1 Algorithm {#alg}

PoMFRIT {{POMFRIT}} is a three-move blind signature built from the MAYO
trapdoor {{MAYO}} and a VOLE-in-the-Head zero-knowledge proof. In the JWS
mapping used here:

- Message: the JWS signing input `m`.
- `sign_1` (holder): commit VOLE randomness; `h = SHAKE256(m || commitment)`
  (39 bytes at L1); pad `r` derived from the committed randomness;
  blinded target `t = h XOR r`. Since `r` is uniform and used once, `t` is
  statistically independent of `m` — blindness is unconditional.
- `sign_2` (issuer): `s` such that `P*(s) = t`, where `P*` is the whipped
  MAYO public map of the epoch key, via the salt-free MAYO preimage sampler.
- `sign_3` (holder): a VOLE-in-the-Head proof `pi` of knowledge of `(s, r)`
  with `P*(s) = h XOR r`.
- Verification: recompute `h` from `m` and the commitment prefix of `pi`;
  verify `pi` against the expanded public map. Verification is
  deterministic, offline, and requires only `m`, the signature value, and
  the issuer's public key.

The scheme binds 32 bytes of session randomness `r_additional` into the
Fiat–Shamir transcript at both proving and verification. The holder
generates it fresh per token and the JWS signature value carries it as a
prefix: `signature = r_additional || pi`. Verifiers split the first 32
bytes off before proof verification. (This matches the authenticator
encoding of the eat-pass implementation; see Implementation Status.)

The `alg` value "PoMFRIT-L1" denotes the same construction eat-pass calls
`PoMFRIT-MAYO1-FV1-128` — the MAYO_1 instance with the FV1_128
VOLE-in-the-Head parameterization of the reference implementation; proof
bytes interoperate.

Parameter sets (MAYO round-2 instances; sizes in bytes; the JWS signature
value is `32 + |pi|`, base64url expansion in parentheses):

| Algorithm  | MAYO set | Issuer JWK `pk` | Blinded target `t` | Issuer reply `s` | Proof `pi` | JWS signature |
|------------|----------|-----------------|--------------------|------------------|------------|---------------|
| PoMFRIT-L1 | MAYO_1   | 1420            | 39                 | 430              | 6895       | 6927 (9236)   |
| PoMFRIT-L3 | MAYO_3   | 2986            | 54                 | 649              | 15862      | 15894 (21192) |
| PoMFRIT-L5 | MAYO_5   | 5554            | 71                 | 924              | 29615      | 29647 (39530) |

Issuance costs the network 469 bytes per token at L1 (39 up, 430 down,
excluding HTTP framing); the ~7 KB proof is generated and spent client-side
and never transits the issuer. Verifiers expand the 1420-byte compact public
key into the internal evaluation form (~146 KB at L1) once per epoch and
cache it.

# JOSE and EVP Registration Sketch {#iana}

This section sketches the registrations a standards-track successor would
request. Nothing is registered by this document.

## JSON Web Signature and Encryption Algorithms

| "alg" value | Description                              | Recommended |
|-------------|------------------------------------------|-------------|
| PoMFRIT-L1  | PoMFRIT blind signature, MAYO_1, NIST L1 | No          |
| PoMFRIT-L3  | PoMFRIT blind signature, MAYO_3, NIST L3 | No          |
| PoMFRIT-L5  | PoMFRIT blind signature, MAYO_5, NIST L5 | No          |

These `alg` values are verification-only from the JOSE point of view: no
single party holds a key that can produce the signature alone, so generic
JWS *signing* APIs do not apply. Verification has the standard
`Verify(key, signingInput, signature) -> bool` shape.

## JSON Web Key Types

| "kty" value | Description                     |
|-------------|---------------------------------|
| MAYO        | MAYO multivariate quadratic map |

Parameters for `kty: "MAYO"`:

| Parameter | Description                                  | Required |
|-----------|----------------------------------------------|----------|
| pset      | Parameter set name ("MAYO_1"/"MAYO_3"/"MAYO_5") | Yes   |
| pk        | base64url compact public key (seed + P3)     | Yes      |

Example blind JWK Set entry:

~~~json
{
  "keys": [{
    "kty": "MAYO",
    "pset": "MAYO_1",
    "kid": "2026-w27",
    "use": "sig",
    "alg": "PoMFRIT-L1",
    "pk": "<1420 bytes, base64url>"
  }]
}
~~~

## Media Types / typ

`application/pvt+jwt` — Private Verification Token, carried in the JOSE
`typ` header as "pvt+jwt".

## JSON Web Token Claims

| Claim            | Description                                        |
|------------------|----------------------------------------------------|
| mailbox_verified | Holder demonstrated mailbox control at iss (blind) |
| epoch            | Issuer signing-epoch identifier                    |

## EVP Metadata Parameters

`blind_issuance_endpoint`, `blind_jwks_uri`,
`blind_signing_alg_values_supported`, `blind_epoch_seconds`,
`blind_max_tokens_per_epoch`, as defined in {{metadata}}, for whatever
registry the EVP metadata document establishes.

# Security Considerations {#security}

**One-more unforgeability.** The supply of valid PVTs is metered by
issuance interactions: L interactions yield at most L tokens (OMUF of
PoMFRIT under the MAYO assumptions; see {{POMFRIT}} for concrete bounds).
The per-epoch budget in {{issuance}} is therefore the abuse-rate knob.
Epoch-scoped acceptance ({{epochs}}) caps hoarding: tokens cannot be
stockpiled across epochs and dumped.

**Blindness and covert channels.** Blindness is statistical: `t` is a
one-time-padded value, so issuance transcripts contain no information about
token contents, forever. Additionally, a malicious issuer cannot embed a
tracking tag in its reply the way a Private State Token issuer can flip a
private-metadata bit: the reply `s` is a witness inside a zero-knowledge
proof and is never shown to the relying party. Any bits the issuer grinds
into its choice of preimage are destroyed by the proof. The remaining
issuer-side signal is traffic analysis of issuance events (count and
timing), mitigated by batching.

**Key partitioning.** The issuer-side linkage attack that survives blinding
is serving different signing keys to different users. {{epochs}} requires
one key per epoch and recommends transparency logging; relying parties
fetching keys anonymously and caching them per epoch make targeted key
substitution detectable.

**Probing and uniform errors.** The issuance endpoint inherits EVP's
uniform-response requirements. Because the request names no email address,
this profile removes EVP's account-probing surface entirely: there is
nothing in the request for an attacker to probe about a third party.

**Token theft.** A PVT is useless without its confirmation private key
(KB-JWT is required at every presentation). Browsers SHOULD device-bind
confirmation keys where platform key stores permit, aligning with
device-bound session credential practice.

**Post-quantum scope.** Unforgeability rests on multivariate-quadratic
assumptions (MAYO) and symmetric primitives (SHAKE, AES-CTR in the VOLE
engine) — plausibly post-quantum. Unlinkability is information-theoretic.
The HTTP Message Signature on the issuance request and the KB-JWT may still
use classical algorithms; compromising them later forges neither past nor
future tokens and unblinds nothing.

**Implementation maturity.** PoMFRIT was published in 2026 and has not
received the cryptanalytic attention of lattice schemes; MAYO is a NIST PQC
round-2 candidate, not a standard. The reference and interoperable
implementations are unaudited. This is an Experimental profile by design.

# Privacy Considerations {#privacy}

What each party learns, per token:

| Party         | Learns                                                    |
|---------------|-----------------------------------------------------------|
| Issuer        | account identity; count and timing of top-ups; nothing about where/whether tokens are spent |
| Relying party | `iss`, `epoch`, a per-origin pseudonym (`cnf` key), `mailbox_verified` |
| Network       | issuance and presentation events, sizes                    |

The relying party learns the user's email *provider* (`iss`). For large
providers this is a weak signal; for a single-user vanity domain it
identifies the user, exactly as in EVP. Users on small domains gain little
from this profile unless the domain delegates to a large issuer — which the
EVP discovery mechanism already supports and which is the RECOMMENDED
deployment for small domains.

The anonymity set is per-issuer per-epoch. Issuers SHOULD publish issuance
volume so relying parties and users can judge it. All other considerations
(browser storage of tokens, clearing with site data, etc.) follow EVP
Section 10.

--- back

# Implementation Status

An interoperable, cgo-free Go implementation of the complete PoMFRIT
`sign_1 / sign_2 / sign_3 / verify` flow exists in {{TAMAYO}} (packages
`pomfrit` and `mayo`), validated byte-for-byte against the reference C++/C
implementation of {{POMFRIT}} at all three levels, including on bare-metal
riscv64. Measured single-core on an Apple M5 Max: blind-sign 0.74 s / 1.9 s
/ 5.2 s and verify 0.63 s / 1.5 s / 3.8 s at L1/L3/L5 (pure Go; the
reference optimized C++ reports sub-100 ms showings at L1). Sizes in
{{alg}} are the byte-exact values from that implementation:
`ProofSize() = 6895 / 15862 / 29615`.

The primitive and its surrounding token machinery already run end to end
in eat-pass {{EATPASS}}, a Rust implementation of PoMFRIT spend tokens on
Privacy Pass rails: the {{RFC9577}} challenge/redemption HTTP flow with token
type 0x4550 and algorithm label `PoMFRIT-MAYO1-FV1-128`, batched blind
issuance into a client-side token store, a mandatory signed append-only
key-transparency log pinned by both client and origin with
consistency-checked key rotation, an epoched central double-spend store,
rate limiting, and fuzzed token parsers. This profile inherits its
authenticator encoding (`r_additional || pi`) and its key-transparency
stance. eat-pass differs in the issuance gate and the binding discipline:
it gates minting on hardware attestation (a FAEST-signed authorization over
a CVM or mobile EAT) rather than on an authenticated mailbox account, and
it binds the origin challenge into the blind-signed message at mint time,
yielding one-time origin-bound tokens — where this profile mints
origin-agnostic tokens bound at presentation via the KB-JWT, because the
stable per-origin pseudonym requires reuse. The two gates slot into the
same primitive. eat-pass's PoMFRIT core links the reference C++/C
implementation natively (Linux x86_64 only); the pure-Go tamayo
implementation removes that platform restriction for server and bare-metal
deployments.

What does not yet exist, and is out of scope here: a browser wallet, the
issuance endpoint on EVP's rails (eat-pass demonstrates the equivalent
endpoint on HTTP-auth rails), and the JWS plumbing for the `alg`/`kty`
values sketched in {{iana}}.

# Acknowledgments
{:numbered="false"}

The rails profiled here are Dick Hardt's Email Verification Protocol. The
signature scheme is due to Baum, Beckmann, Beullens, Mukherjee, and
Rechberger. The framing of blind issuance as an extension profile rather
than a competing protocol follows the Privacy Pass architecture's
{{RFC9576}} separation of issuance and redemption.
