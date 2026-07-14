# Mailproof: email-verified tokens with zero signup

This is the economical reference for issuing tamayo private-identity tokens
gated on proof of mailbox control. No account, no password, no OAuth — the
user proves "I can use this mailbox" once, mints a reusable post-quantum
token on their own device, and spends it at services that never learn who
they are.

Three pieces:

| Piece | What it is | Where |
| --- | --- | --- |
| `issuerd` | Networked issuer: HTTP API, pluggable email ingress, mint budgets keyed on a mailbox HMAC | [`services/issuerd`](../../services/issuerd) |
| `imagehost` | Demo consumer: anonymous image host that verifies tokens with the issuer's public key only | [`imagehost/`](imagehost) |
| `enroll` | Android library: `EnrollClient` + Compose `EnrollOverlay`, plus a demo app | [`android/`](android) |

## Who learns what

The point of the split is that you can audit each party's knowledge:

| Party | Learns | Never learns |
| --- | --- | --- |
| Issuer (`issuerd`) | HMAC bucket of the mailbox (rate limiting), holder public key | The minted token's pseudonyms at any consumer |
| Consumer (`imagehost`) | Origin-bound pseudonym per upload | The email address, the issuer's budget bucket, pseudonyms at other origins |
| Network observer | That some mailbox enrolled | Which token or pseudonym came out of it |

The plaintext address exists in issuerd's memory exactly long enough to
compute `HMAC(gate_key, canonical_address)`, then is dropped. The token is a
blinded PoMFRIT/MAYO (post-quantum) signature over a keypair generated on
the user's device; there is no address field to leak.

> Honest caveat: issuerd currently performs *assisted* minting — it blinds
> the input server-side, so a malicious issuer that logged everything could
> link a bucket to a token at mint time. Client-side blinding removes even
> that; the wire format already supports it.

## Quickstart (no mail server required)

```sh
cd examples/mailproof
docker compose up --build
```

Then walk the whole flow from a shell:

```sh
# 1. Start a session. Dev mode, "send" direction.
curl -s localhost:8788/v1/sessions -d '{"mode":"send"}'
# -> {"session_id":"S","verify_address":"verify+S@issuer.local",...}

# 2. Simulate the verification email (dev mode skips DKIM).
curl -s localhost:8788/v1/ingress/webhook --data-binary $'From: you@example.org\r\nTo: verify+S@issuer.local\r\n\r\nhi\r\n'

# 3. Mint. Generate an Ed25519 keypair and send ONLY the public key.
curl -s localhost:8788/v1/sessions/S/mint -d '{"holder_pub_b64":"<32 bytes, base64url>"}'
# -> {"token_b64":"...", ...}

# 4. Spend at the consumer: get a nonce, sign a presentation, upload.
curl -s localhost:8789/v1/challenges -X POST
curl -s localhost:8789/v1/images -d '{"token_b64":"...","nonce_b64":"...","issued_at":...,"signature_b64":"...","image_b64":"..."}'
# -> {"url":"/i/<id>","pseudonym_hex":"..."}   <- all the host ever knows
```

The Android demo app does steps 1–4 with real UI: `cd android && ./gradlew
:demo:assembleDebug`, install on an emulator, and the compose points at
`10.0.2.2:8788/8789` out of the box.

## Two proof directions

**Send direction (default).** The user emails
`verify+<session>@your-domain` from the mailbox they're proving. In
production issuerd believes the sender only if the message has a DKIM
signature aligned with the From domain — the same alignment rule DMARC
uses. The verification mail sits in the user's own Sent folder afterwards,
which is a feature: the entire disclosure is user-auditable.

**Code direction.** The issuer emails a 6-digit code
(`mailbox.ChallengeStore` semantics: 10-minute TTL, 3 attempts, single
use), the user echoes it back. Needs an outbound relay
(`-relay smtp.example:587 -relay-user … -relay-pass …`) but zero inbound
mail handling.

## Ingress adapters (send direction)

`issuerd` accepts raw RFC822 through one funnel, fed three ways:

1. **Embedded SMTP listener** — `-smtp :25` and an MX record pointing at
   the box. No MTA needed at all.
2. **MTA pipe** — your existing MTA pipes the message to
   `issuerd deliver`. opensmtpd example:

   ```
   action "verify" mda "/usr/local/bin/issuerd deliver --url http://127.0.0.1:8788 --secret-file /etc/issuerd/webhook.secret" user issuerd
   match from any for rcpt-to regex "^verify\+.*" action "verify"
   ```

3. **HTTPS webhook** — `POST /v1/ingress/webhook` with
   `X-Issuerd-Secret`. Works with Cloudflare Email Routing (a Worker
   forwards the raw message), Mailgun routes, or SendGrid inbound parse
   with "raw MIME" checked.

## Interop

The mailbox gate (canonicalization, HMAC bucket derivation, code length and
attempt limits) is wire-compatible with the eat-pass reference and aligned
with the IETF email-verification-protocol draft's goals: prove mailbox
control without turning the address into a tracking key.
