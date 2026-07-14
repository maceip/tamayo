# issuerd — the mailproof reference issuer

A networked tamayo issuer gated on proof of mailbox control. Users prove "I
can use this mailbox" (by sending an email, or by echoing a code), then mint
a private-identity token whose holder key never leaves their device. The
issuer keeps only an HMAC bucket of the address for rate limiting — the
plaintext is dropped the moment the bucket is computed.

Full walkthrough, privacy table, and demo consumer:
[`examples/mailproof`](../../examples/mailproof).

## Run

```sh
go run . -dev                       # HTTP :8788, webhook ingress open, codes print to stderr
go run . -smtp :2525 -domain x.test # plus embedded SMTP ingress
go run . -policy policy.json -seed-file /var/lib/issuerd/seed \
  -webhook-secret "$(cat /etc/issuerd/webhook.secret)" -domain example.org  # production-ish
```

## HTTP surface

| Method and path | What it does |
| --- | --- |
| `GET /v1/issuer` | Algorithm, key version, compact public key (consumers pin this) |
| `POST /v1/sessions` | Start a session; `{"mode":"send"}` or `{"mode":"code"}` |
| `GET /v1/sessions/{id}` | Poll status: `pending` or `verified` |
| `POST /v1/sessions/{id}/send-code` | Code direction: email a 6-digit code to `{"email":...}` |
| `POST /v1/sessions/{id}/verify-code` | Code direction: `{"email":...,"code":...}` |
| `POST /v1/sessions/{id}/mint` | Assisted mint for a verified session: `{"holder_pub_b64":...}` |
| `POST /v1/ingress/webhook` | Raw RFC822 in, `X-Issuerd-Secret` header required outside dev |

## Email ingress (send direction)

Three adapters feed one funnel; sender identity is only believed with a
DKIM signature aligned to the From domain (skipped in `-dev`):

- embedded SMTP listener (`-smtp :25` + an MX record),
- MTA pipe: `issuerd deliver --url ... --secret-file ...` (opensmtpd `mda`),
- HTTPS webhook (Cloudflare Email Routing worker, Mailgun route, etc.).
