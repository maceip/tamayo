export type CaseSegment = {
  label: 'built' | 'broke' | 'fix';
  text: string;
};

export type CaseIteration = {
  version: string;
  verdict: 'broken' | 'shipped';
  title: string;
  math: string[];
  segments: CaseSegment[];
};

/**
 * SigBird case study: free image hosting for email signatures, gated by a
 * tamayo private-identity token. Told honestly — including the two versions
 * that were wrong and why.
 */
export const caseIterations: CaseIteration[] = [
  {
    version: 'v1',
    verdict: 'broken',
    title: 'The gateway made your key',
    math: [
      'gateway: (sk, pk) ← KeyGen()',
      'reply { token, sk }   // seed crossed the wire',
    ],
    segments: [
      {
        label: 'built',
        text:
          'Assisted mint generated the holder keypair server-side and returned the seed to the app. One round trip, no client crypto.',
      },
      {
        label: 'broke',
        text:
          'Whoever runs or logs the gateway holds every holder key — a “private identity” whose private key the server minted is just an account you don’t control.',
      },
      {
        label: 'fix',
        text:
          'Keys are generated on-device. Only the public key crosses the wire; the gateway rejects mints without it and never returns key material.',
      },
    ],
  },
  {
    version: 'v2',
    verdict: 'broken',
    title: 'The client named its own budget',
    math: [
      'mints(bucket) ≤ 32 / hour',
      'bucket = request.bucket_id   // attacker: bucket = rand()',
    ],
    segments: [
      {
        label: 'built',
        text:
          'A mint budget of 32 per hour per bucket — but the bucket ID came from the request body. The client named its own rate-limit key.',
      },
      {
        label: 'broke',
        text:
          'A spammer names a fresh bucket per request: 32 × ∞. Clients that keep the default share one bucket, so one greedy client starves the rest. Both failures at once.',
      },
      {
        label: 'fix',
        text:
          'A single global bucket fixes the spam and keeps the starvation — one client can still drain everyone’s allowance. The bucket has to belong to someone.',
      },
    ],
  },
  {
    version: 'v3',
    verdict: 'shipped',
    title: 'The server names the identifier',
    math: [
      'dev:  bucket = H(salt ‖ source)',
      'prod: bucket = HMAC(k, mailbox)   // address never revealed',
      'mints(bucket, 1h) ≤ limit',
    ],
    segments: [
      {
        label: 'built',
        text:
          'The gateway derives the budget key from the connection source with a per-boot salt; budgets and session caps are per source. In production the bucket is a keyed HMAC of the authenticated mailbox — the user’s own account is the budget identity, without revealing the address.',
      },
      {
        label: 'fix',
        text:
          'A greedy source exhausts only its own quota, and the client no longer supplies any value the rate limiter depends on.',
      },
    ],
  },
];

/** What actually crosses the wire once the design is right. */
export const wireMath: { expr: string; note: string }[] = [
  {
    expr: 'nym = H(origin ‖ token)',
    note: 'same site, same pseudonym — different site, unlinkable',
  },
  {
    expr: 'present = Sign(sk, origin ‖ nonce ‖ issued_at)',
    note: 'holder proof-of-possession; the nonce spends once',
  },
  {
    expr: 'PUT bound to (sha256, length, type)',
    note: 'the presigned upload can only carry the declared bytes',
  },
  {
    expr: 'email = ∅',
    note: 'no address is collected, so none can leak — or be lied about',
  },
];

export const caseLesson =
  'Both bugs were the same bug: the client named a value the other side needed to control. Who names an identifier decides what it protects — key custody belongs to the holder, budget identifiers to the issuer. tokenauth now rejects production policies that leave the budget bucket caller-named without an explicit opt-in.';
