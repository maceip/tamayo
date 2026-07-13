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
          'The server (and anyone reading its logs) held every user’s private key, so it could impersonate any of them. That isn’t a private identity; it’s an account the server controls.',
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
          'A spammer just sends a new random bucket ID with every request and gets a fresh 32-mint allowance each time. Meanwhile everyone who kept the default shared one bucket, so a single heavy user could exhaust it for the rest.',
      },
      {
        label: 'fix',
        text:
          'Our first fix was one global bucket. That stopped the spam trick but made the starvation worse: now one client could drain the allowance for the entire deployment.',
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
          'The gateway now derives the bucket itself: in dev, a salted hash of the connection source; in production, a keyed HMAC of the mailbox the user actually logged into. The address never appears in tokens or logs.',
      },
      {
        label: 'fix',
        text:
          'A heavy user can only exhaust their own quota, and the client no longer supplies any value the rate limiter depends on.',
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
    note: 'proof the client holds the key; each nonce works once',
  },
  {
    expr: 'PUT bound to (sha256, length, type)',
    note: 'the presigned upload only accepts the declared bytes',
  },
  {
    expr: 'email = ∅',
    note: 'no address is collected, so there is nothing to leak',
  },
];

export const caseLesson =
  'Both bugs came down to letting the client pick a value the server needed to control: its own private key custody in v1, its own rate-limit bucket in v2. Since then, tokenauth refuses to compile a production policy that leaves the budget bucket up to the caller unless the policy opts in explicitly.';
