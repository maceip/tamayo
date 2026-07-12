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
          'Assisted mint generated the holder keypair server-side and returned the seed to the app. Convenient: one round trip, no client crypto.',
      },
      {
        label: 'broke',
        text:
          'Whoever runs (or logs) the gateway holds every holder key. Sign(sk, ·) proves possession — of a key the server also possesses. A “private identity” whose private key the server minted is just an account you don’t control.',
      },
      {
        label: 'fix',
        text:
          'Keys are generated on-device. Only holder_pub_b64 crosses the wire; the gateway rejects mints without it and never returns key material.',
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
          'A mint budget: 32 per hour per bucket. But the bucket ID came from the request body — the client named its own rate-limit key.',
      },
      {
        label: 'broke',
        text:
          'A spammer sends a fresh random bucket per request, so every request gets a fresh 32-mint allowance. The effective limit is 32 × ∞. A rate limit the client can rename is decoration.',
      },
      {
        label: 'fix',
        text:
          'First attempt: one global bucket. New failure — a single greedy client drains the whole allowance and every honest client starves. Swapped a spam hole for a denial of service.',
      },
    ],
  },
  {
    version: 'v3',
    verdict: 'shipped',
    title: 'The server names the identifier',
    math: [
      'bucket = H(salt ‖ source)   // server-derived, salted',
      'mints(bucket, 1h) ≤ limit; sessions(bucket) ≤ cap',
    ],
    segments: [
      {
        label: 'built',
        text:
          'The gateway derives the budget key from the connection source with a per-boot salt. Budgets and open-session caps are per source; a global session ceiling backstops the map.',
      },
      {
        label: 'fix',
        text:
          'A greedy source exhausts only its own quota. Nobody else stalls, logs never store a raw IP, and the client no longer supplies any value the rate limiter depends on.',
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
  'Both bugs were the same bug: the client got to name a value the protocol needed the other side to control. Key custody belongs to the holder; budget identifiers belong to the issuer. Who names an identifier decides what it protects.';
