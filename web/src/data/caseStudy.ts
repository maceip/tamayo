export type CaseSegment = {
  label: 'model' | 'broke' | 'fix';
  text: string;
};

export type CaseIteration = {
  version: string;
  verdict: 'broken' | 'shipped';
  title: string;
  diagram: string[];
  segments: CaseSegment[];
};

/**
 * SigBird post-mortem: we pointed a coding model at "add best-in-class
 * authorization to free signature-image hosting" and it shipped compiling,
 * plausible, wrong code twice before the design was right.
 */
export const caseIterations: CaseIteration[] = [
  {
    version: 'attempt 1',
    verdict: 'broken',
    title: 'It generated your key on the server',
    diagram: [
      'app ──── mint request ────▶ gateway',
      '                            (sk, pk) ← KeyGen()',
      'app ◀─── { token, sk } ──── gateway',
      '',
      '✗ every private key crossed the wire',
      '✗ server (and its logs) can impersonate anyone',
    ],
    segments: [
      {
        label: 'model',
        text:
          'One round trip, no client-side crypto: the gateway generated the holder keypair and mailed the seed back with the token. The demo worked and nothing in the test suite objected.',
      },
      {
        label: 'broke',
        text:
          'A private identity where the server holds every private key is an account the server controls. Anyone with the gateway\u2019s logs could present as any user.',
      },
      {
        label: 'fix',
        text:
          'Keys are generated on-device. Only the public key crosses the wire, and the gateway rejects any mint that doesn\u2019t bring one.',
      },
    ],
  },
  {
    version: 'attempt 2',
    verdict: 'broken',
    title: 'It let the client name its own rate limit',
    diagram: [
      'mints(bucket) ≤ 32 / hour',
      'bucket = request.bucket_id',
      '',
      'spammer:  bucket = rand()  → fresh 32 every call',
      'everyone else: default bucket → one heavy user',
      '                               starves the rest',
    ],
    segments: [
      {
        label: 'model',
        text:
          'A mint budget of 32 per hour per bucket, which sounds right until you notice the bucket ID came from the request body.',
      },
      {
        label: 'broke',
        text:
          'A spammer sends a new random bucket with every request and never hits the limit. Honest clients shared the default bucket, so one heavy user exhausted it for everyone else.',
      },
      {
        label: 'fix',
        text:
          'The obvious patch — one global bucket — stopped the spam trick and made starvation worse: now a single client could drain the whole deployment\u2019s allowance.',
      },
    ],
  },
  {
    version: 'attempt 3',
    verdict: 'shipped',
    title: 'The server names the identifier',
    diagram: [
      'dev:  bucket = H(salt ‖ source)',
      'prod: bucket = HMAC(k, mailbox)',
      '      // address never revealed',
      'mints(bucket, 1h) ≤ limit',
    ],
    segments: [
      {
        label: 'fix',
        text:
          'The gateway derives the bucket itself: a salted hash of the connection source in dev, a keyed HMAC of the mailbox the user actually logged into in production. The address never appears in tokens or logs, a heavy user only exhausts their own quota, and the client no longer supplies any value the rate limiter depends on.',
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
  'Both wrong versions passed tests and looked reasonable in review, which is the problem: authorization bugs like these only show up when someone attacks the design. Both came down to the client picking a value the server needed to control (key custody in attempt 1, the rate-limit bucket in attempt 2). tokenauth now refuses to compile a production policy that leaves the budget bucket up to the caller, so the next model that tries this gets stopped at build time.';
