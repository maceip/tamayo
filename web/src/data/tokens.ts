export type TokenCard = {
  /** Wire name — the string that appears in policy files and log lines. */
  family: string;
  /** Technical display name. */
  name: string;
  /** What it is built on. */
  stack: string;
  plain: string;
  learns: string;
  hidden: string;
  issuer: string;
  model: string;
  summary: string;
  note: string;
  tone: 'green' | 'cyan' | 'amber' | 'violet';
};

export const tokens: TokenCard[] = [
  {
    family: 'burn',
    name: 'Burn token',
    stack: 'PoMFRIT one-more-MAYO blind signature',
    plain: 'Let this request through once, within a budget.',
    learns: 'allowed once',
    hidden: 'stable identity',
    issuer: 'budget and policy result',
    model: 'drink ticket',
    summary: 'Single-use anonymous credential, rate-limited by issuer policy.',
    note: 'Spent at presentation: the verifier records the nonce, so a second use of the same token fails the replay check.',
    tone: 'green',
  },
  {
    family: 'private_identity',
    name: 'Private-identity token',
    stack: 'blind issuance + origin-bound pseudonym + holder proof-of-possession',
    plain: 'Remember me here, not everywhere.',
    learns: 'same visitor at this site',
    hidden: 'email and cross-site identity',
    issuer: 'token family and policy result',
    model: 'venue wristband',
    summary: 'nym = H(origin ‖ token): continuity at one site, unlinkable across sites.',
    note: 'Use this when you want returning visitors but don’t need their email. <a href="#sigbird">SigBird</a> uses it to gate free signature-image hosting.',
    tone: 'cyan',
  },
  {
    family: 'policy_email',
    name: 'Policy-bound email JWT',
    stack: 'email JWT + KB-JWT presentation; ML-DSA-44 PQ profile',
    plain: 'Show my email when the service really needs it.',
    learns: 'email and issuance context',
    hidden: 'unneeded account history',
    issuer: 'email proof plus required gate',
    model: 'checked badge',
    summary: 'Address-bearing proof where issuance can require policy or runtime evidence.',
    note: 'This is for services that need the address and also need an issuer-side policy check.',
    tone: 'amber',
  },
  {
    family: 'evt',
    name: 'Email Verification Token (EVT)',
    stack: 'draft-hardt-email-verification interop',
    plain: 'Interop with the IETF email-verification draft.',
    learns: 'verified email address',
    hidden: 'private-token machinery',
    issuer: 'email session and browser key',
    model: 'email receipt',
    summary: 'Compatibility with the Email Verification Token flow.',
    note: 'EVT means Email Verification Token; see the current IETF draft: <a href="https://datatracker.ietf.org/doc/html/draft-hardt-email-verification-01">draft-hardt-email-verification</a>.',
    tone: 'violet',
  },
];
