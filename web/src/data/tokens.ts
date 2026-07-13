export type TokenCard = {
  name: string;
  plain: string;
  learns: string;
  hidden: string;
  issuer: string;
  model: string;
  button: string;
  summary: string;
  note: string;
};

export const tokens: TokenCard[] = [
  {
    name: 'Anonymous rate-limited credential',
    plain: 'Let this request through once, within a budget.',
    learns: 'allowed once',
    hidden: 'stable identity',
    issuer: 'budget and policy result',
    model: 'drink ticket',
    button: 'Anonymous rate-limited credential',
    summary: 'One-use access without a stable account handle.',
    note: 'Anonymous, one-use, and rate-limited by issuer policy.',
  },
  {
    name: 'Private identity token',
    plain: 'Remember me here, not everywhere.',
    learns: 'same visitor at this site',
    hidden: 'email and cross-site identity',
    issuer: 'token family and policy result',
    model: 'venue wristband',
    button: 'Private identity token',
    summary: 'A relying-party-bound pseudonym for continuity without an email address.',
    note: 'Use this when you want returning visitors but don’t need their email. <a href="#sigbird">SigBird</a> uses it to gate free signature-image hosting.',
  },
  {
    name: 'Policy-bound email token',
    plain: 'Show my email when the service really needs it.',
    learns: 'email and issuance context',
    hidden: 'unneeded account history',
    issuer: 'email proof plus required gate',
    model: 'checked badge',
    button: 'Policy-bound email token',
    summary: 'Address-bearing email proof where issuance can require policy or runtime evidence.',
    note: 'This is for services that need the address and also need an issuer-side policy check.',
  },
  {
    name: 'EVT email validation token',
    plain: 'Interop with the IETF email-verification draft.',
    learns: 'verified email address',
    hidden: 'private-token machinery',
    issuer: 'email session and browser key',
    model: 'email receipt',
    button: 'EVT email validation token',
    summary: 'Compatibility with the Email Verification Token flow.',
    note: 'EVT means Email Verification Token; see the current IETF draft: <a href="https://datatracker.ietf.org/doc/html/draft-hardt-email-verification-01">draft-hardt-email-verification</a>.',
  },
];
