export type StoryStep = {
  scene: string;
  title: string;
  body: string;
  tags: string[];
  pass: string;
};

export const steps: StoryStep[] = [
  {
    scene: 'ask',
    title: 'Send $40. Message three people.',
    body: 'You ask an agent to move your own money and message real contacts. Completely ordinary work.',
    tags: ['PayPal', 'LinkedIn', 'your account'],
    pass: 'one task',
  },
  {
    scene: 'surfaces',
    title: 'The agent is not on one screen.',
    body: 'It runs across your laptop, phone, tablet, and a cloud browser. One person, many sessions, and now a machine doing the clicking.',
    tags: ['laptop', 'phone', 'tablet', 'cloud browser'],
    pass: 'many surfaces',
  },
  {
    scene: 'flood',
    title: 'Every surface asks for proof.',
    body: 'SMS codes, passkeys, email links, “new device” warnings — all for a task you already approved once.',
    tags: ['SMS code', 'passkey', 'email link', 'new device'],
    pass: 'same user',
  },
  {
    scene: 'refuse',
    title: 'PayPal and LinkedIn see a bot.',
    body: 'From the outside, your agent is indistinguishable from fraud, spam, scraping, or a stolen session, so it gets blocked.',
    tags: ['fraud', 'spam', 'scraping', 'stolen session'],
    pass: 'no usable evidence',
  },
  {
    scene: 'blunt',
    title: 'The current options are bad.',
    body: 'Give the agent your password, grant it a huge OAuth scope, let its browser get blocked, or sit through another round of challenges yourself.',
    tags: ['password', 'broad OAuth', 'blocked browser'],
    pass: 'all-or-nothing',
  },
  {
    scene: 'pass',
    title: 'A limited pass is enough.',
    body: 'A trusted issuer checks a rule and signs a token. The agent presents it, the service verifies it, and nobody had to create an account.',
    tags: ['checked rule', 'narrow pass', 'verify once'],
    pass: 'this action only',
  },
];
