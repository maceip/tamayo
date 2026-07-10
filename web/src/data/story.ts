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
    body: 'You ask an agent to move your own money and message real contacts. Ordinary work — not a breach.',
    tags: ['PayPal', 'LinkedIn', 'your account'],
    pass: 'one task',
  },
  {
    scene: 'surfaces',
    title: 'The agent is not on one screen.',
    body: 'Laptop, phone, tablet, cloud browser. Same person, many sessions — and now a machine running the clicks.',
    tags: ['laptop', 'phone', 'tablet', 'cloud browser'],
    pass: 'many surfaces',
  },
  {
    scene: 'flood',
    title: 'Every surface asks for proof.',
    body: 'SMS codes, passkeys, email links, “new device” warnings. The task is still yours; the prompts are not.',
    tags: ['SMS code', 'passkey', 'email link', 'new device'],
    pass: 'same user',
  },
  {
    scene: 'refuse',
    title: 'PayPal and LinkedIn see a bot.',
    body: 'From the outside, a helpful agent looks like fraud, spam, scraping, or a stolen session. They block what they cannot measure.',
    tags: ['fraud', 'spam', 'scraping', 'stolen session'],
    pass: 'no usable evidence',
  },
  {
    scene: 'blunt',
    title: 'Today you overshare or you stall.',
    body: 'Hand the agent a password, grant a fat OAuth scope, drive a browser that gets blocked, or send yourself through another challenge loop.',
    tags: ['password', 'broad OAuth', 'blocked browser'],
    pass: 'all-or-nothing',
  },
  {
    scene: 'pass',
    title: 'A limited pass is enough.',
    body: 'Something trusted checks a rule. The agent presents a narrow pass. The service verifies that fact — not a new account handle.',
    tags: ['checked rule', 'narrow pass', 'verify once'],
    pass: 'this action only',
  },
];
