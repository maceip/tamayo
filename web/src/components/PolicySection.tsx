import { For, type JSX } from 'solid-js';

const CEDAR = 'https://www.cedarpolicy.com/';
const CEDAR_GH = 'https://github.com/cedar-policy/cedar';
const SIGBIRD_POLICY =
  'https://github.com/maceip/SigBird/blob/main/services/signature-image-gateway/policy.dev.json';

/** Inline annotation: wavy red for a footgun, green underline for a guardrail. */
function Bad(props: { n: number; children: JSX.Element }) {
  return (
    <mark class="pol-bad">
      {props.children}
      <sup>{props.n}</sup>
    </mark>
  );
}

function Good(props: { n: number; children: JSX.Element }) {
  return (
    <mark class="pol-good">
      {props.children}
      <sup>{props.n}</sup>
    </mark>
  );
}

const IAM_NOTES = [
  'Wildcard principal: every future role matching agent-* silently inherits this grant.',
  's3:* is about a hundred actions today plus whatever ships next quarter, and AssumeRole lets the agent pivot into other roles.',
  'Every bucket and object in the account.',
  'The caller writes its own User-Agent header, so an attacker just opts out. Same bug class SigBird shipped (below).',
  'Matches the whole internet while reading like a restriction.',
];

const TA_NOTES = [
  'Production mode: a policy that accepts dev-grade evidence stops compiling.',
  'Every authorization expires on its own in two minutes.',
  'No runtime attestation, no mint.',
  'The server derives the rate-limit bucket from the authenticated caller. A request cannot name its own.',
  'Only the binary with this measurement can mint burn tokens.',
  '16 mints per bucket per hour, then deny.',
];

const SB_NOTES = [
  'The dev file. Production swaps this gate for a keyed HMAC of the mailbox the user logged into, so the budget follows the account without revealing the address.',
  'Legal only because mode is development; the same line under production is a compile error.',
  '32 mints per hour per bucket, where the bucket is a salted hash of the connection source that the gateway derives itself.',
];

export function PolicySection() {
  return (
    <section class="section" id="policy">
      <div class="section-head">
        <h2>Simplicity scaled: a policy engine born out of Cedar</h2>
        <p>
          <a href={CEDAR} target="_blank" rel="noreferrer">Cedar</a> showed that authorization
          policy works best as a small, analyzable language: deny by default, validated before it
          runs, short enough to read in review (
          <a href={CEDAR_GH} target="_blank" rel="noreferrer">cedar-policy on GitHub</a>).{' '}
          <code>tokenauth</code> applies that discipline to mint decisions. A policy is one JSON
          file that compiles or doesn't, and the compiler treats weak evidence as an error rather
          than a warning.
        </p>
      </div>

      <div class="pol-compare t-stagger">
        <article class="pol-panel bb t-card-resize">
          <h3 class="pol-title bad-side">How cloud IAM says "let the agent work"</h3>
          <pre class="pol-code"><code>{'{\n  "Version": "2012-10-17",\n  "Statement": [{\n    "Sid": "LetTheAgentsWork",\n    "Effect": "Allow",\n    "Principal": { "AWS":\n      '}<Bad n={1}>{'"arn:aws:iam::123456789012:role/agent-*"'}</Bad>{' },\n    "Action": ['}<Bad n={2}>{'"s3:*"'}</Bad>{', "ses:SendEmail",\n               '}<Bad n={2}>{'"sts:AssumeRole"'}</Bad>{'],\n    "Resource": '}<Bad n={3}>{'"*"'}</Bad>{',\n    "Condition": {\n      "StringLike": { '}<Bad n={4}>{'"aws:UserAgent": "*MyAgent*"'}</Bad>{' },\n      "IpAddress": { '}<Bad n={5}>{'"aws:SourceIp": "0.0.0.0/0"'}</Bad>{' }\n    }\n  }]\n}'}</code></pre>
          <ol class="pol-legend bad">
            <For each={IAM_NOTES}>{(note) => <li>{note}</li>}</For>
          </ol>
          <p class="pol-coda">
            Contrived, but every line is something that ships. Nothing expires, nothing is
            budgeted, and this Allow quietly merges with every other statement in the account.
          </p>
        </article>

        <article class="pol-panel bb t-card-resize">
          <h3 class="pol-title good-side">The same intent in tokenauth</h3>
          <pre class="pol-code"><code>{'{\n  "version": 1,\n  '}<Good n={1}>{'"mode": "production"'}</Good>{',\n  "defaults": { "max_batch": 8,\n                '}<Good n={2}>{'"authorization_ttl_seconds": 120'}</Good>{' },\n  "token_families": {\n    "burn": {\n      "enabled": true,\n      "allowed_gates": ["tee"],\n      "budget_group": "burn",\n      '}<Good n={3}>{'"requires_attestation": true'}</Good>{'\n    }\n  },\n  "gates": { "tee": { "enabled": true,\n             '}<Good n={4}>{'"bucket_source": "caller"'}</Good>{' } },\n  "measurements": [{\n    '}<Good n={5}>{'"value_x": "a7f3…be12"'}</Good>{', "allow": ["burn"]\n  }],\n  "budgets": {\n    "burn": '}<Good n={6}>{'{ "limit": 16, "window_seconds": 3600 }'}</Good>{'\n  }\n}'}</code></pre>
          <ol class="pol-legend good">
            <For each={TA_NOTES}>{(note) => <li>{note}</li>}</For>
          </ol>
          <p class="pol-coda">
            Anything not named here is denied. The whole file is the review surface.
          </p>
        </article>
      </div>

      <div class="pol-panel pol-real bb t-stagger">
        <h3 class="pol-title">
          The real one:{' '}
          <a href={SIGBIRD_POLICY} target="_blank" rel="noreferrer">
            SigBird's gateway policy
          </a>
        </h3>
        <div class="pol-real-grid">
          <pre class="pol-code"><code>{'{\n  "version": 1,\n  '}<Good n={1}>{'"mode": "development"'}</Good>{',\n  "defaults": {\n    '}<Good n={2}>{'"allow_software_witness": true'}</Good>{',\n    "max_batch": 8,\n    "authorization_ttl_seconds": 120\n  },\n  "token_families": {\n    "private_identity": {\n      "enabled": true,\n      "allowed_gates": ["tee"],\n      "budget_group": "private",\n      "requires_attestation": true\n    }\n  },\n  "gates": { "tee": { "enabled": true } },\n  "measurements": [\n    { "value_x": "dev-measurement",\n      "allow": ["private_identity"] }\n  ],\n  "budgets": {\n    "private": '}<Good n={3}>{'{ "limit": 32,\n                 "window_seconds": 3600 }'}</Good>{'\n  }\n}'}</code></pre>
          <ol class="pol-legend good">
            <For each={SB_NOTES}>{(note) => <li>{note}</li>}</For>
          </ol>
        </div>
      </div>
    </section>
  );
}
