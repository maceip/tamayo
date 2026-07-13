import { For } from 'solid-js';
import { caseIterations, caseLesson, wireMath } from '../data/caseStudy';

const SEGMENT_TITLES = { model: 'What the model built', broke: 'Broke', fix: 'Fix' } as const;
const SIGBIRD_PR = 'https://github.com/maceip/SigBird/pull/17';
const SIGBIRD = 'https://github.com/maceip/SigBird';

export function CaseStudy() {
  return (
    <section class="section" id="sigbird">
      <div class="section-head">
        <h2>You can't vibe code authorization. We tried.</h2>
        <p>
          Like everyone else on the planet we are vibe-code replacing all our systems. When the
          email client (<a href={SIGBIRD} target="_blank" rel="noreferrer">SigBird</a>) was done,
          we wanted best-in-class authorization on its free signature-image hosting, so we set
          GPT 5.6 Sol MAX on the case. This is what happened.
        </p>
      </div>

      <div class="case-grid t-stagger">
        <For each={caseIterations}>
          {(step) => (
            <article class={`case-card bb-pulse t-card-resize ${step.verdict}`}>
              <div class="case-meta">
                <span class="case-version">{step.version}</span>
                <span class={`case-verdict ${step.verdict}`}>
                  {step.verdict === 'broken' ? 'broken' : 'shipped'}
                </span>
              </div>
              <h3>{step.title}</h3>
              <pre class="case-math"><code>{step.diagram.join('\n')}</code></pre>
              <For each={step.segments}>
                {(seg) => (
                  <p class={`case-seg ${seg.label}`}>
                    <b>{SEGMENT_TITLES[seg.label]}</b> {seg.text}
                  </p>
                )}
              </For>
            </article>
          )}
        </For>
      </div>

      <div class="case-wire bb t-stagger">
        <h3>What crosses the wire now</h3>
        <For each={wireMath}>
          {(row) => (
            <div class="case-wire-row">
              <code>{row.expr}</code>
              <span>{row.note}</span>
            </div>
          )}
        </For>
      </div>

      <p class="case-lesson">
        {caseLesson}{' '}
        <a href={SIGBIRD_PR} target="_blank" rel="noreferrer">Read the fix PR →</a>
      </p>
    </section>
  );
}
