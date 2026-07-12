import { batch, createEffect, createMemo, createSelector, createSignal, For, on, onCleanup, onMount } from 'solid-js';
import { steps } from '../data/story';
import { createPageVisible } from '../lib/media';

export function StoryBoard(props: { autoplay?: boolean }) {
  let sectionEl!: HTMLElement;
  const [index, setIndex] = createSignal(0);
  // `undefined` means "follow the autoplay prop"; a user action overrides it.
  const [userPlaying, setUserPlaying] = createSignal<boolean>();
  // Transient suppressions — they gate the timer without touching user intent.
  const [hovering, setHovering] = createSignal(false);
  const [inView, setInView] = createSignal(false);
  const pageVisible = createPageVisible();

  const playing = () => userPlaying() ?? props.autoplay !== false;
  const running = () => playing() && !hovering() && inView() && pageVisible();
  const step = createMemo(() => steps[index()]!);
  const isActive = createSelector(index);

  // The dial reclaims control whenever it changes; defer skips the mount run.
  createEffect(on(() => props.autoplay, () => setUserPlaying(undefined), { defer: true }));

  onMount(() => {
    const io = new IntersectionObserver(
      ([entry]) => setInView(!!entry?.isIntersecting),
      { threshold: 0.15 },
    );
    io.observe(sectionEl);
    onCleanup(() => io.disconnect());
  });

  const go = (next: number) =>
    batch(() => {
      setIndex(((next % steps.length) + steps.length) % steps.length);
      setUserPlaying(false);
    });

  createEffect(() => {
    if (!running()) return;
    index(); // restart the dwell timer whenever the step changes
    const timer = window.setInterval(() => setIndex((i) => (i + 1) % steps.length), 5200);
    onCleanup(() => window.clearInterval(timer));
  });

  return (
    <section class="section dark" id="movie" ref={sectionEl}>
      <div class="section-head">
        <h2>When an agent acts for you</h2>
        <p>
          A normal request fans out across devices. Services see automation. Tamayo turns a checked
          fact into a pass the agent can present.
        </p>
      </div>

      <div class="story-grid">
        <div
          class="scene-board bb"
          data-scene={step().scene}
          aria-label="Story scene"
          onMouseEnter={() => setHovering(true)}
          onMouseLeave={() => setHovering(false)}
        >
          <svg class="route-svg" viewBox="0 0 720 620" preserveAspectRatio="none" aria-hidden="true">
            <path d="M360 292 C230 220 160 180 112 154" />
            <path d="M360 292 C494 220 564 180 610 154" />
            <path d="M360 448 C360 388 360 344 360 292" />
            <path class="good" d="M360 448 C260 390 190 280 112 154" />
            <path class="good" d="M360 448 C464 390 536 280 610 154" />
          </svg>

          <div class="service paypal">
            <strong>PayPal</strong>
            <span class="service-idle">money movement</span>
            <span class="service-blocked">blocked · looks automated</span>
            <span class="service-ok">accepted · pass verified</span>
          </div>
          <div class="service linkedin">
            <strong>LinkedIn</strong>
            <span class="service-idle">identity · messaging</span>
            <span class="service-blocked">blocked · looks like spam</span>
            <span class="service-ok">accepted · pass verified</span>
          </div>

          <div class="actor">you</div>
          <div class="agent-node">agent</div>

          <div class="device-node laptop"><strong>laptop</strong><span>new session</span></div>
          <div class="device-node phone"><strong>phone</strong><span>push prompt</span></div>
          <div class="device-node tablet"><strong>tablet</strong><span>email code</span></div>
          <div class="device-node cloud"><strong>cloud browser</strong><span>agent run</span></div>

          <div class="prompt-bubble one"><strong>SMS code</strong><span>enter 6 digits</span></div>
          <div class="prompt-bubble two"><strong>Passkey</strong><span>confirm on device</span></div>
          <div class="prompt-bubble three"><strong>Email link</strong><span>open to continue</span></div>
          <div class="prompt-bubble four"><strong>New device</strong><span>was this you?</span></div>

          <div class="risk-note">
            <strong>Looks like automation</strong>
            <span>Fraud, scrapers, and stolen sessions look the same from here.</span>
          </div>

          <div class="blunt-lanes" aria-hidden="true">
            <div class="blunt-lane"><strong>Password</strong><span>hand the keys over</span></div>
            <div class="blunt-lane"><strong>Fat OAuth</strong><span>grant the whole account</span></div>
            <div class="blunt-lane"><strong>Blocked</strong><span>browser automation dies</span></div>
          </div>

          <div class="token-chip">
            <strong>Limited pass</strong>
            <span>{step().pass}</span>
          </div>

          <div class="proof-panel">
            <div><b>Issuer</b><span>checks a rule</span></div>
            <div><b>Holder</b><span>gets the pass</span></div>
            <div><b>Verifier</b><span>sees one fact</span></div>
          </div>
        </div>

        <div class="story-copy">
          <div class="step-count">{index() + 1} / {steps.length}</div>
          <h3>{step().title}</h3>
          <p>{step().body}</p>
          <div class="tag-row">
            <For each={step().tags}>{(tag) => <span class="tag">{tag}</span>}</For>
          </div>
          <div class="story-controls">
            <button class="icon-button" type="button" aria-label="Previous" onClick={() => go(index() - 1)}>
              <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 18l-6-6 6-6" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
            <button class="icon-button" type="button" aria-label="Next" onClick={() => go(index() + 1)}>
              <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </button>
            <button
              class="play-button"
              type="button"
              aria-pressed={playing() ? 'true' : 'false'}
              onClick={() => setUserPlaying(!playing())}
            >
              <span>{playing() ? 'Pause' : 'Play'}</span>
            </button>
          </div>
          <div class="story-progress" aria-hidden="true">
            <span style={{ width: `${((index() + 1) / steps.length) * 100}%` }} />
          </div>
          <div class="dots" aria-label="Story steps">
            <For each={steps}>
              {(_, i) => (
                <button
                  class="dot"
                  type="button"
                  classList={{ active: isActive(i()) }}
                  aria-label={`Step ${i() + 1}`}
                  aria-current={isActive(i()) ? 'step' : 'false'}
                  onClick={() => go(i())}
                />
              )}
            </For>
          </div>
        </div>
      </div>
    </section>
  );
}
