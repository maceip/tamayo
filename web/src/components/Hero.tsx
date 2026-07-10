import { For, onCleanup, onMount } from 'solid-js';
import { startHeroAuthorizationSequence } from '../lib/heroAuthorization';
import { startPlanetParallax } from '../lib/heroParallax';

const PLANETS = [
  { tone: 'finance', title: 'money', sub: 'PayPal task' },
  { tone: 'identity', title: 'identity', sub: 'LinkedIn task' },
  { tone: 'device', title: 'device cloud', sub: 'phone, laptop, tablet, agent' },
  { tone: 'challenge', title: 'challenge', sub: 'security prompt' },
] as const;

function randomPlanetScale(): number {
  // Inclusive [1, 2] — never smaller than current, up to 2×.
  return 1 + Math.random();
}

export function Hero(props: { scale?: number }) {
  let heroEl!: HTMLElement;
  let orbitField!: HTMLDivElement;

  onMount(() => {
    orbitField.querySelectorAll<HTMLElement>('.auth-planet').forEach((el) => {
      const s = randomPlanetScale();
      el.style.setProperty('--planet-scale', String(s));
    });

    const stopAuth = startHeroAuthorizationSequence(orbitField);
    const stopParallax = startPlanetParallax(heroEl, orbitField);
    onCleanup(() => {
      stopAuth();
      stopParallax();
    });
  });

  // Avoid transform:scale(1) — a no-op transform still creates a containing block / layer cost.
  const scaleStyle = () => {
    const s = props.scale;
    if (s == null || Math.abs(s - 1) < 0.001) return undefined;
    return { transform: `scale(${s})`, 'transform-origin': 'top center' };
  };

  return (
    <header class="hero" ref={heroEl} style={scaleStyle()}>
      <div class="hero-scene" aria-label="Authorization request animation">
        <div class="hero-line one" />
        <div class="hero-line two" />
        <div class="hero-line three" />
        <div class="flow-cell c1" />
        <div class="flow-cell c2" />
        <div class="flow-cell c3" />
        <div class="flow-cell c4" />
        <div class="flow-cell c5" />
        <div class="hero-orbit-field" ref={orbitField}>
          <div class="auth-launcher" />
          <For each={[...PLANETS]}>
            {(p) => (
              <div class={`auth-planet ${p.tone}`}>
                <div class="auth-planet-body" aria-hidden="true" />
                <div class="auth-planet-label">
                  <strong>{p.title}</strong>
                  <span>{p.sub}</span>
                </div>
              </div>
            )}
          </For>
        </div>
      </div>
      <div class="hero-copy">
        <h1 data-testid="tamayo-hero-title">Universal Authorization</h1>
        <p>
          Checked facts become narrow passes — enough for a service to accept one approved action,
          without minting a tracking handle.
        </p>
        <div class="hero-actions">
          <a class="button bb-pulse" href="#tamago">TamaGo</a>
          <a class="button secondary bb-line" href="#passes">Token types</a>
        </div>
      </div>
    </header>
  );
}
