import { onCleanup, onMount } from 'solid-js';
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
  let logEl!: HTMLDivElement;

  onMount(() => {
    const stopAuth = startHeroAuthorizationSequence(orbitField, logEl);
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
          {/* Static list — plain map, no <For> bookkeeping. Scale is set at render
              instead of a querySelectorAll pass after mount. */}
          {PLANETS.map((p) => (
            <div
              class={`auth-planet ${p.tone}`}
              style={{ '--planet-scale': randomPlanetScale().toFixed(3) }}
            >
              <div class="auth-planet-body" aria-hidden="true" />
              <div class="auth-planet-label">
                <strong>{p.title}</strong>
                <span>{p.sub}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div class="hero-copy">
        <h1 data-testid="tamayo-hero-title">Universal Authorization</h1>
        <p>
          An issuer checks a rule once and signs a token good for one action. The service verifies
          the token without learning who you are or creating an account.
        </p>
        <div class="hero-actions">
          <a class="button bb-pulse" href="#tamago">TamaGo</a>
          <a class="button secondary bb-line" href="#passes">Token types</a>
        </div>
      </div>
      <aside class="hero-tui" aria-label="Simulated authorization log">
        <div class="hero-tui-bar">
          <span class="hero-tui-title">tamayo/authorization-log</span>
          <span class="hero-tui-live" aria-hidden="true">live</span>
        </div>
        <div class="hero-tui-row hero-tui-cols" aria-hidden="true">
          <span>time</span>
          <span>client</span>
          <span>token</span>
          <span>audience</span>
          <span>desk</span>
          <span>score</span>
          <span>status</span>
        </div>
        <div class="hero-tui-rows" ref={logEl} />
      </aside>
    </header>
  );
}
