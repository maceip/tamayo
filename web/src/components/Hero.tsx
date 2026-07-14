import { onCleanup, onMount } from 'solid-js';
import { startHeroAuthorizationSequence } from '../lib/heroAuthorization';
import { startPlanetParallax } from '../lib/heroParallax';

const PLANETS = [
  { tone: 'finance', provider: 'paypal', title: 'money', sub: 'PayPal task' },
  { tone: 'identity', provider: 'linkedin', title: 'identity', sub: 'LinkedIn task' },
  { tone: 'device', provider: 'google', title: 'device cloud', sub: 'phone, laptop, tablet, agent' },
  { tone: 'challenge', provider: 'cloudflare', title: 'challenge', sub: 'security prompt' },
] as const;

type PlanetProvider = (typeof PLANETS)[number]['provider'];

function ProviderSymbol(props: { provider: PlanetProvider }) {
  if (props.provider === 'cloudflare') {
    return (
      <svg class="auth-provider-symbol" viewBox="0 0 46 30" aria-hidden="true">
        <path d="M15.1 24.6H39c3.7 0 6.7-2.7 6.7-6.1 0-3.1-2.6-5.7-5.9-6.1a10.3 10.3 0 0 0-19.7-2.3 7.9 7.9 0 0 0-11.7 6.4c0 4.5 3 8.1 6.7 8.1Z" />
        <path class="auth-provider-cloudline" d="M1 27h32.5M6.5 22.2h27.8" />
      </svg>
    );
  }

  return (
    <span class="auth-provider-symbol" aria-hidden="true">
      {props.provider === 'linkedin' ? 'in' : props.provider === 'google' ? 'G' : 'P'}
    </span>
  );
}

function PlanetServiceIdentity(props: { provider: PlanetProvider }) {
  return (
    <div class={`auth-planet-surface-id provider-${props.provider}`} aria-hidden="true">
      <span class="auth-provider-mark">
        <ProviderSymbol provider={props.provider} />
      </span>
    </div>
  );
}

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
    <header class="hero" id="top" ref={heroEl} style={scaleStyle()}>
      <div class="hero-scene" role="group" aria-label="Authorization request animation">
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
              <div class="auth-planet-body" aria-hidden="true">
                <PlanetServiceIdentity provider={p.provider} />
              </div>
              <div class="auth-planet-label">
                <strong>{p.title}</strong>
                <span>{p.sub}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div class="hero-defense-layer" data-authorization-defense-layer />
      <div class="hero-copy">
        <h1 data-testid="tamayo-hero-title">Let your agents fly</h1>
      </div>
      <p class="hero-desc">
        Tamayo is a universal security framework for agents, whether Claude runs in a secure
        enclave with remote attestation or on Betsy's laptop. Every action the agent takes
        presents a signed, single-use pass instead of your identity.
      </p>
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
        <div class="hero-tui-rows" ref={logEl} role="log" aria-live="off" aria-label="Recent authorization decisions" />
      </aside>
      <div class="hero-control-shelf" aria-hidden="true" />
      <div class="hero-actions">
        <a class="push-btn primary" href="#quickstart">
          <span class="push-shadow" aria-hidden="true" />
          <span class="push-edge" aria-hidden="true" />
          <span class="push-front">Quick start</span>
        </a>
        <a class="push-btn secondary" href="#deployments">
          <span class="push-shadow" aria-hidden="true" />
          <span class="push-edge" aria-hidden="true" />
          <span class="push-front">How it's built</span>
        </a>
      </div>
      <span class="sr-only" data-authorization-announcer role="status" aria-live="assertive" aria-atomic="true" />
    </header>
  );
}
