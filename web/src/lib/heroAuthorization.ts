/** Hero authorization-flight sequence — CubeSat craft with good / failed / malicious outcomes. */

type AuthOutcome = 'good' | 'failed' | 'malicious';

function planetKey(planet: HTMLElement): string {
  return [...planet.classList].find((name) => name !== 'auth-planet') || 'planet';
}

// Departures-board log: one row per launched pass, status resolving in step
// with the flight. This is what makes the scene legible as authorization
// traffic instead of ornament.
const PLANET_LOG: Record<string, { target: string; family: string }> = {
  finance: { target: 'paypal.com', family: 'burn' },
  identity: { target: 'linkedin.com', family: 'private_identity' },
  device: { target: 'cloud-browser', family: 'evt' },
  challenge: { target: 'sso-challenge', family: 'policy_email' },
};

const LOG_STATUS_TEXT: Record<'flight' | AuthOutcome, string> = {
  flight: 'in flight',
  good: 'verified',
  failed: 'failed',
  malicious: 'blocked',
};

const MAX_LOG_ROWS = 6;

function logTime(date: Date): string {
  return date.toTimeString().slice(0, 8);
}

function appendLogRow(
  log: HTMLElement,
  key: string,
  status: 'flight' | AuthOutcome,
  at = new Date(),
): HTMLElement {
  const meta = PLANET_LOG[key] ?? { target: key, family: 'burn' };
  const row = document.createElement('div');
  row.className = 'hero-log-row';
  row.dataset.status = status;
  row.innerHTML = `
    <span class="hero-log-time">${logTime(at)}</span>
    <span class="hero-log-req">${meta.family} → ${meta.target}</span>
    <span class="hero-log-status">${LOG_STATUS_TEXT[status]}</span>
  `;
  while (log.children.length >= MAX_LOG_ROWS) log.firstElementChild?.remove();
  log.appendChild(row);
  return row;
}

function resolveLogRow(row: HTMLElement | null, outcome: AuthOutcome): void {
  if (!row || !row.isConnected) return;
  row.dataset.status = outcome;
  const status = row.querySelector('.hero-log-status');
  if (status) status.textContent = LOG_STATUS_TEXT[outcome];
}

function createSatellite(outcome: AuthOutcome): HTMLButtonElement {
  const satellite = document.createElement('button');
  const classes = ['authorization-satellite', 'is-flying'];
  if (outcome === 'malicious') classes.push('malicious');
  if (outcome === 'failed') classes.push('failed');
  satellite.className = classes.join(' ');
  satellite.type = 'button';

  const labels: Record<AuthOutcome, string> = {
    good: 'Anonymous authorization pass',
    failed: 'Failed authorization pass — missed orbit',
    malicious: 'Blocked anonymous authorization pass',
  };
  satellite.setAttribute('aria-label', labels[outcome]);
  satellite.dataset.authStatus =
    outcome === 'malicious' ? 'blocked' : outcome === 'failed' ? 'failed' : 'anonymous';

  // CubeSat + multi-layer booster flame (flight only; stripped on orbit)
  satellite.innerHTML = `
    <span class="sat-booster" aria-hidden="true">
      <span class="sat-nozzle"></span>
      <span class="sat-flame sat-flame-outer"></span>
      <span class="sat-flame sat-flame-mid"></span>
      <span class="sat-flame sat-flame-core"></span>
      <span class="sat-spark sat-spark-a"></span>
      <span class="sat-spark sat-spark-b"></span>
      <span class="sat-spark sat-spark-c"></span>
    </span>
    <span class="sat-panel sat-panel-left" aria-hidden="true"></span>
    <span class="sat-bus" aria-hidden="true">
      <span class="sat-bay"></span>
      <span class="sat-mast"></span>
      <span class="sat-dish"></span>
    </span>
    <span class="sat-panel sat-panel-right" aria-hidden="true"></span>
  `;
  return satellite;
}

export function startHeroAuthorizationSequence(field: HTMLElement, log?: HTMLElement | null): () => void {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const planets = [...field.querySelectorAll<HTMLElement>('.auth-planet')];

  // Seed the board with settled traffic so it reads as an ongoing log, not
  // an empty widget waiting for the first launch.
  if (log) {
    const now = Date.now();
    ([
      ['identity', 'good', 41_000],
      ['finance', 'good', 27_000],
      ['challenge', 'malicious', 12_000],
    ] as const).forEach(([key, outcome, ago]) => {
      appendLogRow(log, key, outcome, new Date(now - ago));
    });
  }

  if (reduced.matches || planets.length === 0) return () => {};

  const hero = field.closest('.hero') as HTMLElement | null;
  const orbits = new Map<string, HTMLElement>();
  let launchCount = 0;
  let goodCount = 0;
  let failedCount = 0;
  const guaranteedBadLaunch = 4;
  let tooltip: HTMLElement | null = null;
  let tooltipTimer = 0;
  let intervalId = 0;
  let timeoutId = 0;
  let paused = false;

  const stopTimers = () => {
    window.clearTimeout(timeoutId);
    window.clearInterval(intervalId);
    timeoutId = 0;
    intervalId = 0;
  };

  const startTimers = () => {
    if (paused || document.hidden || intervalId) return;
    timeoutId = window.setTimeout(fire, 900);
    intervalId = window.setInterval(fire, 15000);
  };

  const getTooltip = () => {
    if (tooltip) return tooltip;
    tooltip = document.createElement('span');
    tooltip.className = 'authorization-popover';
    tooltip.setAttribute('role', 'tooltip');
    tooltip.innerHTML = `
      <span class="authorization-ticket" aria-hidden="true"></span>
      <span data-auth-tooltip-label>anonymous</span>
      <span class="authorization-status" data-auth-tooltip-status hidden></span>
    `;
    field.appendChild(tooltip);
    return tooltip;
  };

  const showTooltip = (satellite: HTMLElement, sticky = false) => {
    const tip = getTooltip();
    const status = satellite.dataset.authStatus ?? 'anonymous';
    const label = tip.querySelector('[data-auth-tooltip-label]');
    const statusEl = tip.querySelector<HTMLElement>('[data-auth-tooltip-status]');
    if (label) {
      label.textContent =
        status === 'blocked' ? 'blocked' : status === 'failed' ? 'failed' : 'anonymous';
    }
    if (statusEl) {
      statusEl.hidden = status === 'anonymous';
      statusEl.textContent = status === 'blocked' ? 'malicious' : status === 'failed' ? 'missed orbit' : '';
    }
    tip.classList.toggle('is-blocked', status === 'blocked');
    tip.classList.toggle('is-failed', status === 'failed');

    const fieldRect = field.getBoundingClientRect();
    const satRect = satellite.getBoundingClientRect();
    tip.classList.add('is-visible');
    tip.style.top = `${satRect.top - fieldRect.top - 12}px`;
    tip.style.left = `${satRect.left - fieldRect.left + satRect.width / 2}px`;
    window.clearTimeout(tooltipTimer);
    if (sticky) {
      const openDuration = status === 'blocked' || status === 'failed' ? 2600 : 1800;
      tooltipTimer = window.setTimeout(() => tip.classList.remove('is-visible'), openDuration);
    }
  };

  const hideTooltip = () => {
    window.clearTimeout(tooltipTimer);
    tooltipTimer = window.setTimeout(() => tooltip?.classList.remove('is-visible'), 120);
  };

  const getOrbit = (planet: HTMLElement, styles: CSSStyleDeclaration) => {
    const key = planetKey(planet);
    const existing = orbits.get(key);
    if (existing) return existing;
    const orbit = document.createElement('span');
    orbit.className = 'authorization-orbit';
    orbit.dataset.planet = key;
    orbit.style.setProperty('--planet-x', styles.getPropertyValue('--planet-x').trim() || '50vw');
    orbit.style.setProperty('--planet-y', styles.getPropertyValue('--planet-y').trim() || '50svh');
    orbit.style.setProperty('--orbit-size', styles.getPropertyValue('--orbit-size').trim() || '144px');
    field.appendChild(orbit);
    orbits.set(key, orbit);
    return orbit;
  };

  const attachToOrbit = (
    flight: HTMLElement,
    orbit: HTMLElement,
    satellite: HTMLElement,
    key: string,
    count: number,
  ) => {
    const track = document.createElement('span');
    track.className = 'authorization-track';
    track.style.setProperty('--orbit-delay', `${-(count % 8) * 3.7}s`);
    satellite.classList.remove('is-flying');
    satellite.classList.add('is-orbiting');
    satellite.querySelector('.sat-booster')?.remove();
    track.appendChild(satellite);
    orbit.appendChild(track);
    flight.remove();
    window.setTimeout(() => {
      track.remove();
      if (!orbit.querySelector('.authorization-track')) {
        orbit.remove();
        orbits.delete(key);
      }
    }, 43_000);
  };

  const pickOutcome = (): AuthOutcome => {
    const guaranteed = launchCount === guaranteedBadLaunch;
    const dice = !guaranteed && launchCount % 10 === 0 ? Math.floor(Math.random() * 6) + 1 : null;
    if (guaranteed || dice === 6) return 'malicious';

    // Failed at 1/3 the rate of good → 1 failed per 3 good (every 4th non-malicious).
    const nonMaliciousIndex = goodCount + failedCount;
    if (nonMaliciousIndex % 4 === 3) return 'failed';
    return 'good';
  };

  const fire = () => {
    if (paused || document.hidden || planets.length === 0) return;
    launchCount += 1;
    const count = launchCount;
    const planet = planets[(count - 1) % planets.length]!;
    const styles = getComputedStyle(planet);
    const key = planetKey(planet);
    const outcome = pickOutcome();
    const flight = document.createElement('span');
    const satellite = createSatellite(outcome);

    if (outcome === 'good') goodCount += 1;
    if (outcome === 'failed') failedCount += 1;

    const logRow = log ? appendLogRow(log, key, 'flight') : null;

    const missSide = count % 2 === 0 ? '1' : '-1';
    flight.className =
      outcome === 'malicious'
        ? 'authorization-flight malicious'
        : outcome === 'failed'
          ? 'authorization-flight failed'
          : 'authorization-flight';
    flight.style.setProperty('--planet-x', styles.getPropertyValue('--planet-x').trim() || '50vw');
    flight.style.setProperty('--planet-y', styles.getPropertyValue('--planet-y').trim() || '50svh');
    flight.style.setProperty('--miss-x', `calc(${missSide} * ${6 + (count % 5)}vw)`);
    flight.appendChild(satellite);
    field.appendChild(flight);

    satellite.addEventListener('mouseenter', () => showTooltip(satellite));
    satellite.addEventListener('mouseleave', hideTooltip);
    satellite.addEventListener('focus', () => showTooltip(satellite));
    satellite.addEventListener('blur', hideTooltip);
    satellite.addEventListener('click', (event) => {
      event.stopPropagation();
      showTooltip(satellite, true);
    });

    if (outcome === 'malicious') {
      flight.addEventListener('animationend', () => flight.remove(), { once: true });
      window.setTimeout(() => {
        if (satellite.isConnected) showTooltip(satellite, true);
        resolveLogRow(logRow, 'malicious');
      }, 3300);
    } else if (outcome === 'failed') {
      flight.addEventListener('animationend', () => flight.remove(), { once: true });
      window.setTimeout(() => {
        if (satellite.isConnected) showTooltip(satellite, true);
        resolveLogRow(logRow, 'failed');
      }, 4200);
    } else {
      const orbit = getOrbit(planet, styles);
      flight.addEventListener(
        'animationend',
        () => {
          attachToOrbit(flight, orbit, satellite, key, count);
          resolveLogRow(logRow, 'good');
        },
        { once: true },
      );
    }
  };

  timeoutId = window.setTimeout(fire, 1400);
  intervalId = window.setInterval(fire, 15000);

  const onVisibility = () => {
    if (document.hidden || paused) {
      stopTimers();
    } else {
      startTimers();
    }
  };
  document.addEventListener('visibilitychange', onVisibility);

  // Pause launches + CSS motion when the hero is off-screen — keeps page scroll smooth.
  const io = new IntersectionObserver(
    ([entry]) => {
      paused = !entry?.isIntersecting;
      if (paused) {
        hero?.classList.add('is-away');
        stopTimers();
      } else {
        hero?.classList.remove('is-away');
        startTimers();
      }
    },
    { root: null, threshold: 0.08, rootMargin: '0px' },
  );
  if (hero) io.observe(hero);

  return () => {
    stopTimers();
    window.clearTimeout(tooltipTimer);
    document.removeEventListener('visibilitychange', onVisibility);
    io.disconnect();
    hero?.classList.remove('is-away');
    field.querySelectorAll('.authorization-flight, .authorization-orbit, .authorization-popover').forEach((n) => n.remove());
    orbits.clear();
  };
}
