/** Hero authorization-flight sequence — CubeSat craft with explicit outcome phases. */

import {
  AUDIENCES,
  CLIENTS,
  DESKS,
  PLANET_AUDIENCE,
  TOKEN_FAMILIES,
  iconURL,
} from '../data/heroLog';

type AuthOutcome = 'approved' | 'denied' | 'malicious';
type LogStatus = 'pending' | 'approved' | 'denied' | 'threat' | 'neutralized';
type SatelliteStatus = 'pending' | 'approved' | 'denied' | 'threat' | 'neutralized';

const LOG_STATUS_TEXT: Record<LogStatus, string> = {
  pending: 'evaluating',
  approved: 'authorized',
  denied: 'Authorization Denied',
  threat: 'threat detected',
  neutralized: 'neutralized',
};

const SATELLITE_LABELS: Record<SatelliteStatus, string> = {
  pending: 'Authorization pending',
  approved: 'Authorization approved',
  denied: 'Authorization Denied',
  threat: 'Malicious authorization detected — activate defense',
  neutralized: 'Malicious authorization neutralized',
};

const TOOLTIP_COPY: Record<SatelliteStatus, { label: string; detail: string }> = {
  pending: { label: 'Authorization Pending', detail: 'evaluating pass' },
  approved: { label: 'Authorization Approved', detail: 'orbit stable' },
  denied: { label: 'Authorization Denied', detail: 'pass rejected' },
  threat: { label: 'Malicious Attempt', detail: 'activate to intercept' },
  neutralized: { label: 'Threat Neutralized', detail: 'defense confirmed' },
};

const MAX_LOG_ROWS = 6;
const FIRST_LAUNCH_DELAY = 900;
const NEXT_LAUNCH_DELAY = 1_600;

function planetKey(planet: HTMLElement): string {
  return [...planet.classList].find((name) => name !== 'auth-planet') || 'planet';
}

const pick = <T,>(list: readonly T[]): T => list[Math.floor(Math.random() * list.length)]!;

function pickFamily(): string {
  const total = TOKEN_FAMILIES.reduce((sum, family) => sum + family.weight, 0);
  let roll = Math.random() * total;
  for (const family of TOKEN_FAMILIES) {
    roll -= family.weight;
    if (roll <= 0) return family.name;
  }
  return TOKEN_FAMILIES[0]!.name;
}

/** Risk score consistent with how the presentation will resolve. */
function scoreFor(outcome: AuthOutcome): string {
  const range: [number, number] =
    outcome === 'malicious' ? [0.78, 0.99] : outcome === 'denied' ? [0.31, 0.62] : [0.01, 0.24];
  return (range[0] + Math.random() * (range[1] - range[0])).toFixed(2);
}

function scoreBand(score: string): string {
  const value = Number(score);
  return value >= 0.7 ? 'high' : value >= 0.3 ? 'mid' : 'low';
}

function logTime(date: Date): string {
  return date.toTimeString().slice(0, 8);
}

const icon = (slug: string, cls: string) =>
  `<img class="${cls}" src="${iconURL(slug)}" alt="" loading="lazy" width="14" height="14" onerror="this.style.display='none'">`;

type LogRowSpec = {
  audienceDomain?: string;
  outcome: AuthOutcome;
  status: LogStatus;
  at?: Date;
};

// Row → satellite link so hovering a log line can spotlight its craft.
const rowSatellites = new WeakMap<HTMLElement, HTMLElement>();

function linkRowToSatellite(row: HTMLElement, satellite: HTMLElement): void {
  rowSatellites.set(row, satellite);
  row.classList.add('has-sat');
  row.addEventListener('mouseenter', () => {
    if (satellite.isConnected) satellite.classList.add('is-spotted');
  });
  row.addEventListener('mouseleave', () => satellite.classList.remove('is-spotted'));
}

function appendLogRow(log: HTMLElement, spec: LogRowSpec): HTMLElement {
  const audience = AUDIENCES.find((item) => item.domain === spec.audienceDomain) ?? pick(AUDIENCES);
  const client = pick(CLIENTS);
  const score = scoreFor(spec.outcome);
  const row = document.createElement('div');
  row.className = 'hero-tui-row';
  row.dataset.status = spec.status;
  row.innerHTML = `
    <span class="tui-time">${logTime(spec.at ?? new Date())}</span>
    <span class="tui-client">${icon(client.slug, 'tui-ico')}${client.name}</span>
    <span class="tui-token">${pickFamily()}</span>
    <span class="tui-aud">${icon(audience.slug, 'tui-ico')}${audience.domain}</span>
    <span class="tui-desk">${pick(DESKS)}</span>
    <span class="tui-score" data-band="${scoreBand(score)}">${score}</span>
    <span class="tui-status">${LOG_STATUS_TEXT[spec.status]}</span>
  `;
  while (log.children.length >= MAX_LOG_ROWS) {
    const evicted = log.firstElementChild as HTMLElement | null;
    if (evicted) rowSatellites.get(evicted)?.classList.remove('is-spotted');
    evicted?.remove();
  }
  log.appendChild(row);
  return row;
}

function resolveLogRow(row: HTMLElement | null, status: LogStatus): void {
  if (!row?.isConnected) return;
  row.dataset.status = status;
  const statusElement = row.querySelector('.tui-status');
  if (statusElement) statusElement.textContent = LOG_STATUS_TEXT[status];
}

function finalLogStatus(outcome: AuthOutcome): LogStatus {
  return outcome === 'malicious' ? 'neutralized' : outcome;
}

/** Outcome mix for ambient (no visible satellite) traffic. */
function ambientOutcome(): AuthOutcome {
  const roll = Math.random();
  if (roll < 0.06) return 'malicious';
  if (roll < 0.16) return 'denied';
  return 'approved';
}

function setSatelliteStatus(satellite: HTMLElement, status: SatelliteStatus): void {
  satellite.dataset.authStatus = status;
  satellite.setAttribute('aria-label', SATELLITE_LABELS[status]);
}

function createSatellite(outcome: AuthOutcome): HTMLButtonElement {
  const satellite = document.createElement('button');
  const classes = ['authorization-satellite', 'is-flying'];
  if (outcome === 'malicious') classes.push('malicious');
  if (outcome === 'denied') classes.push('denied');
  satellite.className = classes.join(' ');
  satellite.type = 'button';
  satellite.dataset.authOutcome = outcome;
  satellite.setAttribute('aria-expanded', 'false');
  setSatelliteStatus(satellite, 'pending');

  // The nozzle stays with a coasting craft; flame and sparks only exist while thrusting.
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

/** Only finish a phase when the flight's own named animation finishes. */
function onOwnAnimationEnd(
  element: HTMLElement,
  animationName: string,
  callback: () => void,
): () => void {
  const listener = (event: AnimationEvent) => {
    if (event.target !== element || event.animationName !== animationName) return;
    element.removeEventListener('animationend', listener);
    callback();
  };
  element.addEventListener('animationend', listener);
  return () => element.removeEventListener('animationend', listener);
}

export function startHeroAuthorizationSequence(field: HTMLElement, log?: HTMLElement | null): () => void {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const planets = [...field.querySelectorAll<HTMLElement>('.auth-planet')];
  const hero = field.closest('.hero') as HTMLElement | null;
  const defenseLayer = hero?.querySelector<HTMLElement>('[data-authorization-defense-layer]') ?? null;
  const tooltipLayer = defenseLayer ?? field;
  const announcer = hero?.querySelector<HTMLElement>('[data-authorization-announcer]') ?? null;

  // Seed the board so it reads as ongoing traffic before the first launch.
  if (log) {
    const now = Date.now();
    for (let index = MAX_LOG_ROWS - 1; index >= 1; index -= 1) {
      const outcome = ambientOutcome();
      appendLogRow(log, {
        outcome,
        status: finalLogStatus(outcome),
        at: new Date(now - index * (9_000 + Math.random() * 14_000)),
      });
    }
  }

  if (planets.length === 0) return () => {};

  const orbits = new Map<string, HTMLElement>();
  const activeFlights = new Set<HTMLElement>();
  const activeFlightRecords = new Map<HTMLElement, { row: HTMLElement | null; outcome: AuthOutcome }>();
  const activeAnimations = new Set<Animation>();
  const ownedTimeouts = new Set<number>();
  let launchCount = 0;
  let approvedCount = 0;
  let deniedCount = 0;
  const guaranteedBadLaunch = 4;
  let launchTimer = 0;
  let ambientTimer = 0;
  let tooltip: HTMLElement | null = null;
  let tooltipTarget: HTMLElement | null = null;
  let pinnedTarget: HTMLElement | null = null;
  let tooltipTimer = 0;
  let tooltipRaf = 0;
  let tooltipWidth = 0;
  let tooltipHeight = 0;
  let tooltipLayerWidth = 0;
  let tooltipLayerHeight = 0;
  let paused = false;
  let motionDisabled = reduced.matches;
  let disposed = false;

  const later = (callback: () => void, delay: number): number => {
    const id = window.setTimeout(() => {
      ownedTimeouts.delete(id);
      if (!disposed) callback();
    }, delay);
    ownedTimeouts.add(id);
    return id;
  };

  const clearOwnedTimeout = (id: number): void => {
    if (!id) return;
    window.clearTimeout(id);
    ownedTimeouts.delete(id);
  };

  const announce = (message: string): void => {
    if (announcer) announcer.textContent = message;
  };

  const getTooltip = () => {
    if (tooltip) return tooltip;
    tooltip = document.createElement('span');
    tooltip.id = 'hero-authorization-tooltip';
    tooltip.className = 'authorization-popover';
    tooltip.setAttribute('role', 'tooltip');
    tooltip.innerHTML = `
      <span class="authorization-ticket" aria-hidden="true"></span>
      <span data-auth-tooltip-label>Authorization Pending</span>
      <span class="authorization-status" data-auth-tooltip-status>evaluating pass</span>
    `;
    tooltipLayer.appendChild(tooltip);
    return tooltip;
  };

  const updateTooltip = (satellite: HTMLElement): HTMLElement => {
    const tip = getTooltip();
    const status = (satellite.dataset.authStatus ?? 'pending') as SatelliteStatus;
    const copy = TOOLTIP_COPY[status];
    const label = tip.querySelector('[data-auth-tooltip-label]');
    const detail = tip.querySelector('[data-auth-tooltip-status]');
    if (label) label.textContent = copy.label;
    if (detail) detail.textContent = copy.detail;
    for (const name of ['pending', 'approved', 'denied', 'threat', 'neutralized']) {
      tip.classList.toggle(`is-${name}`, status === name);
    }
    return tip;
  };

  const refreshTooltipMetrics = (): void => {
    tooltipWidth = tooltip?.offsetWidth ?? 0;
    tooltipHeight = tooltip?.offsetHeight ?? 0;
    tooltipLayerWidth = tooltipLayer.offsetWidth;
    tooltipLayerHeight = tooltipLayer.offsetHeight;
  };

  const positionTooltip = (): void => {
    tooltipRaf = 0;
    if (!tooltip?.classList.contains('is-visible') || !tooltipTarget?.isConnected) return;
    const layerRect = tooltipLayer.getBoundingClientRect();
    const satelliteRect = tooltipTarget.getBoundingClientRect();
    const scaleX = tooltipLayerWidth ? layerRect.width / tooltipLayerWidth : 1;
    const scaleY = tooltipLayerHeight ? layerRect.height / tooltipLayerHeight : scaleX;
    const unclampedX = (satelliteRect.left - layerRect.left + satelliteRect.width / 2) / scaleX;
    const localTop = (satelliteRect.top - layerRect.top) / scaleY;
    const localBottom = (satelliteRect.bottom - layerRect.top) / scaleY;
    const minX = tooltipWidth / 2 + 8;
    const maxX = tooltipLayerWidth - tooltipWidth / 2 - 8;
    const placeBelow = localTop < tooltipHeight + 18;
    tooltip.classList.toggle('is-below', placeBelow);
    tooltip.style.left = `${Math.min(Math.max(unclampedX, minX), Math.max(minX, maxX))}px`;
    tooltip.style.top = placeBelow ? `${localBottom + 8}px` : `${localTop - 8}px`;
    tooltipRaf = window.requestAnimationFrame(positionTooltip);
  };

  const closeTooltip = (): void => {
    clearOwnedTimeout(tooltipTimer);
    tooltipTimer = 0;
    if (tooltipRaf) window.cancelAnimationFrame(tooltipRaf);
    tooltipRaf = 0;
    tooltip?.classList.remove('is-visible', 'is-below');
    tooltipTarget?.removeAttribute('aria-describedby');
    tooltipTarget?.setAttribute('aria-expanded', 'false');
    tooltipTarget = null;
    pinnedTarget = null;
  };

  const showTooltip = (satellite: HTMLElement, sticky = false): void => {
    if (!satellite.isConnected) return;
    if (tooltipTarget && tooltipTarget !== satellite) {
      tooltipTarget.removeAttribute('aria-describedby');
      tooltipTarget.setAttribute('aria-expanded', 'false');
    }
    clearOwnedTimeout(tooltipTimer);
    tooltipTimer = 0;
    tooltipTarget = satellite;
    pinnedTarget = sticky ? satellite : null;
    const tip = updateTooltip(satellite);
    satellite.setAttribute('aria-describedby', tip.id);
    satellite.setAttribute('aria-expanded', 'true');
    tip.classList.add('is-visible');
    refreshTooltipMetrics();
    if (!tooltipRaf) tooltipRaf = window.requestAnimationFrame(positionTooltip);
    tooltipTimer = later(closeTooltip, sticky ? 5_000 : 8_000);
  };

  const hideTooltip = (satellite: HTMLElement): void => {
    if (pinnedTarget === satellite || tooltipTarget !== satellite) return;
    clearOwnedTimeout(tooltipTimer);
    tooltipTimer = later(closeTooltip, 120);
  };

  const refreshTooltip = (satellite: HTMLElement): void => {
    if (tooltipTarget === satellite) updateTooltip(satellite);
  };

  const cleanupOrbitIfEmpty = (key: string, orbit: HTMLElement): void => {
    if (orbit.querySelector('.authorization-track')) return;
    orbit.remove();
    if (orbits.get(key) === orbit) orbits.delete(key);
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
    orbit.style.setProperty('--parallax-factor', styles.getPropertyValue('--parallax-factor').trim() || '0.2');
    field.appendChild(orbit);
    orbits.set(key, orbit);
    return orbit;
  };

  const removeFlight = (flight: HTMLElement, satellite: HTMLElement): void => {
    if (tooltipTarget === satellite) closeTooltip();
    if (document.activeElement === satellite) {
      hero?.querySelector<HTMLElement>('.hero-actions a')?.focus({ preventScroll: true });
    }
    activeFlights.delete(flight);
    activeFlightRecords.delete(flight);
    flight.remove();
  };

  const attachToOrbit = (
    flight: HTMLElement,
    orbit: HTMLElement,
    satellite: HTMLElement,
    key: string,
  ): void => {
    if (!flight.isConnected) return;
    const before = satellite.getBoundingClientRect();
    const track = document.createElement('span');
    track.className = 'authorization-track';
    track.style.animationPlayState = 'paused';
    satellite.classList.remove('is-flying');
    satellite.classList.add('is-orbiting');
    satellite.querySelector('.sat-booster')?.remove();
    setSatelliteStatus(satellite, 'approved');
    refreshTooltip(satellite);
    track.appendChild(satellite);
    orbit.appendChild(track);
    activeFlights.delete(flight);
    activeFlightRecords.delete(flight);
    flight.remove();

    const after = satellite.getBoundingClientRect();
    const fieldRect = field.getBoundingClientRect();
    const scaleX = field.offsetWidth ? fieldRect.width / field.offsetWidth : 1;
    const scaleY = field.offsetHeight ? fieldRect.height / field.offsetHeight : scaleX;
    const deltaX = (before.left - after.left) / scaleX;
    const deltaY = (before.top - after.top) / scaleY;
    const capture = satellite.animate(
      [
        { transform: `translate(calc(-50% + ${deltaX}px), calc(-50% + ${deltaY}px)) rotate(-8deg)` },
        { transform: 'translate(-50%, -50%) rotate(0deg)' },
      ],
      { duration: 480, easing: 'cubic-bezier(.22,.88,.32,1)', fill: 'both' },
    );
    activeAnimations.add(capture);
    capture.addEventListener(
      'finish',
      () => {
        activeAnimations.delete(capture);
        capture.cancel();
        if (track.isConnected && !motionDisabled) {
          track.style.animationPlayState = 'running';
          scheduleLaunch(NEXT_LAUNCH_DELAY);
        }
      },
      { once: true },
    );

    const removeAfterRevolution = (event: AnimationEvent) => {
      if (event.target !== track || event.animationName !== 'satelliteOrbit') return;
      track.removeEventListener('animationiteration', removeAfterRevolution);
      if (tooltipTarget === satellite) closeTooltip();
      if (document.activeElement === satellite) {
        hero?.querySelector<HTMLElement>('.hero-actions a')?.focus({ preventScroll: true });
      }
      track.remove();
      cleanupOrbitIfEmpty(key, orbit);
    };
    track.addEventListener('animationiteration', removeAfterRevolution);
  };

  const clearThreatState = (): void => {
    hero?.classList.remove('is-under-attack');
    document.documentElement.classList.remove('authorization-alert');
  };

  const pickOutcome = (): AuthOutcome => {
    const guaranteed = launchCount === guaranteedBadLaunch;
    const dice = !guaranteed && launchCount % 10 === 0 ? Math.floor(Math.random() * 6) + 1 : null;
    if (guaranteed || dice === 6) return 'malicious';

    // One ordinary denial for every three approved presentations.
    const nonMaliciousIndex = approvedCount + deniedCount;
    if (nonMaliciousIndex % 4 === 3) return 'denied';
    return 'approved';
  };

  const fire = (): void => {
    if (paused || motionDisabled || document.hidden || planets.length === 0) return;
    launchCount += 1;
    const count = launchCount;
    const planet = planets[(count - 1) % planets.length]!;
    const styles = getComputedStyle(planet);
    const key = planetKey(planet);
    const outcome = pickOutcome();
    const orbit = getOrbit(planet, styles);
    const flight = document.createElement('span');
    const satellite = createSatellite(outcome);
    let threatAction: (() => void) | null = null;

    if (outcome === 'approved') approvedCount += 1;
    if (outcome === 'denied') deniedCount += 1;

    const logRow = log
      ? appendLogRow(log, { audienceDomain: PLANET_AUDIENCE[key], outcome, status: 'pending' })
      : null;
    if (logRow) linkRowToSatellite(logRow, satellite);

    const missSide = count % 2 === 0 ? '1' : '-1';
    flight.className =
      outcome === 'malicious'
        ? 'authorization-flight malicious'
        : outcome === 'denied'
          ? 'authorization-flight denied'
          : 'authorization-flight';
    flight.style.setProperty('--planet-x', styles.getPropertyValue('--planet-x').trim() || '50vw');
    flight.style.setProperty('--planet-y', styles.getPropertyValue('--planet-y').trim() || '50svh');
    flight.style.setProperty('--parallax-factor', styles.getPropertyValue('--parallax-factor').trim() || '0.2');
    flight.style.setProperty('--orbit-radius', `${orbit.offsetWidth / 2}px`);
    flight.style.setProperty('--miss-x', `calc(${missSide} * ${6 + (count % 5)}vw)`);
    flight.appendChild(satellite);

    if (outcome === 'malicious') {
      const reticle = document.createElement('span');
      reticle.className = 'authorization-threat-reticle';
      reticle.setAttribute('aria-hidden', 'true');
      const beam = document.createElement('span');
      beam.className = 'authorization-defense-beam';
      beam.setAttribute('aria-hidden', 'true');
      const burst = document.createElement('span');
      burst.className = 'authorization-blast-burst';
      burst.setAttribute('aria-hidden', 'true');
      flight.append(reticle, beam, burst);
    }

    (outcome === 'malicious' && defenseLayer ? defenseLayer : field).appendChild(flight);
    activeFlights.add(flight);
    activeFlightRecords.set(flight, { row: logRow, outcome });

    satellite.addEventListener('mouseenter', () => showTooltip(satellite));
    satellite.addEventListener('mouseleave', () => hideTooltip(satellite));
    satellite.addEventListener('focus', () => showTooltip(satellite));
    satellite.addEventListener('blur', () => {
      if (tooltipTarget === satellite) closeTooltip();
    });
    satellite.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeTooltip();
    });
    satellite.addEventListener('click', (event) => {
      event.stopPropagation();
      if (satellite.dataset.authStatus === 'threat' && threatAction) {
        threatAction();
        return;
      }
      if (pinnedTarget === satellite) closeTooltip();
      else showTooltip(satellite, true);
    });

    if (outcome === 'approved') {
      onOwnAnimationEnd(flight, 'authorizationApproach', () => {
        attachToOrbit(flight, orbit, satellite, key);
        resolveLogRow(logRow, 'approved');
      });
      return;
    }

    if (outcome === 'denied') {
      onOwnAnimationEnd(flight, 'authorizationDeniedApproach', () => {
        satellite.classList.remove('is-flying');
        satellite.classList.add('is-coasting');
        setSatelliteStatus(satellite, 'denied');
        refreshTooltip(satellite);
        resolveLogRow(logRow, 'denied');
        showTooltip(satellite, true);
        onOwnAnimationEnd(flight, 'authorizationDeniedFall', () => {
          removeFlight(flight, satellite);
          cleanupOrbitIfEmpty(key, orbit);
          scheduleLaunch(NEXT_LAUNCH_DELAY);
        });
        flight.classList.add('is-rejected');
      });
      return;
    }

    onOwnAnimationEnd(flight, 'authorizationThreatApproach', () => {
      let threatPhase: 'targeted' | 'blasted' = 'targeted';
      setSatelliteStatus(satellite, 'threat');
      refreshTooltip(satellite);
      resolveLogRow(logRow, 'threat');
      announce('Malicious authorization detected. Defense target locked.');
      hero?.classList.add('is-under-attack');
      document.documentElement.classList.add('authorization-alert');
      later(() => document.documentElement.classList.remove('authorization-alert'), 620);
      showTooltip(satellite, true);

      const blastThreat = () => {
        if (threatPhase !== 'targeted') return;
        threatPhase = 'blasted';
        satellite.classList.remove('is-flying');
        satellite.classList.add('is-neutralized');
        setSatelliteStatus(satellite, 'neutralized');
        refreshTooltip(satellite);
        resolveLogRow(logRow, 'neutralized');
        announce('Malicious authorization neutralized.');
        flight.classList.remove('is-targeted');
        onOwnAnimationEnd(flight, 'authorizationBlast', () => {
          removeFlight(flight, satellite);
          cleanupOrbitIfEmpty(key, orbit);
          clearThreatState();
          scheduleLaunch(NEXT_LAUNCH_DELAY);
        });
        flight.classList.add('is-blasted');
      };

      threatAction = blastThreat;
      onOwnAnimationEnd(flight, 'authorizationTargetHold', blastThreat);
      flight.classList.add('is-targeted');
    });
  };

  const scheduleLaunch = (delay = NEXT_LAUNCH_DELAY): void => {
    if (
      launchTimer ||
      activeFlights.size > 0 ||
      activeAnimations.size > 0 ||
      paused ||
      motionDisabled ||
      document.hidden
    ) return;
    launchTimer = later(() => {
      launchTimer = 0;
      fire();
    }, delay);
  };

  const scheduleAmbient = (): void => {
    if (!log || ambientTimer || paused || motionDisabled || document.hidden) return;
    ambientTimer = later(() => {
      ambientTimer = 0;
      const outcome = ambientOutcome();
      const row = appendLogRow(log, { outcome, status: 'pending' });
      later(() => {
        if (outcome !== 'malicious') {
          resolveLogRow(row, outcome);
          return;
        }
        resolveLogRow(row, 'threat');
        later(() => resolveLogRow(row, 'neutralized'), 700);
      }, 700 + Math.random() * 1_800);
      scheduleAmbient();
      // Slow enough that satellite-backed rows (the hoverable ones) survive
      // several evictions before scrolling off the board.
    }, 6_500 + Math.random() * 4_500);
  };

  const stopSchedulers = (): void => {
    clearOwnedTimeout(launchTimer);
    clearOwnedTimeout(ambientTimer);
    launchTimer = 0;
    ambientTimer = 0;
  };

  const startSchedulers = (firstDelay = 900): void => {
    if (paused || motionDisabled || document.hidden) return;
    if (activeFlights.size === 0 && activeAnimations.size === 0) scheduleLaunch(firstDelay);
    scheduleAmbient();
  };

  const settleForReducedMotion = (): void => {
    for (const [flight, record] of activeFlightRecords) {
      resolveLogRow(record.row, finalLogStatus(record.outcome));
      flight.remove();
    }
    activeFlightRecords.clear();
    activeFlights.clear();
    for (const animation of activeAnimations) animation.cancel();
    activeAnimations.clear();
    field.querySelectorAll<HTMLElement>('.authorization-track').forEach((track) => {
      track.style.animation = 'none';
      track.style.animationPlayState = 'paused';
    });
    for (const [key, orbit] of orbits) cleanupOrbitIfEmpty(key, orbit);
    closeTooltip();
    clearThreatState();
    announce('Animation paused because reduced motion is enabled.');
  };

  const clearMotion = (): void => {
    for (const animation of activeAnimations) animation.cancel();
    activeAnimations.clear();
    for (const flight of activeFlights) flight.remove();
    activeFlights.clear();
    activeFlightRecords.clear();
    field.querySelectorAll('.authorization-orbit').forEach((node) => node.remove());
    orbits.clear();
    closeTooltip();
    clearThreatState();
  };

  const onVisibility = () => {
    hero?.classList.toggle('is-away', document.hidden || paused);
    if (document.hidden || paused || motionDisabled) {
      stopSchedulers();
      for (const animation of activeAnimations) animation.pause();
    } else {
      for (const animation of activeAnimations) animation.play();
      startSchedulers();
    }
  };
  document.addEventListener('visibilitychange', onVisibility);
  window.addEventListener('resize', refreshTooltipMetrics, { passive: true });

  const onReducedMotion = (event: MediaQueryListEvent) => {
    motionDisabled = event.matches;
    if (motionDisabled) {
      stopSchedulers();
      settleForReducedMotion();
    } else {
      field.querySelectorAll<HTMLElement>('.authorization-track').forEach((track) => {
        track.style.removeProperty('animation');
        track.style.animationPlayState = 'running';
      });
      startSchedulers(FIRST_LAUNCH_DELAY);
    }
  };
  reduced.addEventListener('change', onReducedMotion);

  // Pause scheduling and CSS motion when the hero is off-screen.
  const observer = new IntersectionObserver(
    ([entry]) => {
      paused = !entry?.isIntersecting;
      hero?.classList.toggle('is-away', paused || document.hidden);
      if (paused) {
        stopSchedulers();
        for (const animation of activeAnimations) animation.pause();
        closeTooltip();
      }
      else {
        for (const animation of activeAnimations) animation.play();
        startSchedulers();
      }
    },
    { root: null, threshold: 0.08, rootMargin: '0px' },
  );
  if (hero) observer.observe(hero);

  startSchedulers(FIRST_LAUNCH_DELAY);

  return () => {
    disposed = true;
    stopSchedulers();
    for (const id of ownedTimeouts) window.clearTimeout(id);
    ownedTimeouts.clear();
    if (tooltipRaf) window.cancelAnimationFrame(tooltipRaf);
    document.removeEventListener('visibilitychange', onVisibility);
    window.removeEventListener('resize', refreshTooltipMetrics);
    reduced.removeEventListener('change', onReducedMotion);
    observer.disconnect();
    hero?.classList.remove('is-away');
    clearMotion();
    tooltip?.remove();
    tooltip = null;
  };
}
