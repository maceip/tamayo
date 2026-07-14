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
type LogStatus = 'speculative' | 'pending' | 'approved' | 'denied' | 'threat' | 'neutralized';
type SatelliteStatus =
  | 'pending'
  | 'authorizing'
  | 'capturing'
  | 'approved'
  | 'denied'
  | 'threat'
  | 'neutralized';

const LOG_STATUS_TEXT: Record<LogStatus, string> = {
  speculative: 'Speculative',
  pending: 'Authorization Pending',
  approved: 'Authorization Approved',
  denied: 'Authorization Denied',
  threat: 'Malicious Attempt',
  neutralized: 'Threat Neutralized',
};

const SATELLITE_LABELS: Record<SatelliteStatus, string> = {
  pending: 'Authorization pending',
  authorizing: 'Authorization check in progress',
  capturing: 'Authorization approved — destination capture in progress',
  approved: 'Authorization approved',
  denied: 'Authorization Denied',
  threat: 'Malicious authorization detected — activate defense',
  neutralized: 'Malicious authorization neutralized',
};

const TOOLTIP_COPY: Record<SatelliteStatus, { label: string; detail: string }> = {
  pending: { label: 'Authorization Pending', detail: 'evaluating pass' },
  authorizing: { label: 'Authorization Pending', detail: 'multi-axis verification' },
  capturing: { label: 'Authorization Approved', detail: 'securing destination' },
  approved: { label: 'Authorization Approved', detail: 'authorization stable' },
  denied: { label: 'Authorization Denied', detail: 'pass rejected' },
  threat: { label: 'Malicious Attempt', detail: 'activate to intercept' },
  neutralized: { label: 'Threat Neutralized', detail: 'defense confirmed' },
};

const MAX_AUTOMATIC_SATELLITES = 3;
const INITIAL_AUTOMATIC_OUTCOMES: readonly AuthOutcome[] = ['approved', 'malicious', 'denied'];
const LOG_ROW_HEIGHT_FALLBACK = 54;
const FIRST_LAUNCH_DELAY = 900;
const AUTOMATIC_LAUNCH_STAGGER = 850;
const NEXT_LAUNCH_DELAY = 1_600;
const TICKER_FEED_DELAY = 1_800;
const ORBIT_RESIDENCY_HOLD = 12_000;
const MANUAL_ORBIT_WATCHDOG = 52_000;
const STATIC_RESULT_HOLD = 6_500;
const STATIC_THREAT_HOLD = 30_000;
const STATIC_NEUTRALIZED_HOLD = 2_400;
const PARALLAX_START_EVENT = 'tamayo:hero-parallax-start';

type ConnectionPowerHints = EventTarget & { saveData?: boolean };
type BatteryPowerHints = EventTarget & { charging: boolean; level: number };
type NavigatorPowerHints = Navigator & {
  connection?: ConnectionPowerHints;
  deviceMemory?: number;
  getBattery?: () => Promise<BatteryPowerHints>;
};

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
  planetKey: string;
  audienceDomain?: string;
  outcome: AuthOutcome;
  status: LogStatus;
  at?: Date;
};

// Row interaction is installed once and always resolves the current link from
// these maps. Replaying a speculative row therefore cannot retain stale craft
// closures or accumulate duplicate event listeners.
const rowSatellites = new WeakMap<HTMLElement, HTMLElement>();
const rowSimulators = new WeakMap<HTMLElement, () => void>();
const interactiveRows = new WeakSet<HTMLElement>();
const pointerHighlightedRows = new WeakSet<HTMLElement>();
const focusHighlightedRows = new WeakSet<HTMLElement>();

function measuredLogCapacity(log: HTMLElement): number {
  const styles = getComputedStyle(log);
  const configuredRowHeight = Number.parseFloat(
    styles.getPropertyValue('--ticker-row-height-px'),
  );
  const rowHeight =
    Number.isFinite(configuredRowHeight) && configuredRowHeight > 0
      ? configuredRowHeight
      : LOG_ROW_HEIGHT_FALLBACK;
  return Math.max(1, Math.floor((log.clientHeight + 0.5) / rowHeight));
}

function visibleLogCapacity(log: HTMLElement): number {
  const cached = Number.parseInt(log.dataset.visibleRows ?? '', 10);
  return Number.isFinite(cached) && cached > 0 ? cached : measuredLogCapacity(log);
}

function retainedLogCapacity(log: HTMLElement): number {
  // The three deterministic opening attempts must remain addressable even on
  // a one-row phone viewport. This is a queue-retention invariant, not a
  // visual row count: only measuredLogCapacity() controls what is displayed.
  return Math.max(visibleLogCapacity(log), INITIAL_AUTOMATIC_OUTCOMES.length);
}

function syncVisibleLogWindow(log: HTMLElement): number {
  const capacity = measuredLogCapacity(log);
  log.dataset.visibleRows = String(capacity);

  const rows = [...log.children].filter(
    (child): child is HTMLElement => child instanceof HTMLElement,
  );
  const focusedRow = rows.find((row) => row.contains(document.activeElement));
  const threatRow = [...rows].reverse().find(
    (row) => row.dataset.status === 'threat' && rowSatellites.get(row)?.isConnected,
  );
  const visibleRows = rows.slice(-capacity);

  // Never hide the control a keyboard user is operating or the defense action
  // for a live threat merely because a new tail entry arrived. Focus wins the
  // single-row phone slot while it is actively in use; otherwise Neutralize is
  // pinned until the threat resolves.
  const priorityRows = [focusedRow, threatRow].filter(
    (row, index, priorities): row is HTMLElement => !!row && priorities.indexOf(row) === index,
  );
  for (const priorityRow of priorityRows) {
    if (visibleRows.includes(priorityRow)) continue;
    const replaceIndex = visibleRows.findIndex((row) => !priorityRows.includes(row));
    if (replaceIndex >= 0) visibleRows.splice(replaceIndex, 1, priorityRow);
  }

  const visibleSet = new Set(visibleRows);
  for (const row of rows) {
    const outsideWindow = !visibleSet.has(row);
    row.classList.toggle('is-outside-ticker-window', outsideWindow);
    row.setAttribute('aria-hidden', String(outsideWindow));
  }
  return capacity;
}

function syncRowHighlight(row: HTMLElement): void {
  const highlighted = pointerHighlightedRows.has(row) || focusHighlightedRows.has(row);
  row.classList.toggle('is-highlighted', highlighted);
  const satellite = rowSatellites.get(row);
  satellite?.classList.toggle('is-spotted', highlighted && satellite.isConnected);
}

function installLogRowInteractions(row: HTMLElement): void {
  if (interactiveRows.has(row)) return;
  interactiveRows.add(row);

  row.addEventListener('pointerenter', () => {
    pointerHighlightedRows.add(row);
    syncRowHighlight(row);
  });
  row.addEventListener('pointerleave', () => {
    pointerHighlightedRows.delete(row);
    syncRowHighlight(row);
  });
  row.addEventListener('focusin', () => {
    focusHighlightedRows.add(row);
    syncRowHighlight(row);
    if (row.parentElement) syncVisibleLogWindow(row.parentElement);
  });
  row.addEventListener('focusout', (event) => {
    if (event.relatedTarget instanceof Node && row.contains(event.relatedTarget)) return;
    focusHighlightedRows.delete(row);
    syncRowHighlight(row);
    queueMicrotask(() => {
      if (row.parentElement) syncVisibleLogWindow(row.parentElement);
    });
  });
  row.addEventListener('click', (event) => {
    const target = event.target as Element;
    if (target.closest('.tui-simulate-action')) {
      event.stopPropagation();
      rowSimulators.get(row)?.();
      return;
    }
    if (target.closest('button')) return;
    const satellite = rowSatellites.get(row);
    if (satellite?.isConnected) satellite.click();
  });
  row.addEventListener('keydown', (event) => {
    if (event.target !== row || (event.key !== 'Enter' && event.key !== ' ')) return;
    const satellite = rowSatellites.get(row);
    if (!satellite?.isConnected) return;
    event.preventDefault();
    satellite.click();
  });
}

function linkRowToSatellite(row: HTMLElement, satellite: HTMLElement): void {
  rowSatellites.get(row)?.classList.remove('is-spotted');
  rowSatellites.set(row, satellite);
  row.classList.remove('is-speculative');
  row.classList.add('has-sat');
  row.dataset.linkState = 'live';
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  row.setAttribute('aria-label', 'Authorization Pending. Activate to inspect the related satellite.');
  if (satellite.id) row.setAttribute('aria-controls', satellite.id);
  row.parentElement?.appendChild(row);
  if (row.parentElement) syncVisibleLogWindow(row.parentElement);
  syncRowHighlight(row);
}

function unlinkRowFromSatellite(row: HTMLElement | null): void {
  if (!row) return;
  rowSatellites.get(row)?.classList.remove('is-spotted');
  rowSatellites.delete(row);
  row.classList.remove('has-sat');
  row.removeAttribute('tabindex');
  row.removeAttribute('role');
  row.removeAttribute('aria-label');
  row.removeAttribute('aria-controls');
  row.dataset.linkState = 'speculative';
  syncRowHighlight(row);
}

function renderSpeculativeLogRow(row: HTMLElement): HTMLButtonElement | null {
  if (!row.isConnected) return null;
  const previousStatus = row.dataset.status;
  if (previousStatus && previousStatus !== 'speculative') row.dataset.lastStatus = previousStatus;
  unlinkRowFromSatellite(row);
  row.dataset.status = 'speculative';
  row.classList.add('is-speculative');
  row.setAttribute('role', 'group');
  const audience = row.dataset.audienceDomain ?? 'this destination';
  row.setAttribute('aria-label', `Speculative authorization attempt for ${audience}`);

  const statusElement = row.querySelector<HTMLElement>('.tui-status');
  if (!statusElement) return null;
  const action = document.createElement('button');
  action.type = 'button';
  action.className = 'tui-simulate-action';
  action.disabled = !rowSimulators.has(row);
  action.setAttribute('aria-label', `Simulate speculative authorization attempt for ${audience}`);
  action.innerHTML = `
    <span class="tui-speculative-label">Speculative</span>
    <span class="tui-simulate-label">Simulate</span>
    <span class="tui-simulate-beam" aria-hidden="true"></span>
  `;
  statusElement.replaceChildren(action);
  return action;
}

function appendLogRow(log: HTMLElement, spec: LogRowSpec): HTMLElement {
  const retentionCapacity = retainedLogCapacity(log);
  const previousTops =
    log.children.length >= visibleLogCapacity(log)
      ? new Map(
          [...log.children]
            .map((child) => child as HTMLElement)
            .filter((row) => !row.classList.contains('is-outside-ticker-window'))
            .map((row) => [row, row.getBoundingClientRect().top] as const),
        )
      : new Map<HTMLElement, number>();
  const audience = AUDIENCES.find((item) => item.domain === spec.audienceDomain) ?? pick(AUDIENCES);
  const client = pick(CLIENTS);
  const tokenFamily = pickFamily();
  const score = scoreFor(spec.outcome);
  const row = document.createElement('div');
  row.className = 'hero-tui-row';
  row.dataset.status = spec.status;
  row.dataset.planet = spec.planetKey;
  row.dataset.audienceDomain = audience.domain;
  row.dataset.outcome = spec.outcome;
  row.dataset.tokenFamily = tokenFamily;
  row.innerHTML = `
    <span class="tui-time" data-label="time">${logTime(spec.at ?? new Date())}</span>
    <span class="tui-client" data-label="client">${icon(client.slug, 'tui-ico')}${client.name}</span>
    <span class="tui-token" data-label="token">${tokenFamily}</span>
    <span class="tui-aud" data-label="audience">${icon(audience.slug, 'tui-ico')}${audience.domain}</span>
    <span class="tui-desk" data-label="desk">${pick(DESKS)}</span>
    <span class="tui-score" data-label="score" data-band="${scoreBand(score)}">${score}</span>
    <span class="tui-status" data-label="status">${LOG_STATUS_TEXT[spec.status]}</span>
  `;
  while (log.children.length >= retentionCapacity) {
    const evicted = [...log.children].find((child) => {
      const candidate = child as HTMLElement;
      return !rowSatellites.get(candidate)?.isConnected && !candidate.contains(document.activeElement);
    }) as HTMLElement | undefined;
    // A live flight must never lose its corresponding row. If every slot is
    // live, temporarily exceed the visual cap and recycle one after detachment.
    if (!evicted) break;
    if (evicted?.contains(document.activeElement)) {
      log.closest('.hero')?.querySelector<HTMLElement>('.hero-actions a')?.focus({ preventScroll: true });
    }
    rowSimulators.delete(evicted);
    pointerHighlightedRows.delete(evicted);
    focusHighlightedRows.delete(evicted);
    rowSatellites.get(evicted)?.classList.remove('is-spotted');
    evicted?.remove();
  }
  log.appendChild(row);
  installLogRowInteractions(row);
  syncVisibleLogWindow(log);
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    for (const [existingRow, previousTop] of previousTops) {
      if (!existingRow.isConnected) continue;
      const delta = previousTop - existingRow.getBoundingClientRect().top;
      if (Math.abs(delta) < 0.5) continue;
      existingRow.animate(
        [
          { transform: `translateY(${delta}px)` },
          { transform: 'translateY(0)' },
        ],
        { duration: 320, easing: 'cubic-bezier(.22,.72,.24,1)' },
      );
    }
  }
  return row;
}

function resolveLogRow(row: HTMLElement | null, status: LogStatus): void {
  if (!row?.isConnected) return;
  row.dataset.status = status;
  row.classList.remove('is-speculative');
  // A live threat owns the final mobile ticker slot so its Neutralize action
  // remains visible even if desktop rows have been reordered.
  if (status === 'threat' && rowSatellites.get(row)?.isConnected) {
    row.parentElement?.appendChild(row);
    if (row.parentElement) syncVisibleLogWindow(row.parentElement);
  }
  const statusElement = row.querySelector('.tui-status');
  if (!statusElement) return;
  statusElement.textContent = '';
  const satellite = rowSatellites.get(row);
  if (status === 'threat' && satellite?.isConnected) {
    const rowHadFocus = document.activeElement === row;
    row.removeAttribute('tabindex');
    row.setAttribute('role', 'group');
    row.setAttribute('aria-label', 'Malicious authorization attempt. Use Neutralize to intercept it.');
    const action = document.createElement('button');
    action.type = 'button';
    action.className = 'tui-threat-action';
    action.textContent = 'Neutralize';
    action.setAttribute('aria-label', 'Neutralize malicious authorization attempt');
    action.addEventListener('click', (event) => {
      event.stopPropagation();
      if (satellite.isConnected) satellite.click();
    });
    statusElement.appendChild(action);
    if (rowHadFocus) action.focus({ preventScroll: true });
    return;
  }
  if (satellite?.isConnected) {
    row.tabIndex = 0;
    row.setAttribute('role', 'button');
    row.setAttribute('aria-label', `${LOG_STATUS_TEXT[status]}. Activate to inspect the related satellite.`);
  }
  statusElement.textContent = LOG_STATUS_TEXT[status];
}

function finalLogStatus(outcome: AuthOutcome): 'approved' | 'denied' | 'neutralized' {
  return outcome === 'malicious' ? 'neutralized' : outcome;
}

/** Outcome mix used when generating a new speculative scenario. */
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

type PayloadVariant = 'identity' | 'burn' | 'email' | 'event' | 'threat';

const PAYLOAD_VARIANTS: Record<string, { variant: PayloadVariant; glyph: string }> = {
  private_identity: { variant: 'identity', glyph: '◆' },
  burn: { variant: 'burn', glyph: '✦' },
  policy_email: { variant: 'email', glyph: '✉' },
  evt: { variant: 'event', glyph: '↯' },
};

function createSatellite(outcome: AuthOutcome, tokenFamily: string): HTMLButtonElement {
  const satellite = document.createElement('button');
  const classes = ['authorization-satellite', 'is-flying'];
  if (outcome === 'malicious') classes.push('malicious');
  if (outcome === 'denied') classes.push('denied');
  satellite.className = classes.join(' ');
  satellite.type = 'button';
  satellite.dataset.authOutcome = outcome;
  satellite.dataset.tokenFamily = tokenFamily;
  satellite.setAttribute('aria-expanded', 'false');
  setSatelliteStatus(satellite, 'pending');

  const payload = outcome === 'malicious'
    ? { variant: 'threat' as const, glyph: '☠' }
    : (PAYLOAD_VARIANTS[tokenFamily] ?? PAYLOAD_VARIANTS.evt!);

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
    <span class="sat-rcs-system" aria-hidden="true">
      <span class="sat-rcs sat-rcs-up" aria-hidden="true"></span>
      <span class="sat-rcs sat-rcs-right" aria-hidden="true"></span>
      <span class="sat-rcs sat-rcs-down" aria-hidden="true"></span>
      <span class="sat-rcs sat-rcs-left" aria-hidden="true"></span>
    </span>
    <span class="sat-panel sat-panel-left" aria-hidden="true"></span>
    <span class="sat-bus" aria-hidden="true">
      <span class="sat-bay"></span>
      <span class="sat-mast"></span>
      <span class="sat-dish"></span>
    </span>
    <span class="sat-panel sat-panel-right" aria-hidden="true"></span>
    <span class="sat-payload sat-payload-${payload.variant}" aria-hidden="true">
      <span class="sat-payload-gem"></span>
      <span class="sat-payload-glyph">${payload.glyph}</span>
    </span>
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
  const lowPowerPreference = window.matchMedia('(prefers-reduced-data: reduce), (update: slow)');
  const powerNavigator = navigator as NavigatorPowerHints;
  const connection = powerNavigator.connection ?? null;
  const planets = [...field.querySelectorAll<HTMLElement>('.auth-planet')];
  const hero = field.closest('.hero') as HTMLElement | null;
  const defenseLayer = hero?.querySelector<HTMLElement>('[data-authorization-defense-layer]') ?? null;
  const tooltipLayer = defenseLayer ?? field;
  const announcer = hero?.querySelector<HTMLElement>('[data-authorization-announcer]') ?? null;

  if (planets.length === 0) return () => {};

  const planetsByKey = new Map(planets.map((planet) => [planetKey(planet), planet]));
  const attemptSpecs = new WeakMap<HTMLElement, { planetKey: string; outcome: AuthOutcome }>();
  const orbits = new Map<string, HTMLElement>();
  const activeFlights = new Set<HTMLElement>();
  const activeFlightRecords = new Map<HTMLElement, { row: HTMLElement | null }>();
  const activeAnimations = new Set<Animation>();
  const activeCaptures = new Map<
    HTMLElement,
    {
      flight: HTMLElement;
      key: string;
      orbit: HTMLElement;
      row: HTMLElement | null;
      satellite: HTMLElement;
      animation: Animation;
      scheduleRelease: (delay: number) => void;
    }
  >();
  const ownedTimeouts = new Map<
    number,
    {
      callback: () => void;
      remaining: number;
      startedAt: number;
      nativeId: number;
    }
  >();
  const activeThreatFlights = new Set<HTMLElement>();
  const initialAutomaticAttempts = INITIAL_AUTOMATIC_OUTCOMES.map((outcome, index) => ({
    outcome,
    planetKey: planetKey(planets[index % planets.length]!),
    preferredRow: null as HTMLElement | null,
  }));
  const manuallyLaunchedRows = new WeakSet<HTMLElement>();
  let attemptSerial = 0;
  let flightSerial = 0;
  let initialAutomaticIndex = 0;
  let launchTimer = 0;
  let tickerFeedTimer = 0;
  let threatDetectionTimer = 0;
  let tooltip: HTMLElement | null = null;
  let tooltipTarget: HTMLElement | null = null;
  let pinnedTarget: HTMLElement | null = null;
  let tooltipTimer = 0;
  let tooltipRaf = 0;
  let tooltipLastPosition = 0;
  let resizeRaf = 0;
  let tickerResizeRaf = 0;
  let geometryDirty = false;
  let tooltipWidth = 0;
  let tooltipHeight = 0;
  let tooltipLayerWidth = 0;
  let tooltipLayerHeight = 0;
  let paused = false;
  let battery: BatteryPowerHints | null = null;
  const hasLimitedMemory =
    typeof powerNavigator.deviceMemory === 'number' && powerNavigator.deviceMemory <= 4;
  const requestsLowPower = (): boolean =>
    lowPowerPreference.matches ||
    connection?.saveData === true ||
    hasLimitedMemory ||
    (!!battery && !battery.charging && battery.level <= 0.2);
  let lowPowerMode = requestsLowPower();
  let motionDisabled = reduced.matches || lowPowerMode;
  let disposed = false;
  let ownedTimeoutSerial = 0;

  hero?.classList.toggle('is-low-power', lowPowerMode);
  if (hero) hero.dataset.authorizationPower = lowPowerMode ? 'low' : 'full';

  const shouldPauseMotion = (): boolean => paused || motionDisabled || document.hidden;
  // Reduced/low-power mode still permits static, time-bounded simulations.
  // Only loss of visibility suspends their active-duration clocks.
  const shouldSuspendTimeouts = (): boolean => paused || document.hidden;

  const registerAnimation = (animation: Animation): Animation => {
    activeAnimations.add(animation);
    if (shouldPauseMotion()) animation.pause();
    return animation;
  };

  const assertLogIntegrity = (): void => {
    if (!import.meta.env.DEV || !log) return;
    const satellites = new Set<HTMLElement>();
    for (const row of log.querySelectorAll<HTMLElement>('.hero-tui-row')) {
      const satellite = rowSatellites.get(row);
      const hasSatellite = !!satellite?.isConnected;
      const speculative = row.dataset.status === 'speculative';
      const simulateActions = row.querySelectorAll('.tui-simulate-action').length;
      if (speculative !== !hasSatellite || simulateActions !== (speculative ? 1 : 0)) {
        throw new Error(`Authorization ticker invariant failed for ${row.id || 'unnamed row'}`);
      }
      if (satellite) {
        if (satellites.has(satellite) || satellite.dataset.entryId !== row.dataset.entryId) {
          throw new Error(`Authorization ticker link mismatch for ${row.id || 'unnamed row'}`);
        }
        satellites.add(satellite);
      }
    }
  };

  const armOwnedTimeout = (id: number): void => {
    const timer = ownedTimeouts.get(id);
    if (!timer || timer.nativeId || disposed || shouldSuspendTimeouts()) return;
    timer.startedAt = performance.now();
    timer.nativeId = window.setTimeout(() => {
      const current = ownedTimeouts.get(id);
      if (!current) return;
      ownedTimeouts.delete(id);
      current.nativeId = 0;
      if (!disposed) current.callback();
    }, timer.remaining);
  };

  const later = (callback: () => void, delay: number): number => {
    const id = ++ownedTimeoutSerial;
    ownedTimeouts.set(id, {
      callback,
      remaining: Math.max(0, delay),
      startedAt: 0,
      nativeId: 0,
    });
    armOwnedTimeout(id);
    return id;
  };

  const clearOwnedTimeout = (id: number): void => {
    if (!id) return;
    const timer = ownedTimeouts.get(id);
    if (timer?.nativeId) window.clearTimeout(timer.nativeId);
    ownedTimeouts.delete(id);
  };

  const suspendOwnedTimeouts = (): void => {
    const now = performance.now();
    for (const timer of ownedTimeouts.values()) {
      if (!timer.nativeId) continue;
      window.clearTimeout(timer.nativeId);
      timer.nativeId = 0;
      timer.remaining = Math.max(0, timer.remaining - (now - timer.startedAt));
    }
  };

  const resumeOwnedTimeouts = (): void => {
    if (disposed || shouldSuspendTimeouts()) return;
    for (const id of ownedTimeouts.keys()) armOwnedTimeout(id);
  };

  const announce = (message: string): void => {
    if (announcer) announcer.textContent = message;
  };

  const promotePriorityRow = (): HTMLElement | null => {
    if (!log) return null;
    const liveRows = [...log.querySelectorAll<HTMLElement>('.hero-tui-row.has-sat')].filter((row) =>
      rowSatellites.get(row)?.isConnected,
    );
    const priority =
      [...liveRows].reverse().find((row) => row.dataset.status === 'threat') ??
      liveRows[liveRows.length - 1] ??
      null;
    priority?.parentElement?.appendChild(priority);
    if (log) syncVisibleLogWindow(log);
    return priority;
  };

  const discardSpeculativeRow = (row: HTMLElement): void => {
    rowSatellites.delete(row);
    rowSimulators.delete(row);
    attemptSpecs.delete(row);
    interactiveRows.delete(row);
    pointerHighlightedRows.delete(row);
    focusHighlightedRows.delete(row);
    row.remove();
    if (log) syncVisibleLogWindow(log);
  };

  const findDiscardableSpeculativeRow = (): HTMLElement | null =>
    log
      ? [...log.querySelectorAll<HTMLElement>('.hero-tui-row[data-status="speculative"]')]
          .find((row) => !row.contains(document.activeElement)) ?? null
      : null;

  const trimSpeculativeOverflow = (): void => {
    if (!log) return;
    while (log.children.length > retainedLogCapacity(log)) {
      const candidate = findDiscardableSpeculativeRow();
      if (!candidate) return;
      discardSpeculativeRow(candidate);
    }
    syncVisibleLogWindow(log);
  };

  const returnRowToSpeculative = (row: HTMLElement | null, restoreFocus = false): void => {
    if (!row) return;
    const action = renderSpeculativeLogRow(row);
    const priority = promotePriorityRow();
    if (restoreFocus) {
      const focusTarget =
        priority?.querySelector<HTMLElement>('.tui-threat-action') ?? priority ?? action;
      focusTarget?.focus({ preventScroll: true });
    }
    trimSpeculativeOverflow();
    assertLogIntegrity();
  };

  const registerAttemptRow = (
    row: HTMLElement,
    spec: { planetKey: string; outcome: AuthOutcome },
  ): HTMLElement => {
    attemptSerial += 1;
    const entryId = `authorization-attempt-${attemptSerial}`;
    row.id = entryId;
    row.dataset.entryId = entryId;
    attemptSpecs.set(row, spec);
    rowSimulators.set(row, () => simulateAttempt(row));
    renderSpeculativeLogRow(row);
    assertLogIntegrity();
    return row;
  };

  const createAttemptRow = (
    planetKeyValue: string,
    outcome: AuthOutcome,
    at = new Date(),
  ): HTMLElement | null => {
    if (!log) return null;
    const row = appendLogRow(log, {
      planetKey: planetKeyValue,
      audienceDomain: PLANET_AUDIENCE[planetKeyValue],
      outcome,
      status: 'speculative',
      at,
    });
    return registerAttemptRow(row, { planetKey: planetKeyValue, outcome });
  };

  const createAutomaticAttemptRow = (
    spec: { planetKey: string; outcome: AuthOutcome },
    source: 'initial' | 'ambient',
  ): HTMLElement | null => {
    if (!log) return null;
    if (log.children.length >= retainedLogCapacity(log)) {
      const candidate = findDiscardableSpeculativeRow();
      if (!candidate) return null;
      discardSpeculativeRow(candidate);
    }

    const row = createAttemptRow(spec.planetKey, spec.outcome);
    if (row) row.dataset.trafficSource = source;
    return row;
  };

  const createAmbientAttemptRow = (): HTMLElement | null => {
    const queuedRow = log
      ? [...log.querySelectorAll<HTMLElement>(
          '.hero-tui-row[data-status="speculative"][data-traffic-source="feed"]',
        )]
          .reverse()
          .find((row) => !row.contains(document.activeElement)) ?? null
      : null;
    if (queuedRow) {
      queuedRow.dataset.trafficSource = 'ambient';
      return queuedRow;
    }

    const planet = planets[flightSerial % planets.length]!;
    return createAutomaticAttemptRow(
      { planetKey: planetKey(planet), outcome: ambientOutcome() },
      'ambient',
    );
  };

  const appendTickerFeedRow = (): void => {
    if (!log) return;
    const planet = planets[(attemptSerial + flightSerial) % planets.length]!;
    const row = createAttemptRow(planetKey(planet), ambientOutcome());
    if (row) row.dataset.trafficSource = 'feed';
  };

  const fillVisibleLogWindow = (): void => {
    if (!log) return;
    const capacity = syncVisibleLogWindow(log);
    while (log.children.length < capacity) appendTickerFeedRow();
    trimSpeculativeOverflow();
    syncVisibleLogWindow(log);
  };

  const scheduleTickerFeed = (delay = TICKER_FEED_DELAY): void => {
    if (tickerFeedTimer || disposed || paused || document.hidden) return;
    tickerFeedTimer = later(() => {
      tickerFeedTimer = 0;
      if (disposed || paused || document.hidden) return;
      appendTickerFeedRow();
      scheduleTickerFeed();
    }, delay);
  };

  function simulateAttempt(row: HTMLElement): void {
    if (row.dataset.status !== 'speculative' || rowSatellites.get(row)?.isConnected) return;
    const action = row.querySelector<HTMLButtonElement>('.tui-simulate-action');
    if (action) action.disabled = true;
    // Give explicit interaction priority over a pending automatic launch, but
    // do not disable the guaranteed intro queue or later ambient traffic.
    clearOwnedTimeout(launchTimer);
    launchTimer = 0;
    if (!fire(row, true)) {
      if (action) action.disabled = false;
      scheduleLaunch(NEXT_LAUNCH_DELAY);
      return;
    }
    row.dataset.trafficSource = 'manual';
    manuallyLaunchedRows.add(row);
    scheduleLaunch(
      initialAutomaticIndex < initialAutomaticAttempts.length
        ? AUTOMATIC_LAUNCH_STAGGER
        : NEXT_LAUNCH_DELAY,
    );
  }

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
    for (const name of [
      'pending',
      'authorizing',
      'capturing',
      'approved',
      'denied',
      'threat',
      'neutralized',
    ] satisfies SatelliteStatus[]) {
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

  const tooltipNeedsTracking = (): boolean => {
    if (!tooltipTarget?.isConnected || shouldPauseMotion()) return false;
    if (tooltipTarget.closest('[data-static-simulation="true"]')) return false;
    // Targeted threats are stationary except while scroll parallax is changing
    // their local coordinate. Track only for that short scroll window.
    return (
      tooltipTarget.dataset.authStatus !== 'threat' ||
      hero?.classList.contains('is-scrolling') === true
    );
  };

  const positionTooltip = (timestamp = performance.now()): void => {
    tooltipRaf = 0;
    if (!tooltip?.classList.contains('is-visible') || !tooltipTarget?.isConnected) return;
    const keepTracking = tooltipNeedsTracking();
    // The craft is continuously moving, but a 30fps tooltip is visually
    // responsive and avoids forcing two layout reads on every display frame.
    if (keepTracking && timestamp - tooltipLastPosition < 32) {
      tooltipRaf = window.requestAnimationFrame(positionTooltip);
      return;
    }
    tooltipLastPosition = timestamp;
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
    if (keepTracking) tooltipRaf = window.requestAnimationFrame(positionTooltip);
  };

  const onParallaxStart = (): void => {
    if (
      tooltipTarget?.dataset.authStatus === 'threat' &&
      tooltip?.classList.contains('is-visible') &&
      !tooltipRaf
    ) {
      tooltipRaf = window.requestAnimationFrame(positionTooltip);
    }
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
    tooltipLastPosition = 0;
  };

  const priorityThreatTarget = (): HTMLElement | null => {
    if (tooltipTarget?.isConnected && tooltipTarget.dataset.authStatus === 'threat') {
      return tooltipTarget;
    }
    for (const owner of activeThreatFlights) {
      const threat = owner.querySelector<HTMLElement>('.authorization-satellite');
      if (threat?.isConnected) return threat;
    }
    return null;
  };

  const showTooltip = (
    satellite: HTMLElement,
    sticky = false,
    allowThreatOverride = false,
  ): void => {
    if (!satellite.isConnected) return;
    const priorityThreat = priorityThreatTarget();
    // Ambient result transitions and passive hover/focus must not steal the
    // shared popover from an active defense target. A deliberate click may.
    if (priorityThreat && priorityThreat !== satellite && !allowThreatOverride) return;
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
    // Hover previews may time out; keyboard focus and explicit click pins stay
    // open until blur, Escape, a second click, or craft removal.
    if (!sticky && document.activeElement !== satellite) {
      tooltipTimer = later(closeTooltip, 8_000);
    }
  };

  const hideTooltip = (satellite: HTMLElement): void => {
    if (pinnedTarget === satellite || tooltipTarget !== satellite) return;
    clearOwnedTimeout(tooltipTimer);
    tooltipTimer = later(closeTooltip, 120);
  };

  const refreshTooltip = (satellite: HTMLElement): void => {
    if (tooltipTarget !== satellite) return;
    updateTooltip(satellite);
    if (!tooltipRaf && tooltipNeedsTracking()) {
      tooltipRaf = window.requestAnimationFrame(positionTooltip);
    }
  };

  const cleanupOrbitIfEmpty = (key: string, orbit: HTMLElement): void => {
    if (orbit.querySelector('.authorization-track')) return;
    orbit.remove();
    if (orbits.get(key) === orbit) orbits.delete(key);
  };

  const syncOrbitGeometry = (
    orbit: HTMLElement,
    planet: HTMLElement,
    styles = getComputedStyle(planet),
  ): void => {
    orbit.style.setProperty('--planet-x', styles.getPropertyValue('--planet-x').trim() || '50vw');
    orbit.style.setProperty('--planet-y', styles.getPropertyValue('--planet-y').trim() || '50svh');
    orbit.style.setProperty('--orbit-size', styles.getPropertyValue('--orbit-size').trim() || '144px');
    orbit.style.setProperty('--parallax-factor', styles.getPropertyValue('--parallax-factor').trim() || '0.2');
  };

  const getOrbit = (planet: HTMLElement, styles: CSSStyleDeclaration) => {
    const key = planetKey(planet);
    const existing = orbits.get(key);
    if (existing) {
      syncOrbitGeometry(existing, planet, styles);
      return existing;
    }
    const orbit = document.createElement('span');
    orbit.className = 'authorization-orbit';
    orbit.dataset.planet = key;
    syncOrbitGeometry(orbit, planet, styles);
    field.appendChild(orbit);
    orbits.set(key, orbit);
    return orbit;
  };

  const removeFlight = (flight: HTMLElement, satellite: HTMLElement): void => {
    if (tooltipTarget === satellite) closeTooltip();
    const record = activeFlightRecords.get(flight);
    const restoreFocus =
      document.activeElement === satellite || !!record?.row?.contains(document.activeElement);
    returnRowToSpeculative(record?.row ?? null, restoreFocus);
    activeFlights.delete(flight);
    activeFlightRecords.delete(flight);
    flight.remove();
  };

  const beginAuthorizationHold = (
    flight: HTMLElement,
    satellite: HTMLElement,
    onAuthorized: (holdRect: DOMRect) => void,
  ): void => {
    if (!flight.isConnected) return;
    satellite.classList.remove('is-flying', 'is-coasting');
    satellite.classList.add('is-authorizing');
    setSatelliteStatus(satellite, 'authorizing');
    refreshTooltip(satellite);

    onOwnAnimationEnd(flight, 'authorizationHold', () => {
      if (!flight.isConnected) return;
      // Snapshot the completed hold before removing its animation class. Without
      // this, the base approach restarts at its off-screen 0% keyframe and the
      // capture FLIP appears to replace the satellite with a new arrival.
      const holdRect = satellite.getBoundingClientRect();
      // End the satellite's RCS state before installing its successor, but keep
      // the flight wrapper's completed hold transform until that successor owns
      // positioning. This prevents both overlapping thrusters and a restart of
      // the base off-screen approach animation.
      satellite.classList.remove('is-authorizing');
      onAuthorized(holdRect);
      flight.classList.remove('is-authorizing');
    });
    flight.classList.add('is-authorizing');
  };

  const beginCapture = (
    flight: HTMLElement,
    orbit: HTMLElement,
    satellite: HTMLElement,
    key: string,
    row: HTMLElement | null,
    before: DOMRect,
    userInitiated: boolean,
  ): void => {
    if (!flight.isConnected) return;
    const track = document.createElement('span');
    track.className = 'authorization-track is-capturing';
    // Hold the destination coordinate system still while the same satellite
    // performs its FLIP arc. Steady rotation begins only after capture finishes.
    track.style.animationPlayState = 'paused';
    satellite.classList.remove('is-flying', 'is-authorizing', 'is-orbiting');
    satellite.classList.add('is-capturing');
    setSatelliteStatus(satellite, 'capturing');
    refreshTooltip(satellite);
    track.appendChild(satellite);
    orbit.appendChild(track);
    // Keep the flight registered until capture completes so pause/reduced-motion
    // settlement still has an outcome record even after this wrapper is detached.
    flight.remove();

    const after = satellite.getBoundingClientRect();
    const fieldRect = field.getBoundingClientRect();
    const scaleX = field.offsetWidth ? fieldRect.width / field.offsetWidth : 1;
    const scaleY = field.offsetHeight ? fieldRect.height / field.offsetHeight : scaleX;
    const deltaX = (before.left + before.width / 2 - (after.left + after.width / 2)) / scaleX;
    const deltaY = (before.top + before.height / 2 - (after.top + after.height / 2)) / scaleY;
    const arcDirection = deltaX < 0 ? -1 : 1;
    const transformAt = (x: number, y: number, rotation: number, scale = 1) =>
      `translate(calc(-50% + ${x}px), calc(-50% + ${y}px)) rotate(${rotation}deg) scale(${scale})`;
    let orbitResidencyTimer = 0;
    let trackReleased = false;
    const removeAfterRevolution = (event: AnimationEvent): void => {
      if (event.target !== track || event.animationName !== 'satelliteOrbit') return;
      releaseTrack();
    };
    const releaseTrack = (): void => {
      if (trackReleased) return;
      trackReleased = true;
      clearOwnedTimeout(orbitResidencyTimer);
      orbitResidencyTimer = 0;
      track.removeEventListener('animationend', removeAfterRevolution);
      if (tooltipTarget === satellite) closeTooltip();
      const restoreFocus =
        document.activeElement === satellite || !!row?.contains(document.activeElement);
      returnRowToSpeculative(row, restoreFocus);
      track.remove();
      cleanupOrbitIfEmpty(key, orbit);
      scheduleLaunch(NEXT_LAUNCH_DELAY);
    };
    const scheduleRelease = (delay: number): void => {
      clearOwnedTimeout(orbitResidencyTimer);
      orbitResidencyTimer = later(releaseTrack, delay);
    };
    const capture = registerAnimation(satellite.animate(
      [
        {
          offset: 0,
          transform: transformAt(deltaX, deltaY, -8, 1),
        },
        {
          offset: 0.36,
          transform: transformAt(
            deltaX * 0.62 + arcDirection * 8,
            deltaY * 0.62 - 12,
            -3.5,
            1.015,
          ),
        },
        {
          offset: 0.72,
          transform: transformAt(
            deltaX * 0.2 + arcDirection * 5,
            deltaY * 0.2 - 4,
            1.5,
            1.006,
          ),
        },
        {
          offset: 1,
          transform: transformAt(0, 0, 0),
        },
      ],
      { duration: 1_100, easing: 'cubic-bezier(.2,.72,.22,1)', fill: 'both' },
    ));
    activeCaptures.set(track, {
      flight,
      key,
      orbit,
      row,
      satellite,
      animation: capture,
      scheduleRelease,
    });
    capture.addEventListener(
      'finish',
      () => {
        activeAnimations.delete(capture);
        if (!track.isConnected || disposed) return;

        activeCaptures.delete(track);
        track.classList.remove('is-capturing');
        satellite.classList.remove('is-capturing');
        satellite.classList.add('is-orbiting', 'is-capture-decaying');
        satellite.querySelector('.sat-booster')?.remove();
        setSatelliteStatus(satellite, 'approved');
        refreshTooltip(satellite);
        resolveLogRow(row, 'approved');
        activeFlights.delete(flight);
        activeFlightRecords.delete(flight);
        capture.cancel();

        // Off-screen pausing belongs to `.hero.is-away`; an inline paused value
        // would survive resume and strand this track before its first revolution.
        track.style.animationPlayState = 'running';
        // Automatic demos leave after a short sample; an explicit simulation
        // may complete the CSS revolution, with a watchdog for missed events.
        scheduleRelease(userInitiated ? MANUAL_ORBIT_WATCHDOG : ORBIT_RESIDENCY_HOLD);

        const rcs = satellite.querySelector<HTMLElement>('.sat-rcs-system');
        if (!rcs || motionDisabled) {
          rcs?.remove();
          satellite.classList.remove('is-capture-decaying');
          if (!motionDisabled) scheduleLaunch(NEXT_LAUNCH_DELAY);
          return;
        }

        // Capture jets remain white and fully present for the FLIP arc. They
        // begin decaying only after the craft has entered its stable state.
        const decay = registerAnimation(rcs.animate(
          [
            { opacity: 1, transform: 'scale(1)' },
            { offset: 0.62, opacity: 0.52, transform: 'scale(.9)' },
            { opacity: 0, transform: 'scale(.68)' },
          ],
          { duration: 460, easing: 'cubic-bezier(.4,0,.8,.3)', fill: 'both' },
        ));
        decay.addEventListener(
          'finish',
          () => {
            activeAnimations.delete(decay);
            decay.cancel();
            rcs.remove();
            satellite.classList.remove('is-capture-decaying');
            if (!motionDisabled) scheduleLaunch(NEXT_LAUNCH_DELAY);
          },
          { once: true },
        );
      },
      { once: true },
    );

    track.addEventListener('animationend', removeAfterRevolution);
  };

  const beginThreatState = (flight: HTMLElement): void => {
    clearOwnedTimeout(threatDetectionTimer);
    activeThreatFlights.add(flight);
    hero?.classList.add('is-threat-detected', 'is-under-attack');
    document.documentElement.classList.add('authorization-alert');
    threatDetectionTimer = later(() => {
      threatDetectionTimer = 0;
      hero?.classList.remove('is-threat-detected');
      document.documentElement.classList.remove('authorization-alert');
    }, 720);
  };

  const clearThreatState = (flight?: HTMLElement): void => {
    if (flight) activeThreatFlights.delete(flight);
    else activeThreatFlights.clear();
    if (activeThreatFlights.size > 0) return;
    clearOwnedTimeout(threatDetectionTimer);
    threatDetectionTimer = 0;
    hero?.classList.remove('is-threat-detected', 'is-under-attack');
    document.documentElement.classList.remove('authorization-alert');
  };

  const bindSatelliteInteractions = (
    satellite: HTMLButtonElement,
    getThreatAction: () => (() => void) | null,
  ): void => {
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
      const threatAction = getThreatAction();
      if (satellite.dataset.authStatus === 'threat' && threatAction) {
        threatAction();
        return;
      }
      if (pinnedTarget === satellite) closeTooltip();
      else showTooltip(satellite, true, true);
    });
  };

  function fire(
    requestedRow?: HTMLElement,
    userInitiated = false,
    fallbackSpec?: { planetKey: string; outcome: AuthOutcome },
  ): boolean {
    if (paused || document.hidden || planets.length === 0) return false;

    const speculativeRows = log
      ? [...log.querySelectorAll<HTMLElement>('.hero-tui-row[data-status="speculative"]')]
      : [];
    let logRow =
      requestedRow ??
      speculativeRows.find((row) => !row.contains(document.activeElement)) ??
      null;
    if (!logRow) {
      // Do not steal a focused Simulate control for background traffic. If the
      // ticker is otherwise full, wait for focus or a live row to clear rather
      // than exceeding the bounded log with an unrepresented flight.
      if (
        speculativeRows.length > 0 ||
        (log && log.children.length >= retainedLogCapacity(log))
      ) return false;
      const fallbackPlanet = planets[flightSerial % planets.length]!;
      logRow = createAttemptRow(planetKey(fallbackPlanet), ambientOutcome());
    }
    if (logRow && (logRow.dataset.status !== 'speculative' || rowSatellites.get(logRow)?.isConnected)) {
      return false;
    }

    const fallbackPlanet = planets[flightSerial % planets.length]!;
    const spec =
      (logRow && attemptSpecs.get(logRow)) ??
      fallbackSpec ?? {
        planetKey: planetKey(fallbackPlanet),
        outcome: ambientOutcome(),
      };
    const planet = planetsByKey.get(spec.planetKey) ?? fallbackPlanet;
    const styles = getComputedStyle(planet);
    const key = planetKey(planet);
    const outcome = spec.outcome;
    flightSerial += 1;
    const count = flightSerial;
    const orbit = getOrbit(planet, styles);
    const tokenFamily = logRow?.dataset.tokenFamily ?? pickFamily();
    const satellite = createSatellite(outcome, tokenFamily);
    const entryId = logRow?.dataset.entryId ?? `authorization-flight-${count}`;
    satellite.id = `${entryId}-satellite-${count}`;
    satellite.dataset.entryId = entryId;
    let threatAction: (() => void) | null = null;
    const claimedFocusedRow = !!logRow?.contains(document.activeElement);

    if (logRow) {
      const time = logRow.querySelector<HTMLElement>('.tui-time');
      if (time) time.textContent = logTime(new Date());
      linkRowToSatellite(logRow, satellite);
      resolveLogRow(logRow, 'pending');
    }
    bindSatelliteInteractions(satellite, () => threatAction);

    if (motionDisabled) {
      const track = document.createElement('span');
      track.className = 'authorization-track';
      track.dataset.staticSimulation = 'true';
      track.style.animation = 'none';
      track.style.animationPlayState = 'paused';
      satellite.classList.remove('is-flying', 'is-authorizing', 'is-capturing');
      satellite.classList.add('is-orbiting');
      satellite.querySelector('.sat-booster')?.remove();
      satellite.querySelector('.sat-rcs-system')?.remove();
      track.appendChild(satellite);
      orbit.appendChild(track);
      if (logRow) syncRowHighlight(logRow);

      let cleanupTimer = 0;
      let cleaned = false;
      const cleanupStaticSimulation = (wasThreat = false): void => {
        if (cleaned) return;
        cleaned = true;
        clearOwnedTimeout(cleanupTimer);
        cleanupTimer = 0;
        if (tooltipTarget === satellite) closeTooltip();
        const restoreFocus =
          document.activeElement === satellite || !!logRow?.contains(document.activeElement);
        returnRowToSpeculative(logRow, restoreFocus);
        track.remove();
        cleanupOrbitIfEmpty(key, orbit);
        if (wasThreat) clearThreatState(track);
        scheduleLaunch(NEXT_LAUNCH_DELAY);
      };
      const scheduleStaticCleanup = (delay: number, wasThreat = false): void => {
        clearOwnedTimeout(cleanupTimer);
        cleanupTimer = later(() => cleanupStaticSimulation(wasThreat), delay);
      };

      if (outcome === 'malicious') {
        let threatPhase: 'targeted' | 'neutralized' = 'targeted';
        setSatelliteStatus(satellite, 'threat');
        resolveLogRow(logRow, 'threat');
        threatAction = () => {
          if (threatPhase !== 'targeted' || cleaned) return;
          threatPhase = 'neutralized';
          const restoreFocus = !!logRow?.querySelector('.tui-threat-action:focus');
          satellite.classList.add('is-neutralized');
          setSatelliteStatus(satellite, 'neutralized');
          refreshTooltip(satellite);
          resolveLogRow(logRow, 'neutralized');
          const priority = promotePriorityRow();
          if (restoreFocus) {
            const focusTarget =
              priority?.querySelector<HTMLElement>('.tui-threat-action') ?? priority ?? logRow;
            focusTarget?.focus({ preventScroll: true });
          }
          clearThreatState(track);
          announce('Malicious authorization neutralized.');
          scheduleStaticCleanup(STATIC_NEUTRALIZED_HOLD);
        };
        refreshTooltip(satellite);
        showTooltip(satellite, true);
        beginThreatState(track);
        assertLogIntegrity();
        if (userInitiated || claimedFocusedRow) {
          logRow?.querySelector<HTMLElement>('.tui-threat-action')?.focus({ preventScroll: true });
        }
        announce('Malicious authorization detected. Activate Neutralize to intercept it.');
        // Reduced motion removes movement, not the decision. Leave a generous
        // actionable window, then expire the scenario without claiming success.
        scheduleStaticCleanup(STATIC_THREAT_HOLD, true);
        return true;
      }

      const status = finalLogStatus(outcome);
      setSatelliteStatus(satellite, status === 'neutralized' ? 'neutralized' : status);
      resolveLogRow(logRow, status);
      assertLogIntegrity();
      if (userInitiated || claimedFocusedRow) logRow?.focus({ preventScroll: true });
      if (userInitiated) {
        announce(`Simulation completed for ${PLANET_AUDIENCE[key] ?? key}: ${LOG_STATUS_TEXT[status]}.`);
      }
      scheduleStaticCleanup(STATIC_RESULT_HOLD);
      return true;
    }

    const flight = document.createElement('span');

    const missSide = count % 2 === 0 ? '1' : '-1';
    flight.className =
      outcome === 'malicious'
        ? 'authorization-flight malicious'
        : outcome === 'denied'
          ? 'authorization-flight denied'
          : 'authorization-flight';
    flight.dataset.planet = key;
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
    if (logRow) syncRowHighlight(logRow);
    activeFlights.add(flight);
    activeFlightRecords.set(flight, { row: logRow });
    assertLogIntegrity();
    if (userInitiated || claimedFocusedRow) {
      logRow?.focus({ preventScroll: true });
    }
    if (userInitiated) {
      announce(`Simulation launched for ${PLANET_AUDIENCE[key] ?? key}.`);
    }

    if (outcome === 'approved') {
      onOwnAnimationEnd(flight, 'authorizationApproach', () => {
        beginAuthorizationHold(flight, satellite, (holdRect) => {
          beginCapture(flight, orbit, satellite, key, logRow, holdRect, userInitiated);
        });
      });
      return true;
    }

    if (outcome === 'denied') {
      onOwnAnimationEnd(flight, 'authorizationDeniedApproach', () => {
        beginAuthorizationHold(flight, satellite, () => {
          satellite.classList.add('is-coasting');
          setSatelliteStatus(satellite, 'denied');
          refreshTooltip(satellite);
          resolveLogRow(logRow, 'denied');
          onOwnAnimationEnd(flight, 'authorizationDeniedFall', () => {
            removeFlight(flight, satellite);
            cleanupOrbitIfEmpty(key, orbit);
            scheduleLaunch(NEXT_LAUNCH_DELAY);
          });
          flight.classList.add('is-rejected');
          showTooltip(satellite, true);
        });
      });
      return true;
    }

    onOwnAnimationEnd(flight, 'authorizationThreatApproach', () => {
      beginAuthorizationHold(flight, satellite, () => {
        let threatPhase: 'targeted' | 'blasted' = 'targeted';
        satellite.classList.add('is-flying');
        setSatelliteStatus(satellite, 'threat');
        refreshTooltip(satellite);
        resolveLogRow(logRow, 'threat');

        const blastThreat = () => {
          if (threatPhase !== 'targeted') return;
          threatPhase = 'blasted';
          const restoreFocus = !!logRow?.querySelector('.tui-threat-action:focus');
          satellite.classList.remove('is-flying');
          satellite.classList.add('is-neutralized');
          setSatelliteStatus(satellite, 'neutralized');
          refreshTooltip(satellite);
          resolveLogRow(logRow, 'neutralized');
          const priority = promotePriorityRow();
          if (restoreFocus) {
            const focusTarget =
              priority?.querySelector<HTMLElement>('.tui-threat-action') ?? priority ?? logRow;
            focusTarget?.focus({ preventScroll: true });
          }
          announce('Malicious authorization neutralized.');
          onOwnAnimationEnd(flight, 'authorizationBlast', () => {
            removeFlight(flight, satellite);
            cleanupOrbitIfEmpty(key, orbit);
            clearThreatState(flight);
            scheduleLaunch(NEXT_LAUNCH_DELAY);
          });
          flight.classList.add('is-blasted');
          flight.classList.remove('is-targeted');
        };

        threatAction = blastThreat;
        onOwnAnimationEnd(flight, 'authorizationTargetHold', blastThreat);
        flight.classList.add('is-targeted');
        showTooltip(satellite, true);
        beginThreatState(flight);
        announce('Malicious authorization detected. Defense target locked.');
      });
    });
    return true;
  }

  const liveSatelliteCount = (): number =>
    (hero ?? field).querySelectorAll('.authorization-satellite').length;

  const canLaunchAutomatically = (): boolean =>
    !disposed &&
    !paused &&
    !motionDisabled &&
    !document.hidden &&
    activeThreatFlights.size === 0 &&
    liveSatelliteCount() < MAX_AUTOMATIC_SATELLITES;

  const getInitialAutomaticRow = (
    attempt: (typeof initialAutomaticAttempts)[number],
  ): HTMLElement | null => {
    const row = attempt.preferredRow;
    if (
      row?.isConnected &&
      row.dataset.status === 'speculative' &&
      !rowSatellites.get(row)?.isConnected &&
      !manuallyLaunchedRows.has(row) &&
      !row.contains(document.activeElement)
    ) {
      return row;
    }
    return createAutomaticAttemptRow(attempt, 'initial');
  };

  const scheduleLaunch = (delay = NEXT_LAUNCH_DELAY): void => {
    if (launchTimer || !canLaunchAutomatically()) return;
    launchTimer = later(() => {
      launchTimer = 0;
      // Capacity and threat state can change after this timeout is armed.
      if (!canLaunchAutomatically()) return;

      const initialAttempt = initialAutomaticAttempts[initialAutomaticIndex];
      const row = initialAttempt
        ? getInitialAutomaticRow(initialAttempt)
        : createAmbientAttemptRow();
      if (
        (log && !row) ||
        !fire(row ?? undefined, false, initialAttempt)
      ) {
        scheduleLaunch(NEXT_LAUNCH_DELAY);
        return;
      }

      if (initialAttempt) {
        initialAutomaticIndex += 1;
        if (initialAutomaticIndex < initialAutomaticAttempts.length) {
          scheduleLaunch(AUTOMATIC_LAUNCH_STAGGER);
        }
      }
    }, delay);
  };

  const stopSchedulers = (): void => {
    clearOwnedTimeout(launchTimer);
    launchTimer = 0;
    clearOwnedTimeout(tickerFeedTimer);
    tickerFeedTimer = 0;
  };

  const startSchedulers = (firstDelay = FIRST_LAUNCH_DELAY): void => {
    if (paused || motionDisabled || document.hidden) return;
    scheduleTickerFeed();
    scheduleLaunch(firstDelay);
  };

  const settleForStaticMode = (message: string): void => {
    for (const [flight, record] of activeFlightRecords) {
      const removesCraft = flight.isConnected;
      if (removesCraft) {
        const restoreFocus =
          flight.contains(document.activeElement) || !!record.row?.contains(document.activeElement);
        returnRowToSpeculative(record.row, restoreFocus);
      }
      flight.remove();
    }
    for (const animation of activeAnimations) animation.cancel();
    activeAnimations.clear();

    // A capture may already have reparented its craft away from the flight
    // wrapper. Commit that craft to a static approved state rather than leave
    // a canceled FLIP and its jets stranded mid-phase.
    for (const [track, capture] of activeCaptures) {
      track.classList.remove('is-capturing');
      capture.satellite.classList.remove('is-capturing', 'is-capture-decaying');
      capture.satellite.classList.add('is-orbiting');
      capture.satellite.querySelector('.sat-booster')?.remove();
      capture.satellite.querySelector('.sat-rcs-system')?.remove();
      setSatelliteStatus(capture.satellite, 'approved');
      resolveLogRow(capture.row, 'approved');
      capture.scheduleRelease(STATIC_RESULT_HOLD);
    }
    activeCaptures.clear();
    activeFlightRecords.clear();
    activeFlights.clear();
    field
      .querySelectorAll<HTMLElement>('.authorization-satellite.is-capture-decaying')
      .forEach((satellite) => satellite.classList.remove('is-capture-decaying'));
    field.querySelectorAll<HTMLElement>('.authorization-track .sat-rcs-system').forEach((rcs) => rcs.remove());
    field.querySelectorAll<HTMLElement>('.authorization-track').forEach((track) => {
      track.style.animation = 'none';
      track.style.animationPlayState = 'paused';
    });
    for (const [key, orbit] of orbits) cleanupOrbitIfEmpty(key, orbit);
    closeTooltip();
    clearThreatState();
    announce(message);
  };

  const clearMotion = (): void => {
    for (const animation of activeAnimations) animation.cancel();
    activeAnimations.clear();
    log?.querySelectorAll<HTMLElement>('.hero-tui-row.has-sat').forEach((row) => {
      returnRowToSpeculative(row);
    });
    for (const flight of activeFlights) flight.remove();
    activeFlights.clear();
    activeFlightRecords.clear();
    activeCaptures.clear();
    field.querySelectorAll('.authorization-orbit').forEach((node) => node.remove());
    orbits.clear();
    closeTooltip();
    clearThreatState();
  };

  const settleCapturesForGeometry = (): void => {
    for (const capture of activeCaptures.values()) {
      if (capture.animation.playState !== 'finished') capture.animation.finish();
    }
  };

  const syncMotionPauseState = (closeActiveTooltip = false): void => {
    const shouldPause = shouldPauseMotion();
    hero?.classList.toggle('is-away', shouldPause);
    if (shouldSuspendTimeouts()) {
      suspendOwnedTimeouts();
      // The body-level shake cannot inherit `.hero.is-away`; remove it while
      // hidden and restart it when the remaining detection window is visible.
      if (threatDetectionTimer) document.documentElement.classList.remove('authorization-alert');
    } else {
      resumeOwnedTimeouts();
      if (threatDetectionTimer && activeThreatFlights.size > 0) {
        document.documentElement.classList.add('authorization-alert');
      }
    }
    if (shouldPause) {
      stopSchedulers();
      if (resizeRaf) {
        window.cancelAnimationFrame(resizeRaf);
        resizeRaf = 0;
        geometryDirty = true;
      }
      for (const animation of activeAnimations) animation.pause();
      if (closeActiveTooltip) closeTooltip();
    } else {
      if (geometryDirty) {
        geometryDirty = false;
        settleCapturesForGeometry();
      }
      syncResponsiveGeometry();
      // A forced capture settlement queues its finish handler asynchronously.
      // Never replay that finished FLIP from frame zero while the event drains.
      for (const animation of activeAnimations) {
        if (animation.playState === 'paused') animation.play();
      }
      startSchedulers();
    }
  };

  const onVisibility = () => syncMotionPauseState(document.hidden);

  const syncResponsiveGeometry = (): void => {
    for (const planet of planets) {
      const key = planetKey(planet);
      const styles = getComputedStyle(planet);
      const orbit = orbits.get(key);
      if (orbit) syncOrbitGeometry(orbit, planet, styles);

      for (const flight of activeFlights) {
        if (flight.dataset.planet !== key || !flight.isConnected) continue;
        flight.style.setProperty('--planet-x', styles.getPropertyValue('--planet-x').trim() || '50vw');
        flight.style.setProperty('--planet-y', styles.getPropertyValue('--planet-y').trim() || '50svh');
        flight.style.setProperty('--parallax-factor', styles.getPropertyValue('--parallax-factor').trim() || '0.2');
        if (orbit) flight.style.setProperty('--orbit-radius', `${orbit.offsetWidth / 2}px`);
      }
    }
  };

  const onResize = (): void => {
    if (shouldPauseMotion()) {
      geometryDirty = true;
      return;
    }
    if (resizeRaf) return;
    resizeRaf = window.requestAnimationFrame(() => {
      resizeRaf = 0;
      if (shouldPauseMotion()) {
        geometryDirty = true;
        return;
      }
      // A responsive destination can move underneath an in-progress fixed FLIP.
      // Settle that short arc first so resize/orientation changes cannot bend it
      // from stale coordinates or introduce a mid-capture teleport.
      settleCapturesForGeometry();
      syncResponsiveGeometry();
      refreshTooltipMetrics();
      if (tooltip?.classList.contains('is-visible') && !tooltipRaf) {
        tooltipRaf = window.requestAnimationFrame(positionTooltip);
      }
    });
  };
  document.addEventListener('visibilitychange', onVisibility);
  window.addEventListener('resize', onResize, { passive: true });
  hero?.addEventListener(PARALLAX_START_EVENT, onParallaxStart);

  const syncPowerMode = (): void => {
    const wasMotionDisabled = motionDisabled;
    lowPowerMode = requestsLowPower();
    motionDisabled = reduced.matches || lowPowerMode;
    hero?.classList.toggle('is-low-power', lowPowerMode);
    if (hero) hero.dataset.authorizationPower = lowPowerMode ? 'low' : 'full';
    if (motionDisabled === wasMotionDisabled) return;

    if (motionDisabled) {
      stopSchedulers();
      settleForStaticMode(
        reduced.matches
          ? 'Animation paused because reduced motion is enabled.'
          : 'Animation paused to conserve device power. Simulations remain available.',
      );
      syncMotionPauseState(true);
    } else {
      field
        .querySelectorAll<HTMLElement>('.authorization-track:not([data-static-simulation="true"])')
        .forEach((track) => {
          track.style.removeProperty('animation');
          track.style.animationPlayState = 'running';
        });
      syncMotionPauseState();
    }
  };
  const onReducedMotion = () => syncPowerMode();
  const onPowerHintChange = () => syncPowerMode();
  reduced.addEventListener('change', onReducedMotion);
  lowPowerPreference.addEventListener('change', onPowerHintChange);
  connection?.addEventListener('change', onPowerHintChange);

  try {
    const batteryPromise = powerNavigator.getBattery?.();
    if (batteryPromise) {
      void batteryPromise
        .then((manager) => {
          if (disposed) return;
          battery = manager;
          battery.addEventListener('chargingchange', onPowerHintChange);
          battery.addEventListener('levelchange', onPowerHintChange);
          syncPowerMode();
        })
        .catch(() => {});
    }
  } catch {
    // Battery Status is optional and may be blocked by browser policy.
  }

  // Pause scheduling and CSS motion when the hero is off-screen.
  const observer = new IntersectionObserver(
    ([entry]) => {
      paused = !entry?.isIntersecting || entry.intersectionRatio < 0.08;
      syncMotionPauseState(paused || document.hidden);
    },
    { root: null, threshold: 0.08, rootMargin: '0px' },
  );
  if (hero) observer.observe(hero);

  const logResizeObserver = log && typeof ResizeObserver !== 'undefined'
    ? new ResizeObserver(() => {
        if (disposed || tickerResizeRaf) return;
        tickerResizeRaf = window.requestAnimationFrame(() => {
          tickerResizeRaf = 0;
          if (disposed || !log) return;
          const previousCapacity = visibleLogCapacity(log);
          const nextCapacity = syncVisibleLogWindow(log);
          if (nextCapacity > previousCapacity) fillVisibleLogWindow();
          else trimSpeculativeOverflow();
        });
      })
    : null;
  if (log) {
    syncVisibleLogWindow(log);
    logResizeObserver?.observe(log);
  }

  if (log && log.children.length === 0) {
    const now = Date.now();
    // Fill the visible tail window immediately. The first three rows own the
    // deterministic opening vignette; the remaining rows are ordinary queued
    // traffic and retain the normal randomized outcome mix.
    const seedCount = Math.max(visibleLogCapacity(log), INITIAL_AUTOMATIC_OUTCOMES.length);
    const seededOutcomes: AuthOutcome[] = [
      ...INITIAL_AUTOMATIC_OUTCOMES,
      ...Array.from(
        { length: seedCount - INITIAL_AUTOMATIC_OUTCOMES.length },
        () => ambientOutcome(),
      ),
    ];
    seededOutcomes.forEach((outcome, index) => {
      const planet = planets[index % planets.length]!;
      const row = createAttemptRow(
        planetKey(planet),
        outcome,
        new Date(now - (seededOutcomes.length - index) * 12_000),
      );
      if (row && index < initialAutomaticAttempts.length) {
        row.dataset.trafficSource = 'initial';
        initialAutomaticAttempts[index]!.preferredRow = row;
      } else if (row) {
        row.dataset.trafficSource = 'feed';
      }
    });
  }
  fillVisibleLogWindow();

  syncMotionPauseState(motionDisabled);

  return () => {
    disposed = true;
    stopSchedulers();
    for (const timer of ownedTimeouts.values()) {
      if (timer.nativeId) window.clearTimeout(timer.nativeId);
    }
    ownedTimeouts.clear();
    if (tooltipRaf) window.cancelAnimationFrame(tooltipRaf);
    if (tickerResizeRaf) window.cancelAnimationFrame(tickerResizeRaf);
    document.removeEventListener('visibilitychange', onVisibility);
    window.removeEventListener('resize', onResize);
    hero?.removeEventListener(PARALLAX_START_EVENT, onParallaxStart);
    if (resizeRaf) window.cancelAnimationFrame(resizeRaf);
    reduced.removeEventListener('change', onReducedMotion);
    lowPowerPreference.removeEventListener('change', onPowerHintChange);
    connection?.removeEventListener('change', onPowerHintChange);
    battery?.removeEventListener('chargingchange', onPowerHintChange);
    battery?.removeEventListener('levelchange', onPowerHintChange);
    observer.disconnect();
    logResizeObserver?.disconnect();
    hero?.classList.remove('is-away', 'is-low-power');
    if (hero) delete hero.dataset.authorizationPower;
    clearMotion();
    log?.replaceChildren();
    tooltip?.remove();
    tooltip = null;
  };
}
