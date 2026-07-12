import { createSignal, onCleanup, type Accessor } from 'solid-js';

/**
 * Reactive matchMedia. Sampling `.matches` once at mount goes stale the moment
 * the user (or the OS, e.g. low-power mode) flips the preference — this tracks it.
 */
export function createMediaQuery(query: string): Accessor<boolean> {
  const mql = window.matchMedia(query);
  const [matches, setMatches] = createSignal(mql.matches);
  const onChange = (event: MediaQueryListEvent) => setMatches(event.matches);
  mql.addEventListener('change', onChange);
  onCleanup(() => mql.removeEventListener('change', onChange));
  return matches;
}

/** Reactive document visibility — true while the tab is in the foreground. */
export function createPageVisible(): Accessor<boolean> {
  const [visible, setVisible] = createSignal(!document.hidden);
  const onChange = () => setVisible(!document.hidden);
  document.addEventListener('visibilitychange', onChange);
  onCleanup(() => document.removeEventListener('visibilitychange', onChange));
  return visible;
}
