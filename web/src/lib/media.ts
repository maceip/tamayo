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

/**
 * An unfolded foldable should not swap navigation systems when browser chrome
 * changes the visual viewport by a pixel. Enter through a conservative device
 * window, then retain the layout through a wider resize band until the device
 * has clearly become a phone or desktop canvas.
 */
export function createFoldLayout(): Accessor<boolean> {
  const canEnter = () =>
    window.innerWidth >= 680 &&
    window.innerWidth <= 940 &&
    window.innerHeight >= 620;
  const canRemain = () =>
    window.innerWidth >= 680 &&
    window.innerWidth <= 980 &&
    window.innerHeight >= 540;

  const [active, setActive] = createSignal(canEnter());
  let resizeRaf = 0;

  const update = () => {
    if (resizeRaf) window.cancelAnimationFrame(resizeRaf);
    resizeRaf = window.requestAnimationFrame(() => {
      resizeRaf = 0;
      setActive((current) => (current ? canRemain() : canEnter()));
    });
  };

  window.addEventListener('resize', update, { passive: true });
  window.visualViewport?.addEventListener('resize', update, { passive: true });
  onCleanup(() => {
    if (resizeRaf) window.cancelAnimationFrame(resizeRaf);
    window.removeEventListener('resize', update);
    window.visualViewport?.removeEventListener('resize', update);
  });

  return active;
}

/** Reactive document visibility — true while the tab is in the foreground. */
export function createPageVisible(): Accessor<boolean> {
  const [visible, setVisible] = createSignal(!document.hidden);
  const onChange = () => setVisible(!document.hidden);
  document.addEventListener('visibilitychange', onChange);
  onCleanup(() => document.removeEventListener('visibilitychange', onChange));
  return visible;
}
