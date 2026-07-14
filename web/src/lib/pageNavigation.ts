let restoreScrollBehaviorRaf = 0;

function targetForHash(hash: string): HTMLElement | null {
  if (!hash.startsWith('#')) return null;
  const id = decodeURIComponent(hash.slice(1));
  return id ? document.getElementById(id) : null;
}

function targetScrollTop(target: HTMLElement): number {
  if (target.id === 'top') return 0;
  const margin = Number.parseFloat(getComputedStyle(target).scrollMarginTop) || 0;
  return Math.max(0, target.getBoundingClientRect().top + window.scrollY - margin);
}

/**
 * Move to a page section in the current frame. The temporary class prevents
 * the page-wide smooth-scroll preference from turning long rail jumps into a
 * multi-second tour through every intervening section.
 */
export function jumpToElement(target: HTMLElement): void {
  const root = document.documentElement;
  root.classList.add('is-instant-jump');
  document.scrollingElement?.scrollTo({ top: targetScrollTop(target), behavior: 'auto' });

  if (restoreScrollBehaviorRaf) window.cancelAnimationFrame(restoreScrollBehaviorRaf);
  restoreScrollBehaviorRaf = window.requestAnimationFrame(() => {
    restoreScrollBehaviorRaf = 0;
    root.classList.remove('is-instant-jump');
  });
}

export function jumpToCurrentHash(): boolean {
  const target = targetForHash(window.location.hash);
  if (!target) return false;
  jumpToElement(target);
  return true;
}

/** Preserve ordinary browser behavior for modified clicks and new tabs. */
export function jumpToHash(event: MouseEvent, hash: string): boolean {
  if (
    event.defaultPrevented ||
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey
  ) {
    return false;
  }

  const target = targetForHash(hash);
  if (!target) return false;

  event.preventDefault();
  if (window.location.hash === hash) window.history.replaceState(null, '', hash);
  else window.history.pushState(null, '', hash);
  jumpToElement(target);
  return true;
}
