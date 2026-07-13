import { createEffect, createSignal, For, onCleanup, onMount, Show } from 'solid-js';
import { createMediaQuery } from '../lib/media';

export const SECTION_LINKS = [
  { href: '#deployments', label: 'Deployments', short: 'Run' },
  { href: '#agents', label: 'Agents', short: 'Agents' },
  { href: '#policy', label: 'Policy', short: 'Policy' },
  { href: '#quickstart', label: 'Quick start', short: 'Start' },
  { href: '#passes', label: 'Tokens', short: 'Tokens' },
  { href: '#stack', label: 'Stack', short: 'Stack' },
  { href: '#sigbird', label: 'Case study', short: 'Case' },
] as const;

const DESKTOP_LINKS = SECTION_LINKS.filter((item) => item.href === '#agents');

export function Nav() {
  const [open, setOpen] = createSignal(false);
  const [markSpinning, setMarkSpinning] = createSignal(false);
  const [markStoppedByUser, setMarkStoppedByUser] = createSignal(false);
  const compactNav = createMediaQuery('(max-width: 920px)');
  const foldRail = createMediaQuery('(min-width: 700px) and (max-width: 900px) and (min-height: 700px)');
  const reducedMotion = createMediaQuery('(prefers-reduced-motion: reduce)');
  let menuButton!: HTMLButtonElement;
  let brandMark!: HTMLButtonElement;
  let brandMarkDisc!: HTMLSpanElement;
  let markAnimation: Animation | undefined;
  let pointerOverMark = false;
  let markFocused = false;
  let markNudgeRaf = 0;
  let pendingMarkMovement = 0;

  const cancelMarkNudge = () => {
    if (markNudgeRaf) window.cancelAnimationFrame(markNudgeRaf);
    markNudgeRaf = 0;
    pendingMarkMovement = 0;
  };

  createEffect(() => {
    if (!compactNav() || foldRail()) setOpen(false);
  });

  onMount(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || !open()) return;
      setOpen(false);
      menuButton.focus();
    };
    document.addEventListener('keydown', closeOnEscape);
    onCleanup(() => {
      document.removeEventListener('keydown', closeOnEscape);
      cancelMarkNudge();
      markAnimation?.cancel();
    });
  });

  const close = () => setOpen(false);

  const ensureMarkAnimation = () => {
    if (reducedMotion()) return undefined;
    if (!markAnimation) {
      markAnimation = brandMarkDisc.animate(
        [{ transform: 'rotate(0deg)' }, { transform: 'rotate(360deg)' }],
        { duration: 1_500, iterations: Infinity, easing: 'linear' },
      );
    }
    return markAnimation;
  };

  const startMarkSpin = () => {
    if (markStoppedByUser()) return;
    const animation = ensureMarkAnimation();
    if (!animation) return;
    animation.playbackRate = Math.max(1, animation.playbackRate || 1);
    animation.play();
    setMarkSpinning(true);
  };

  const pauseMarkSpin = () => {
    markAnimation?.pause();
    setMarkSpinning(false);
  };

  const nudgeMark = (event: PointerEvent) => {
    if (markStoppedByUser() || reducedMotion()) return;
    const movement = Math.hypot(event.movementX, event.movementY);
    if (movement < 1) return;
    pendingMarkMovement += movement;
    if (markNudgeRaf) return;
    markNudgeRaf = window.requestAnimationFrame(() => {
      markNudgeRaf = 0;
      const accumulatedMovement = pendingMarkMovement;
      pendingMarkMovement = 0;
      if (markStoppedByUser() || reducedMotion()) return;
      const animation = ensureMarkAnimation();
      if (!animation) return;
      animation.playbackRate = Math.min(8, Math.max(1, animation.playbackRate) + accumulatedMovement * .045);
      animation.play();
      setMarkSpinning(true);
    });
  };

  const resetMarkInteraction = () => {
    cancelMarkNudge();
    markAnimation?.cancel();
    markAnimation = undefined;
    setMarkSpinning(false);
    setMarkStoppedByUser(false);
  };

  const enterMark = () => {
    pointerOverMark = true;
    startMarkSpin();
  };

  const leaveMark = () => {
    pointerOverMark = false;
    if (!markFocused) resetMarkInteraction();
  };

  const focusMark = () => {
    markFocused = true;
    startMarkSpin();
  };

  const blurMark = () => {
    markFocused = false;
    if (!pointerOverMark) resetMarkInteraction();
  };

  const toggleMarkSpin = () => {
    if (reducedMotion()) return;
    if (markSpinning()) {
      setMarkStoppedByUser(true);
      cancelMarkNudge();
      pauseMarkSpin();
      return;
    }

    setMarkStoppedByUser(false);
    if (pointerOverMark || markFocused) startMarkSpin();
  };

  const markLabel = () => {
    if (reducedMotion()) return 'Tamayo mark animation is disabled while reduced motion is enabled.';
    if (markStoppedByUser()) return 'Tamayo mark animation is stopped. Activate to restart.';
    if (markSpinning()) return 'Tamayo mark animation is running. Activate to stop.';
    return 'Interactive Tamayo mark. Hover or focus to spin.';
  };

  createEffect(() => {
    if (reducedMotion()) {
      cancelMarkNudge();
      markAnimation?.cancel();
      markAnimation = undefined;
      setMarkSpinning(false);
      return;
    }
    if ((pointerOverMark || markFocused) && !markStoppedByUser()) startMarkSpin();
  });

  return (
    <nav class="site-nav" aria-label="Main">
      <div class="brand">
        <button
          class="brand-mark"
          type="button"
          ref={brandMark}
          aria-label={markLabel()}
          aria-pressed={markSpinning() ? 'true' : 'false'}
          aria-disabled={reducedMotion() ? 'true' : undefined}
          onPointerEnter={enterMark}
          onPointerMove={nudgeMark}
          onPointerLeave={leaveMark}
          onFocus={focusMark}
          onBlur={blurMark}
          onClick={toggleMarkSpin}
        >
          <span class="brand-mark-disc" aria-hidden="true" ref={brandMarkDisc} />
        </button>
        <a class="brand-home" href="#top" aria-label="Tamayo, back to top">Tamayo</a>
      </div>
      <div class="nav-links">
        <For each={DESKTOP_LINKS}>{(item) => <a href={item.href}>{item.label}</a>}</For>
        <a href="https://github.com/maceip/tamayo">GitHub</a>
      </div>
      <button
        class="nav-menu-button"
        type="button"
        ref={menuButton}
        aria-expanded={open() ? 'true' : 'false'}
        aria-controls="mobile-section-menu"
        onClick={() => setOpen((value) => !value)}
      >
        <span aria-hidden="true">{open() ? 'Close' : 'Explore'}</span>
        <span class="sr-only">{open() ? 'Close section menu' : 'Open section menu'}</span>
      </button>
      <Show when={open()}>
        <div id="mobile-section-menu" class="nav-mobile-menu">
          <span class="nav-mobile-kicker">Jump to</span>
          <For each={SECTION_LINKS}>
            {(item, index) => (
              <a href={item.href} onClick={close}>
                <span aria-hidden="true">{String(index() + 1).padStart(2, '0')}</span>
                <strong>{item.label}</strong>
              </a>
            )}
          </For>
          <a href="https://github.com/maceip/tamayo" onClick={close}>
            <span aria-hidden="true">↗</span>
            <strong>GitHub</strong>
          </a>
        </div>
      </Show>
    </nav>
  );
}
