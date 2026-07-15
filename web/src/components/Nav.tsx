import { createEffect, createSignal, For, onCleanup, onMount } from 'solid-js';
import { createMediaQuery } from '../lib/media';
import { jumpToHash } from '../lib/pageNavigation';

/* Single source of truth for site navigation. Every nav surface (desktop
   header, mobile header, foldable rail) renders from this list, so they
   cannot drift apart. */
export const NAV_LINKS = [
  { href: '#agents', label: 'Agents', short: 'Agents' },
] as const;

export function Nav(_props: { foldLayout?: boolean }) {
  const [markSpinning, setMarkSpinning] = createSignal(false);
  const [markStoppedByUser, setMarkStoppedByUser] = createSignal(false);
  const reducedMotion = createMediaQuery('(prefers-reduced-motion: reduce)');
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

  onMount(() => {
    onCleanup(() => {
      cancelMarkNudge();
      markAnimation?.cancel();
    });
  });

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
        <a
          class="brand-home"
          href="#top"
          aria-label="Tamayo, back to top"
          onClick={(event) => jumpToHash(event, '#top')}
        >
          Tamayo
        </a>
      </div>
      <div class="nav-links">
        <For each={NAV_LINKS}>
          {(item) => (
            <a href={item.href} onClick={(event) => jumpToHash(event, item.href)}>
              {item.label}
            </a>
          )}
        </For>
        <a href="https://github.com/maceip/tamayo">GitHub</a>
      </div>
    </nav>
  );
}
