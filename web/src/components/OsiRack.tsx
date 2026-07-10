import { For, onCleanup, onMount } from 'solid-js';
import { OSI_RACK_UNITS } from '../data/osiRack';

const RACK_UNITS_TOP_DOWN = [...OSI_RACK_UNITS].reverse();

/**
 * Oxide-inspired mini rack: CSS 3D chassis whose U-sleds separate slightly
 * as you scroll through the section (subtle explode, not a full teardown).
 */
export function OsiRack() {
  let sectionEl!: HTMLElement;
  let rackEl!: HTMLDivElement;

  onMount(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (reduced.matches) {
      rackEl.style.setProperty('--explode', '0.35');
      return;
    }

    let raf = 0;
    const update = () => {
      raf = 0;
      const rect = sectionEl.getBoundingClientRect();
      const vh = window.innerHeight || 1;
      // 0 when section enters mid-viewport, 1 as it settles / you scroll through it
      const start = vh * 0.85;
      const end = vh * 0.25;
      const raw = (start - rect.top) / (start - end);
      const explode = Math.min(1, Math.max(0, raw)) * 0.72; // “a little”
      rackEl.style.setProperty('--explode', explode.toFixed(3));
    };

    const onScroll = () => {
      if (!raf) raf = window.requestAnimationFrame(update);
    };

    update();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    onCleanup(() => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      if (raf) cancelAnimationFrame(raf);
    });
  });

  return (
    <section class="section osi-rack-section" id="stack" ref={sectionEl}>
      <div class="section-head">
        <h2>A different OSI stack</h2>
        <p>
          Eight layers: measured runtime at the bottom, policy above the tokens, and agents on top —
          the principals that actually spend those passes at machine speed. Scroll to pull the sleds apart.
        </p>
      </div>

      <div class="osi-rack-stage">
        <div class="osi-rack" ref={rackEl} style={{ '--explode': '0', '--units': String(OSI_RACK_UNITS.length) }}>
          <div class="osi-rack-frame" aria-hidden="true">
            <span class="osi-rack-post left" />
            <span class="osi-rack-post right" />
            <span class="osi-rack-top" />
            <span class="osi-rack-bottom" />
            <span class="osi-rack-depth" />
          </div>

          <ol class="osi-rack-units">
            <For each={RACK_UNITS_TOP_DOWN}>
              {(unit) => (
                <li
                  class="osi-u"
                  style={{
                    '--accent': unit.accent,
                  }}
                >
                  <a class="osi-u-face" href={unit.href}>
                    <span class="osi-u-led" aria-hidden="true" />
                    <span class="osi-u-layer">{unit.layer}</span>
                    <span class="osi-u-copy">
                      <strong>{unit.title}</strong>
                      <span>{unit.blurb}</span>
                    </span>
                    <span class="osi-u-handle" aria-hidden="true" />
                  </a>
                </li>
              )}
            </For>
          </ol>
        </div>
      </div>
    </section>
  );
}
