/**
 * Static scenery reusing the hero's planet/satellite paint. These are
 * decoration only: no flight controller, no tooltips, no pointer events.
 */

const PAYLOAD_GLYPHS = {
  identity: '◆',
  burn: '✦',
  email: '✉',
  event: '↯',
} as const;

type PayloadName = keyof typeof PAYLOAD_GLYPHS;

export function DecorPlanet(props: { class?: string; ink?: string }) {
  return (
    <div
      class={`deco-planet ${props.class ?? ''}`}
      style={props.ink ? { '--planet-ink': props.ink } : undefined}
      aria-hidden="true"
    >
      <div class="auth-planet-body"></div>
    </div>
  );
}

export function DecorSatellite(props: { class?: string; payload: PayloadName }) {
  return (
    <span class={`deco-sat ${props.class ?? ''}`} aria-hidden="true">
      <span class="authorization-satellite">
        <span class="sat-panel sat-panel-left"></span>
        <span class="sat-bus">
          <span class="sat-bay"></span>
          <span class="sat-mast"></span>
          <span class="sat-dish"></span>
        </span>
        <span class="sat-panel sat-panel-right"></span>
        <span class={`sat-payload sat-payload-${props.payload}`}>
          <span class="sat-payload-gem"></span>
          <span class="sat-payload-glyph">{PAYLOAD_GLYPHS[props.payload]}</span>
        </span>
      </span>
    </span>
  );
}
