import { createMemo, createSelector, createSignal, For, Show } from 'solid-js';
import { tokens } from '../data/tokens';
import { DecorSatellite } from './SpaceDecor';

export function TokenCatalogue() {
  const [index, setIndex] = createSignal(0);
  const isSelected = createSelector(index);
  const token = createMemo(() => tokens[index()]!);
  let tabList!: HTMLDivElement;

  const selectFromKeyboard = (event: KeyboardEvent) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home'
      ? 0
      : event.key === 'End'
        ? tokens.length - 1
        : (index() + (event.key === 'ArrowRight' ? 1 : -1) + tokens.length) % tokens.length;
    setIndex(next);
    tabList.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  };

  return (
    <section class="section has-space-decor" id="passes">
      <DecorSatellite class="deco-sat-tokens" payload="burn" />
      <div class="section-head">
        <p class="section-path" aria-hidden="true">tamayo/tokens</p>
        <h2>Token types</h2>
        <p>
          Four wire formats in <code>tokenprofile</code> and <code>emailtoken</code>. The family
          name below is the exact string that appears in policy files and log lines: what the
          verifier learns, what stays hidden, and what the issuer checks before minting.
        </p>
      </div>

      <div class="token-layout">
        <div
          class="token-buttons"
          ref={tabList}
          role="tablist"
          aria-label="Token types"
          onKeyDown={selectFromKeyboard}
        >
          <For each={tokens}>
            {(t, i) => (
              <button
                class="token-button bb-line t-card-resize"
                type="button"
                id={`token-tab-${i()}`}
                role="tab"
                classList={{ active: isSelected(i()) }}
                aria-selected={isSelected(i()) ? 'true' : 'false'}
                aria-controls="token-panel"
                tabIndex={isSelected(i()) ? 0 : -1}
                onClick={() => setIndex(i())}
              >
                <strong>{t.name}</strong>
                <code class="token-family">{t.family}</code>
                <span>{t.summary}</span>
              </button>
            )}
          </For>
        </div>
        <div
          class="token-detail bb t-token-swap"
          id="token-panel"
          role="tabpanel"
          aria-labelledby={`token-tab-${index()}`}
          aria-live="polite"
        >
          <div class="token-deck" data-tone={token().tone}>
            <div class="deck-grid" aria-hidden="true" />
            <div class="deck-chip" aria-hidden="true">
              <span class="chip-ring" />
              <span class="chip-core">
                {/* Fit the wire name on a single line regardless of length. */}
                <code style={{ 'font-size': `${Math.min(15, 100 / (token().family.length * 0.62)).toFixed(1)}px` }}>
                  {token().family}
                </code>
              </span>
            </div>
            <div class="deck-plate">
              <b>{token().name}</b>
              <span>{token().plain}</span>
            </div>
            <div class="deck-readout" aria-hidden="true">
              <span>family = {token().family}</span>
              <span>stack &nbsp;= {token().stack}</span>
            </div>
          </div>
          <div class="token-facts">
            <div class="fact"><b>Verifier learns</b><span>{token().learns}</span></div>
            <div class="fact"><b>Stays hidden</b><span>{token().hidden}</span></div>
            <div class="fact"><b>Issuer sees</b><span>{token().issuer}</span></div>
            <div class="fact"><b>Like</b><span>{token().model}</span></div>
          </div>
          <Show when={token().note}>
            <div class="token-note" innerHTML={token().note} />
          </Show>
        </div>
      </div>
    </section>
  );
}
