import { createMemo, createSelector, createSignal, For, Show } from 'solid-js';
import { tokens } from '../data/tokens';

export function TokenCatalogue() {
  const [index, setIndex] = createSignal(0);
  const isSelected = createSelector(index);
  const token = createMemo(() => tokens[index()]!);

  return (
    <section class="section" id="passes">
      <div class="section-head">
        <h2>Token types</h2>
        <p>
          Four wire formats in <code>tokenprofile</code> and <code>emailtoken</code>. The family
          name below is the exact string that appears in policy files and log lines: what the
          verifier learns, what stays hidden, and what the issuer checks before minting.
        </p>
      </div>

      <div class="token-layout">
        <div class="token-buttons">
          <For each={tokens}>
            {(t, i) => (
              <button
                class="token-button bb-line t-card-resize"
                type="button"
                classList={{ active: isSelected(i()) }}
                aria-pressed={isSelected(i()) ? 'true' : 'false'}
                onClick={() => setIndex(i())}
              >
                <strong>{t.name}</strong>
                <code class="token-family">{t.family}</code>
                <span>{t.summary}</span>
              </button>
            )}
          </For>
        </div>
        <div class="token-detail bb t-token-swap" aria-live="polite">
          <div class="token-deck" data-tone={token().tone}>
            <div class="deck-grid" aria-hidden="true" />
            <div class="deck-chip" aria-hidden="true">
              <span class="chip-ring" />
              <span class="chip-core"><code>{token().family}</code></span>
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
