import { createSignal, For, Show } from 'solid-js';
import { tokens } from '../data/tokens';

export function TokenCatalogue() {
  const [index, setIndex] = createSignal(0);
  const token = () => tokens[index()]!;

  return (
    <section class="section" id="passes">
      <div class="section-head">
        <h2>OSI Layer 6: Tokens</h2>
        <p>
          Wire formats in <code>tokenprofile</code> and <code>emailtoken</code>: what the verifier
          learns, what stays hidden, and which checks the issuer runs before minting. Product UI is
          not in these packages.
        </p>
      </div>

      <div class="token-layout">
        <div class="token-buttons">
          <For each={tokens}>
            {(t, i) => (
              <button
                class="token-button bb-line t-card-resize"
                type="button"
                classList={{ active: i() === index() }}
                aria-pressed={i() === index() ? 'true' : 'false'}
                onClick={() => setIndex(i())}
              >
                <strong>{t.button}</strong>
                <span>{t.summary}</span>
              </button>
            )}
          </For>
        </div>
        <div class="token-detail bb t-token-swap" aria-live="polite">
          <div class="token-visual">
            <div class="mini-pass">
              <b>{token().name}</b>
              <span>{token().plain}</span>
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
