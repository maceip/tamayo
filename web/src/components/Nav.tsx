import { createSignal, For, onCleanup, onMount, Show } from 'solid-js';

export const SECTION_LINKS = [
  { href: '#deployments', label: 'Deployments', short: 'Run' },
  { href: '#agents', label: 'Agents', short: 'Agents' },
  { href: '#policy', label: 'Policy', short: 'Policy' },
  { href: '#quickstart', label: 'Quick start', short: 'Start' },
  { href: '#passes', label: 'Tokens', short: 'Tokens' },
  { href: '#stack', label: 'Stack', short: 'Stack' },
  { href: '#sigbird', label: 'Case study', short: 'Case' },
] as const;

export function Nav() {
  const [open, setOpen] = createSignal(false);
  let menuButton!: HTMLButtonElement;

  onMount(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || !open()) return;
      setOpen(false);
      menuButton.focus();
    };
    document.addEventListener('keydown', closeOnEscape);
    onCleanup(() => document.removeEventListener('keydown', closeOnEscape));
  });

  const close = () => setOpen(false);

  return (
    <nav class="site-nav" aria-label="Main">
      <a class="brand" href="#top" aria-label="Tamayo, back to top">
        <span class="brand-mark" aria-hidden="true" />
        <span>Tamayo</span>
      </a>
      <div class="nav-links">
        <For each={SECTION_LINKS}>{(item) => <a href={item.href}>{item.label}</a>}</For>
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
