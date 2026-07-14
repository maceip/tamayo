import { createSignal, For, onCleanup, onMount } from 'solid-js';
import { SECTION_LINKS } from './Nav';
import { jumpToHash } from '../lib/pageNavigation';

export function FoldRail() {
  const [active, setActive] = createSignal('top');

  onMount(() => {
    const sections = ['top', ...SECTION_LINKS.map((item) => item.href.slice(1))]
      .map((id) => document.getElementById(id))
      .filter((section): section is HTMLElement => !!section);

    const updateActive = () => {
      const targetLine = window.innerHeight * 0.3;
      const current = sections.reduce((candidate, section) => {
        return section.getBoundingClientRect().top <= targetLine ? section : candidate;
      }, sections[0]);
      if (current?.id) setActive(current.id);
    };

    const observer = new IntersectionObserver(
      updateActive,
      { rootMargin: '-12% 0px -68% 0px', threshold: [0, 0.08, 0.2, 0.45] },
    );

    sections.forEach((section) => observer.observe(section));
    updateActive();
    onCleanup(() => observer.disconnect());
  });

  return (
    <nav class="fold-rail" aria-label="Page sections">
      <a
        class="fold-rail-home"
        classList={{ active: active() === 'top' }}
        href="#top"
        onClick={(event) => jumpToHash(event, '#top')}
        aria-label="Back to top"
        aria-current={active() === 'top' ? 'location' : undefined}
      >
        <span aria-hidden="true">T</span>
      </a>
      <div class="fold-rail-links">
        <For each={SECTION_LINKS}>
          {(item, index) => {
            const id = item.href.slice(1);
            return (
              <a
                href={item.href}
                onClick={(event) => jumpToHash(event, item.href)}
                classList={{ active: active() === id }}
                aria-label={item.label}
                aria-current={active() === id ? 'location' : undefined}
              >
                <span class="fold-rail-index" aria-hidden="true">
                  {String(index() + 1).padStart(2, '0')}
                </span>
                <span>{item.short}</span>
              </a>
            );
          }}
        </For>
      </div>
      <a class="fold-rail-github" href="https://github.com/maceip/tamayo" aria-label="Tamayo on GitHub">
        <span aria-hidden="true">GH</span>
      </a>
    </nav>
  );
}
