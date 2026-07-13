import { DialRoot, createDialKit } from 'dialkit/solid';
import 'dialkit/styles.css';
import { onCleanup, onMount } from 'solid-js';
import { Nav } from './components/Nav';
import { FoldRail } from './components/FoldRail';
import { Hero } from './components/Hero';
import { DeployTiers } from './components/DeployTiers';
import { StaticSections, AgentsSection } from './components/StaticSections';
import { PolicySection } from './components/PolicySection';
import { QuickStart } from './components/QuickStart';
import { TokenCatalogue } from './components/TokenCatalogue';
import { CaseStudy } from './components/CaseStudy';
import { Footer } from './components/Footer';
import { createMediaQuery } from './lib/media';

function PageDials() {
  const page = createDialKit('Tamayo Pages', {
    heroScale: [1, 0.85, 1.2, 0.01],
    accentShift: { type: 'color' as const, default: '#2368ff' },
  });

  onMount(() => {
    const sections = [...document.querySelectorAll<HTMLElement>('.section')];
    const margin = 240;
    const setInitialState = (section: HTMLElement) => {
      const rect = section.getBoundingClientRect();
      section.classList.toggle('is-offscreen', rect.bottom < -margin || rect.top > window.innerHeight + margin);
    };
    sections.forEach(setInitialState);

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          entry.target.classList.toggle('is-offscreen', !entry.isIntersecting);
        }
      },
      { rootMargin: `${margin}px 0px`, threshold: 0.01 },
    );
    sections.forEach((section) => observer.observe(section));
    onCleanup(() => observer.disconnect());
  });

  // Don't put transform:scale on a page-wide wrapper — it creates a containing
  // block and flattens/breaks the hero flight + orbit transform animations.
  return (
    <div class="page-shell" style={{ '--blue': page().accentShift }}>
      <a class="skip-link" href="#content">Skip to content</a>
      <Nav />
      <FoldRail />
      <Hero scale={page().heroScale} />
      <main id="content">
        <DeployTiers />
        <AgentsSection />
        <PolicySection />
        <QuickStart />
        <TokenCatalogue />
        <StaticSections />
        <CaseStudy />
      </main>
      <Footer />
    </div>
  );
}

export default function App() {
  const compactTools = createMediaQuery('(max-width: 920px)');

  return (
    <>
      <PageDials />
      <DialRoot
        productionEnabled
        position={compactTools() ? 'bottom-right' : 'top-right'}
        defaultOpen={!compactTools()}
        theme="system"
        devSession={{
          projectKey: 'tamayo-pages',
          issueUrl: 'https://github.com/maceip/tamayo/issues/new',
        }}
      />
    </>
  );
}
