import { DialRoot, createDialKit } from 'dialkit/solid';
import 'dialkit/styles.css';
import { Nav } from './components/Nav';
import { Hero } from './components/Hero';
import { OsiRack } from './components/OsiRack';
import { StaticSections, PolicySection, AgentsSection } from './components/StaticSections';
import { TokenCatalogue } from './components/TokenCatalogue';
import { StoryBoard } from './components/StoryBoard';
import { CaseStudy } from './components/CaseStudy';
import { Footer } from './components/Footer';

function PageDials() {
  const page = createDialKit('Tamayo Pages', {
    heroScale: [1, 0.85, 1.2, 0.01],
    accentShift: { type: 'color' as const, default: '#2368ff' },
    storyAutoplay: true,
  });

  // Don't put transform:scale on a page-wide wrapper — it creates a containing
  // block and flattens/breaks the hero flight + orbit transform animations.
  return (
    <div style={{ '--blue': page().accentShift }}>
      <Nav />
      <Hero scale={page().heroScale} />
      <main>
        <OsiRack />
        <StaticSections />
        <TokenCatalogue />
        <PolicySection />
        <AgentsSection />
        <StoryBoard autoplay={page().storyAutoplay} />
        <CaseStudy />
      </main>
      <Footer />
    </div>
  );
}

export default function App() {
  return (
    <>
      <PageDials />
      <DialRoot
        productionEnabled
        position="top-right"
        theme="system"
        devSession={{
          projectKey: 'tamayo-pages',
          issueUrl: 'https://github.com/maceip/tamayo/issues/new',
        }}
      />
    </>
  );
}
