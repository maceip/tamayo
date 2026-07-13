import { DialRoot, createDialKit } from 'dialkit/solid';
import 'dialkit/styles.css';
import { Nav } from './components/Nav';
import { Hero } from './components/Hero';
import { DeployTiers } from './components/DeployTiers';
import { StaticSections, AgentsSection } from './components/StaticSections';
import { PolicySection } from './components/PolicySection';
import { QuickStart } from './components/QuickStart';
import { TokenCatalogue } from './components/TokenCatalogue';
import { CaseStudy } from './components/CaseStudy';
import { Footer } from './components/Footer';

function PageDials() {
  const page = createDialKit('Tamayo Pages', {
    heroScale: [1, 0.85, 1.2, 0.01],
    accentShift: { type: 'color' as const, default: '#2368ff' },
  });

  // Don't put transform:scale on a page-wide wrapper — it creates a containing
  // block and flattens/breaks the hero flight + orbit transform animations.
  return (
    <div style={{ '--blue': page().accentShift }}>
      <Nav />
      <Hero scale={page().heroScale} />
      <main>
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
