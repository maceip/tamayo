export function Nav() {
  return (
    <nav class="site-nav" aria-label="Main">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true" />
        <span>Tamayo</span>
      </div>
      <div class="nav-links">
        <a href="#deployments">Deployments</a>
        <a href="#agents">Agents</a>
        <a href="#policy">Policy</a>
        <a href="#quickstart">Quick start</a>
        <a href="#passes">Tokens</a>
        <a href="#stack">Stack</a>
        <a href="#sigbird">Case study</a>
        <a href="https://github.com/maceip/tamayo">GitHub</a>
      </div>
    </nav>
  );
}
