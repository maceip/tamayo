/** Planet parallax — rAF-throttled, clamped so craft never cross the OSI Layer 1 header. */

const FACTORS: Record<string, number> = {
  finance: 0.22,
  device: 0.14,
  identity: 0.32,
  challenge: 0.26,
};

function planetKey(el: Element): string {
  return [...el.classList].find((name) => name !== 'auth-planet') || 'planet';
}

export function startPlanetParallax(hero: HTMLElement, field: HTMLElement): () => void {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  if (reduced.matches) return () => {};

  const planets = [...field.querySelectorAll<HTMLElement>('.auth-planet')];
  for (const planet of planets) {
    const key = planetKey(planet);
    planet.style.setProperty('--parallax-factor', String(FACTORS[key] ?? 0.2));
  }

  let raf = 0;
  let scrolling = false;
  let scrollEndTimer = 0;

  const measureMax = () => {
    const tamago = document.getElementById('tamago');
    if (!tamago) return hero.offsetHeight * 0.35;
    // Room between hero top and OSI Layer 1 header — planets must not cross this.
    const room = tamago.offsetTop - hero.offsetTop - 96;
    return Math.max(0, room * 0.55);
  };

  let maxShift = measureMax();

  const apply = () => {
    raf = 0;
    const scrolled = Math.max(0, window.scrollY - hero.offsetTop);
    const shift = Math.min(scrolled * 0.42, maxShift);
    field.style.setProperty('--parallax-scroll', `${shift}px`);

    // Keep live orbits locked to the same parallax as their planet
    field.querySelectorAll<HTMLElement>('.authorization-orbit').forEach((orbit) => {
      const key = orbit.dataset.planet || 'planet';
      orbit.style.setProperty('--parallax-factor', String(FACTORS[key] ?? 0.2));
    });
  };

  const onScroll = () => {
    if (!scrolling) {
      scrolling = true;
      hero.classList.add('is-scrolling');
    }
    window.clearTimeout(scrollEndTimer);
    scrollEndTimer = window.setTimeout(() => {
      scrolling = false;
      hero.classList.remove('is-scrolling');
    }, 120);

    if (!raf) raf = window.requestAnimationFrame(apply);
  };

  const onResize = () => {
    maxShift = measureMax();
    apply();
  };

  apply();
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });

  return () => {
    window.removeEventListener('scroll', onScroll);
    window.removeEventListener('resize', onResize);
    window.clearTimeout(scrollEndTimer);
    if (raf) window.cancelAnimationFrame(raf);
    hero.classList.remove('is-scrolling');
    field.style.removeProperty('--parallax-scroll');
  };
}
