/** Planet parallax — rAF-throttled and clamped above the OSI Layer 1 header. */

const FACTORS: Record<string, number> = {
  finance: 0.22,
  device: 0.14,
  identity: 0.32,
  challenge: 0.26,
};

function planetKey(element: Element): string {
  return [...element.classList].find((name) => name !== 'auth-planet') || 'planet';
}

export function startPlanetParallax(hero: HTMLElement, field: HTMLElement): () => void {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const defenseLayer = hero.querySelector<HTMLElement>('[data-authorization-defense-layer]');
  const planets = [...field.querySelectorAll<HTMLElement>('.auth-planet')];
  for (const planet of planets) {
    planet.style.setProperty('--parallax-factor', String(FACTORS[planetKey(planet)] ?? 0.2));
  }

  let raf = 0;
  let scrolling = false;
  let scrollEndTimer = 0;
  let listening = false;

  const measureMax = () => {
    const tamago = document.getElementById('tamago');
    if (!tamago) return hero.offsetHeight * 0.35;
    const room = tamago.offsetTop - hero.offsetTop - 96;
    return Math.max(0, room * 0.55);
  };

  let maxShift = measureMax();

  const apply = () => {
    raf = 0;
    const scrolled = Math.max(0, window.scrollY - hero.offsetTop);
    const shift = Math.min(scrolled * 0.42, maxShift);
    field.style.setProperty('--parallax-scroll', `${shift}px`);
    defenseLayer?.style.setProperty('--parallax-scroll', `${shift}px`);
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

  const stopListening = () => {
    if (!listening) return;
    window.removeEventListener('scroll', onScroll);
    window.removeEventListener('resize', onResize);
    listening = false;
    window.clearTimeout(scrollEndTimer);
    if (raf) window.cancelAnimationFrame(raf);
    raf = 0;
    scrolling = false;
    hero.classList.remove('is-scrolling');
  };

  const startListening = () => {
    if (listening || reduced.matches) return;
    listening = true;
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onResize, { passive: true });
    onResize();
  };

  const onReducedMotion = (event: MediaQueryListEvent) => {
    if (event.matches) {
      stopListening();
      field.style.setProperty('--parallax-scroll', '0px');
      defenseLayer?.style.setProperty('--parallax-scroll', '0px');
    } else {
      startListening();
    }
  };

  reduced.addEventListener('change', onReducedMotion);
  startListening();
  if (reduced.matches) {
    field.style.setProperty('--parallax-scroll', '0px');
    defenseLayer?.style.setProperty('--parallax-scroll', '0px');
  }

  return () => {
    stopListening();
    reduced.removeEventListener('change', onReducedMotion);
    field.style.removeProperty('--parallax-scroll');
    defenseLayer?.style.removeProperty('--parallax-scroll');
  };
}
