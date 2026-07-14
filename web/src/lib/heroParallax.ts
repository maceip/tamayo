/** Planet parallax — rAF-throttled and clamped above the OSI Layer 1 header. */

const FACTORS: Record<string, number> = {
  finance: 0.22,
  device: 0.14,
  identity: 0.32,
  challenge: 0.26,
};
const PARALLAX_START_EVENT = 'tamayo:hero-parallax-start';

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
  const initialRect = hero.getBoundingClientRect();
  let inView = initialRect.bottom > 0 && initialRect.top < window.innerHeight;

  const lowPower = () => hero.dataset.authorizationPower === 'low';
  const shouldListen = () => inView && !document.hidden && !reduced.matches && !lowPower();

  const measureMax = () => {
    const stack = document.getElementById('stack');
    if (!stack) return hero.offsetHeight * 0.35;
    const room = stack.offsetTop - hero.offsetTop - 96;
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
    let startedScrolling = false;
    if (!scrolling) {
      scrolling = true;
      startedScrolling = true;
      hero.classList.add('is-scrolling');
    }
    window.clearTimeout(scrollEndTimer);
    scrollEndTimer = window.setTimeout(() => {
      scrolling = false;
      hero.classList.remove('is-scrolling');
    }, 120);
    if (!raf) raf = window.requestAnimationFrame(apply);
    if (startedScrolling) {
      // Register the parallax write before waking the tooltip tracker so both
      // stay aligned without a permanent positioning loop.
      hero.dispatchEvent(new Event(PARALLAX_START_EVENT));
    }
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
    if (listening || !shouldListen()) return;
    listening = true;
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onResize, { passive: true });
    onResize();
  };

  const resetParallax = () => {
    field.style.setProperty('--parallax-scroll', '0px');
    defenseLayer?.style.setProperty('--parallax-scroll', '0px');
  };

  const syncListening = () => {
    if (shouldListen()) {
      startListening();
      return;
    }
    stopListening();
    if (reduced.matches || lowPower()) resetParallax();
  };

  const onReducedMotion = () => syncListening();
  const onVisibility = () => syncListening();

  reduced.addEventListener('change', onReducedMotion);
  document.addEventListener('visibilitychange', onVisibility);

  const viewObserver = new IntersectionObserver(
    ([entry]) => {
      inView = !!entry?.isIntersecting;
      syncListening();
    },
    { threshold: 0, rootMargin: '120px 0px' },
  );
  viewObserver.observe(hero);

  // The authorization controller owns dynamic power detection. Observe only
  // its compact data flag so parallax does not install a second battery/network
  // listener stack.
  const powerObserver = new MutationObserver(syncListening);
  powerObserver.observe(hero, { attributes: true, attributeFilter: ['data-authorization-power'] });
  syncListening();

  return () => {
    stopListening();
    reduced.removeEventListener('change', onReducedMotion);
    document.removeEventListener('visibilitychange', onVisibility);
    viewObserver.disconnect();
    powerObserver.disconnect();
    field.style.removeProperty('--parallax-scroll');
    defenseLayer?.style.removeProperty('--parallax-scroll');
  };
}
