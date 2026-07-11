declare const __BUILD_ID__: string;

const RELOADED_KEY = 'tamayo-reloaded-for';

/**
 * GitHub Pages serves index.html with max-age=600 and the header cannot be
 * changed, so browsers keep showing a pre-deploy build for up to 10 minutes.
 * Compare our embedded build id against version.json (fetched with no-store,
 * so it skips the HTTP cache) and reload once when a newer deploy exists.
 * location.reload() revalidates the document, unlike plain navigation.
 */
async function checkFreshness(): Promise<void> {
  try {
    const res = await fetch(`${import.meta.env.BASE_URL}version.json`, { cache: 'no-store' });
    if (!res.ok) return;
    const { build } = (await res.json()) as { build?: string };
    if (!build || build === __BUILD_ID__) return;
    if (sessionStorage.getItem(RELOADED_KEY) === build) return; // avoid a reload loop
    sessionStorage.setItem(RELOADED_KEY, build);
    location.reload();
  } catch {
    // offline or fetch blocked - nothing to do
  }
}

export function watchFreshness(): void {
  if (import.meta.env.DEV) return;
  void checkFreshness();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') void checkFreshness();
  });
}
