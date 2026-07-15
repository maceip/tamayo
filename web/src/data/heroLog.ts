/**
 * Data for the hero authorization-log TUI. Companies are audiences that
 * tokens get presented to; only four of them have visible planets in the
 * scene — the rest stream through the log as ambient traffic.
 *
 * Icons are vendored in public/icons so the live authorization log never
 * depends on a third-party request. See public/icons/README.md for provenance.
 */

const ICON_ROOT = `${import.meta.env.BASE_URL}icons`;

export const iconURL = (slug: string) => `${ICON_ROOT}/${slug}.svg`;

export type LogAudience = { slug: string; domain: string };

export const AUDIENCES: LogAudience[] = [
  { slug: 'openai', domain: 'openai.com' },
  { slug: 'claude', domain: 'anthropic.com' },
  { slug: 'paypal', domain: 'paypal.com' },
  { slug: 'spotify', domain: 'spotify.com' },
  { slug: 'digitalocean', domain: 'digitalocean.com' },
  { slug: 'github', domain: 'github.com' },
  { slug: 'cloudflare', domain: 'cloudflare.com' },
  { slug: 'stripe', domain: 'stripe.com' },
  { slug: 'netflix', domain: 'netflix.com' },
  { slug: 'slack', domain: 'slack.com' },
  { slug: 'discord', domain: 'discord.com' },
  { slug: 'dropbox', domain: 'dropbox.com' },
  { slug: 'notion', domain: 'notion.so' },
  { slug: 'reddit', domain: 'reddit.com' },
  { slug: 'shopify', domain: 'shopify.com' },
  { slug: 'tailscale', domain: 'tailscale.com' },
  { slug: 'twitch', domain: 'twitch.tv' },
  { slug: 'linkedin', domain: 'linkedin.com' },
  { slug: 'google', domain: 'google.com' },
  { slug: 'gitlab', domain: 'gitlab.com' },
  { slug: 'heroku', domain: 'heroku.com' },
  { slug: 'netlify', domain: 'netlify.com' },
  { slug: 'supabase', domain: 'supabase.com' },
  { slug: 'amazon-web-services', domain: 'aws.amazon.com' },
  { slug: 'proton-mail', domain: 'proton.me' },
  { slug: 'telegram', domain: 'telegram.org' },
  { slug: 'zoom', domain: 'zoom.us' },
];

/** The four planets that are actually animated map to fixed audiences. */
export const PLANET_AUDIENCE: Record<string, string> = {
  finance: 'paypal.com',
  identity: 'linkedin.com',
  device: 'google.com',
  challenge: 'cloudflare.com',
};

export type LogClient = { slug: string; name: string };

/** What presented the token. `termix` doubles as the generic CLI/SDK client icon. */
export const CLIENTS: LogClient[] = [
  { slug: 'thunderbird', name: 'thunderbird' },
  { slug: 'firefox', name: 'firefox-ext' },
  { slug: 'chromium', name: 'headless-chromium' },
  { slug: 'android', name: 'android-app' },
  { slug: 'apple', name: 'macos-app' },
  { slug: 'termix', name: 'go-sdk' },
  { slug: 'termix', name: 'cli' },
  { slug: 'docker', name: 'docker-job' },
  { slug: 'visual-studio-code', name: 'vscode-ext' },
  { slug: 'zed', name: 'zed-agent' },
];

/** Weighted toward the families a deployment actually mints most. */
export const TOKEN_FAMILIES: { name: string; weight: number }[] = [
  { name: 'private_identity', weight: 40 },
  { name: 'burn', weight: 30 },
  { name: 'policy_email', weight: 18 },
  { name: 'evt', weight: 12 },
];

export const DESKS = [
  'mint-01', 'mint-02', 'mint-03', 'mint-04',
  'mint-05', 'mint-06', 'mint-07', 'mint-08',
];
