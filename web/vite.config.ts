import { defineConfig, type Plugin } from 'vite';
import solid from 'vite-plugin-solid';
import { execSync } from 'node:child_process';

// GitHub Pages caches index.html for 10 minutes with no way to change the
// header, so stale HTML keeps shipping old asset URLs after a deploy. Stamp
// each build and emit version.json so the app can detect and self-refresh.
function buildId(): string {
  try {
    return execSync('git rev-parse --short HEAD').toString().trim();
  } catch {
    return String(Date.now());
  }
}

function versionFilePlugin(id: string): Plugin {
  return {
    name: 'emit-version-json',
    apply: 'build',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'version.json',
        source: JSON.stringify({ build: id }),
      });
    },
  };
}

const BUILD_ID = buildId();

export default defineConfig({
  plugins: [solid(), versionFilePlugin(BUILD_ID)],
  define: {
    __BUILD_ID__: JSON.stringify(BUILD_ID),
  },
  // GitHub Pages project site: https://maceip.github.io/tamayo/
  base: '/tamayo/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 5174,
  },
});
