# Tamayo Pages (Solid)

SolidJS rewrite of the Tamayo GitHub Pages explainer, with DialKit dials + Solid-native annotation toolbar.

## Develop

```bash
# from repo root (or web/)
cd web
npm install
npm run dev
```

Open http://127.0.0.1:5174/tamayo/

## Build for Pages

```bash
cd web
npm run build
# copies into ../docs via the pages workflow / scripts/publish-pages.sh
```

Output: `web/dist/` → published as the Pages site root.
