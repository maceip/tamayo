#!/usr/bin/env bash
# Build the Solid Pages app and sync into docs/ for local Pages preview / commit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/web"
npm install
npm run typecheck
npm run build

mkdir -p "$ROOT/docs"
# Keep markdown docs; replace SPA shell + assets from the Vite build
rsync -a \
  --exclude 'implementation-inventory.md' \
  --exclude 'known-gaps.md' \
  --exclude 'pq-email-profile.md' \
  --exclude 'token-roadmap.md' \
  --exclude 'eggs' \
  --exclude 'style' \
  "$ROOT/web/dist/" "$ROOT/docs/"

test -f "$ROOT/docs/index.html"
echo "Published Solid SPA into docs/ ($(du -sh "$ROOT/docs" | awk '{print $1}'))"
