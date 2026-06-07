#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"
LIMIT="${1:-25}"

cd "$ROOT"
docker compose exec -T app python - "$LIMIT" < scripts/import-bag-feed.py
