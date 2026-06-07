#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"
LIMIT="${1:-25}"
DOCKER_BIN="/usr/bin/docker"

cd "$ROOT"
"$DOCKER_BIN" compose exec -T app python - "$LIMIT" < scripts/import-bag-feed.py
