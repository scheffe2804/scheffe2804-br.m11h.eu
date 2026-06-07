#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"
DOCKER_BIN="/usr/bin/docker"

cd "$ROOT"
"$DOCKER_BIN" compose exec -T app python - "$@" < scripts/healthcheck-br-wissen.py
