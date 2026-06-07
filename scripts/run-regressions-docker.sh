#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"

cd "$ROOT"
docker compose exec -T app python - < scripts/run-regressions.py
