#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"
DOCKER_BIN="/usr/bin/docker"

if [[ $# -ne 1 ]]; then
  echo "Usage: export-answer-docker.sh <answer_uid>" >&2
  exit 2
fi

cd "$ROOT"
"$DOCKER_BIN" compose exec -T app python - "$1" < scripts/export-answer.py
