#!/usr/bin/env bash
set -euo pipefail

# Read-only helper. Does not print env vars or tunnel tokens.
DOCKER_BIN="/usr/bin/docker"

echo "# cloudflared containers"
"$DOCKER_BIN" ps --filter ancestor=cloudflare/cloudflared:latest --format 'name={{.Names}} image={{.Image}} status={{.Status}}'
echo
echo "# warning"
echo "Do not inspect or print full cloudflared commands/env without secret review; tunnel tokens may be embedded."
