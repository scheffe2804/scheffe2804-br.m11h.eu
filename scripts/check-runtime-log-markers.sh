#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${APP_DIR}"

containers=(
  br-wissen-proxy
  br-wissen-cloudflared
  br-wissen-app
  br-wissen-worker
  br-wissen-db
)

markers=(
  'Cf-Access-Jwt-Assertion'
  'Authorization'
  'Proxy-Authorization'
  'X-Auth-Token'
  'X-Api-Key'
)

status="ok"
findings=0

for container in "${containers[@]}"; do
  if ! docker inspect "${container}" >/dev/null 2>&1; then
    echo "runtime_log_marker_check=${container} status=missing_container findings=0"
    status="fail"
    continue
  fi

  container_findings=0
  for marker in "${markers[@]}"; do
    if docker logs "${container}" 2>&1 | grep -Fq -- "${marker}"; then
      container_findings=$((container_findings + 1))
    fi
  done

  findings=$((findings + container_findings))
  if (( container_findings > 0 )); then
    status="fail"
    echo "runtime_log_marker_check=${container} status=found findings=${container_findings}"
  else
    echo "runtime_log_marker_check=${container} status=ok findings=0"
  fi
done

echo "runtime_log_marker_status=${status} checks=${#containers[@]} markers=${#markers[@]} findings=${findings}"

if [[ "${status}" != "ok" ]]; then
  exit 1
fi
