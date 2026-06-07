#!/usr/bin/env bash
set -euo pipefail

SRC_HOST="${BR_M00H_HOST:-m00h}"
SRC_PATH="${BR_M00H_SOURCE_PATH:-/srv/tailshare/Betriebsrat/}"
DEST_ROOT="${BR_STORAGE_ROOT:-/srv/br-wissensdatenbank}"
DEST_PATH="${DEST_ROOT}/imports/m00h/"
LOG_DIR="${DEST_ROOT}/logs"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_DIR}/import-m00h-${STAMP}.log"

mkdir -p "$DEST_PATH" "$LOG_DIR"
chmod 750 "$DEST_ROOT" "$DEST_PATH" "$LOG_DIR"

{
  echo "# m00h Betriebsrat Import"
  echo "timestamp=${STAMP}"
  echo "source=${SRC_HOST}:${SRC_PATH}"
  echo "destination=${DEST_PATH}"
  echo "mode=${1:-sync}"
  echo
  if [[ "${1:-sync}" == "dry-run" ]]; then
    rsync -azn --delete --itemize-changes --protect-args "${SRC_HOST}:${SRC_PATH}" "$DEST_PATH"
  else
    rsync -az --delete --itemize-changes --protect-args "${SRC_HOST}:${SRC_PATH}" "$DEST_PATH"
    echo
    echo "# sha256"
    find "$DEST_PATH" -type f -print0 | sort -z | xargs -0 sha256sum
  fi
} | tee "$LOG_FILE"

chmod 640 "$LOG_FILE"
