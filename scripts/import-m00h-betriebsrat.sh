#!/usr/bin/env bash
set -euo pipefail

SRC_HOST="${BR_M00H_HOST:-m00h}"
SRC_PATH="${BR_M00H_SOURCE_PATH:-/srv/tailshare/Betriebsrat/}"
DEST_ROOT="${BR_STORAGE_ROOT:-/srv/br-wissensdatenbank}"
DEST_PATH="${DEST_ROOT}/imports/m00h/"
LOG_DIR="${DEST_ROOT}/logs"
DATE_BIN="/usr/bin/date"
MKDIR_BIN="/usr/bin/mkdir"
CHMOD_BIN="/usr/bin/chmod"
RSYNC_BIN="/usr/bin/rsync"
FIND_BIN="/usr/bin/find"
SORT_BIN="/usr/bin/sort"
XARGS_BIN="/usr/bin/xargs"
SHA256SUM_BIN="/usr/bin/sha256sum"
TEE_BIN="/usr/bin/tee"
STAMP="$($DATE_BIN -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_DIR}/import-m00h-${STAMP}.log"

"$MKDIR_BIN" -p "$DEST_PATH" "$LOG_DIR"
"$CHMOD_BIN" 750 "$DEST_ROOT" "$DEST_PATH" "$LOG_DIR"

{
  echo "# m00h Betriebsrat Import"
  echo "timestamp=${STAMP}"
  echo "source=${SRC_HOST}:${SRC_PATH}"
  echo "destination=${DEST_PATH}"
  echo "mode=${1:-sync}"
  echo
  if [[ "${1:-sync}" == "dry-run" ]]; then
    "$RSYNC_BIN" -azn --delete --itemize-changes --protect-args "${SRC_HOST}:${SRC_PATH}" "$DEST_PATH"
  else
    "$RSYNC_BIN" -az --delete --itemize-changes --protect-args "${SRC_HOST}:${SRC_PATH}" "$DEST_PATH"
    echo
    echo "# sha256"
    "$FIND_BIN" "$DEST_PATH" -type f -print0 | "$SORT_BIN" -z | "$XARGS_BIN" -0 "$SHA256SUM_BIN"
  fi
} | "$TEE_BIN" "$LOG_FILE"

"$CHMOD_BIN" 640 "$LOG_FILE"
