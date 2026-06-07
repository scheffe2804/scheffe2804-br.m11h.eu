#!/usr/bin/env bash
set -euo pipefail

# Wrapper for the automated BR-Wissen restore-smoke drill.
# It writes a compact metadata-only log with restrictive permissions and then
# rotates old restore-smoke logs. Secret values, dump contents and restored
# credential contents are never printed by the underlying restore script.

ROOT="${BR_STORAGE_ROOT:-/srv/br-wissensdatenbank}"
APP_DIR="${BR_APP_DIR:-/home/chris/web/br.m11h.eu}"
DATE_BIN="/usr/bin/date"
MKDIR_BIN="/usr/bin/mkdir"
TOUCH_BIN="/usr/bin/touch"
CHMOD_BIN="/usr/bin/chmod"
FIND_BIN="/usr/bin/find"
SORT_BIN="/usr/bin/sort"
AWK_BIN="/usr/bin/awk"
RM_BIN="/usr/bin/rm"
TEE_BIN="/usr/bin/tee"
LOG_DIR="${ROOT}/logs"
STAMP="$($DATE_BIN -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_DIR}/restore-smoke-${STAMP}.log"
SNAPSHOT="${BR_RESTORE_SMOKE_SNAPSHOT:-latest}"
RESTORE_LOG_KEEP="${BR_RESTORE_LOG_KEEP:-20}"

if ! [[ "$RESTORE_LOG_KEEP" =~ ^[0-9]+$ ]] || [[ "$RESTORE_LOG_KEEP" -lt 1 ]]; then
  echo "restore_drill_status=invalid_restore_log_keep"
  echo "restore_log_keep=${RESTORE_LOG_KEEP}"
  exit 1
fi

umask 027
"$MKDIR_BIN" -p "$LOG_DIR"
"$TOUCH_BIN" "$LOG_FILE"
"$CHMOD_BIN" 640 "$LOG_FILE"

{
  echo "# BR-Wissen Restore Smoke Drill"
  echo "timestamp=${STAMP}"
  echo "snapshot=${SNAPSHOT}"
  echo "restore_log=${LOG_FILE}"
  echo "storage_capacity_preflight=running"
  "${APP_DIR}/scripts/check-storage-capacity.py" --summary
  "${APP_DIR}/scripts/restore-smoke-br-wissen.sh" --snapshot "$SNAPSHOT" --db
  echo "restore_log_keep=${RESTORE_LOG_KEEP}"
  mapfile -t old_logs < <("$FIND_BIN" "$LOG_DIR" -maxdepth 1 -type f -name 'restore-smoke-*.log' -printf '%T@ %p\n' | "$SORT_BIN" -rn | "$AWK_BIN" -v keep="$RESTORE_LOG_KEEP" 'NR>keep {sub(/^[^ ]+ /, ""); print}')
  if [[ "${#old_logs[@]}" -gt 0 ]]; then
    printf 'removing_old_restore_logs=%d\n' "${#old_logs[@]}"
    "$RM_BIN" -f -- "${old_logs[@]}"
  else
    echo "removing_old_restore_logs=0"
  fi
  echo "restore_drill_status=ok"
} | "$TEE_BIN" "$LOG_FILE"

"$CHMOD_BIN" 640 "$LOG_FILE"
