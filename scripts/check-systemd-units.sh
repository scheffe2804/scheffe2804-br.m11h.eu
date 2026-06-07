#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
summary=0

for arg in "$@"; do
  case "$arg" in
    --summary)
      summary=1
      ;;
    *)
      echo "Usage: check-systemd-units.sh [--summary]" >&2
      exit 2
      ;;
  esac
done

units=(
  br-wissen-healthcheck.service
  br-wissen-healthcheck.timer
  br-wissen-backup.service
  br-wissen-backup.timer
  br-wissen-import-m00h.service
  br-wissen-import-m00h.timer
  br-wissen-import-bag.service
  br-wissen-import-bag.timer
  br-wissen-restore-smoke.service
  br-wissen-restore-smoke.timer
)

timers=(
  br-wissen-healthcheck.timer
  br-wissen-backup.timer
  br-wissen-import-m00h.timer
  br-wissen-import-bag.timer
  br-wissen-restore-smoke.timer
)

services=(
  br-wissen-healthcheck.service
  br-wissen-backup.service
  br-wissen-import-m00h.service
  br-wissen-import-bag.service
  br-wissen-restore-smoke.service
)

sync_failures=0
timer_failures=0
unit_missing=0
failed_services=0

if [[ "$summary" -eq 0 ]]; then
  echo "# Systemd Unit Guard"
fi

for unit in "${units[@]}"; do
  src="${ROOT}/systemd/${unit}"
  dst="/etc/systemd/system/${unit}"
  status="ok"
  if [[ ! -f "$src" || ! -f "$dst" ]]; then
    status="missing"
    unit_missing=$((unit_missing + 1))
  elif ! cmp -s "$src" "$dst"; then
    status="diff"
    sync_failures=$((sync_failures + 1))
  fi
  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_unit_sync=%s status=%s\n' "$unit" "$status"
  fi
done

for timer in "${timers[@]}"; do
  timer_status="$(systemctl is-active "$timer" 2>/dev/null || true)"
  if [[ "$timer_status" != "active" ]]; then
    timer_failures=$((timer_failures + 1))
  fi
  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_timer=%s active=%s\n' "$timer" "$timer_status"
  fi
done

for service in "${services[@]}"; do
  service_state="$(systemctl is-failed "$service" 2>/dev/null || true)"
  if [[ "$service_state" == "failed" ]]; then
    failed_services=$((failed_services + 1))
  fi
  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_service=%s failed_state=%s\n' "$service" "$service_state"
  fi
done

violations=$((sync_failures + timer_failures + unit_missing + failed_services))
if [[ "$violations" -eq 0 ]]; then
  printf 'systemd_unit_guard_status=ok units=%d timers=%d services=%d sync_failures=0 missing_units=0 inactive_timers=0 failed_services=0\n' \
    "${#units[@]}" "${#timers[@]}" "${#services[@]}"
  exit 0
fi

printf 'systemd_unit_guard_status=fail units=%d timers=%d services=%d sync_failures=%d missing_units=%d inactive_timers=%d failed_services=%d\n' \
  "${#units[@]}" "${#timers[@]}" "${#services[@]}" "$sync_failures" "$unit_missing" "$timer_failures" "$failed_services"
exit 1
