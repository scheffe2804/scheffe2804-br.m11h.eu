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
unit_policy_failures=0
parent_policy_failures=0
attr_policy_failures=0
failed_services=0
checks=0
LSATTR_BIN="$(command -v lsattr || true)"
GETFACL_BIN="$(command -v getfacl || true)"
GETFATTR_BIN="$(command -v getfattr || true)"
project_unit_owner="unknown"
project_unit_group="unknown"
if [[ -d "${ROOT}/systemd" ]]; then
  project_unit_owner="$(stat -c '%U' "${ROOT}/systemd")"
  project_unit_group="$(stat -c '%G' "${ROOT}/systemd")"
fi

check_attr_policy() {
  local path="$1"
  local label="$2"
  local path_type="$3"
  local flags output unexpected

  # Metadata-only filesystem attribute policy. lsattr is available on this host
  # and is used to fail closed on unexpected Linux file attributes. The normal
  # extents flag "e" is allowed; other visible attributes are treated as drift.
  # ACL/xattr tools are not installed here, so their availability is exposed in
  # the compact summary instead of installing packages or changing the system.
  checks=$((checks + 1))
  if [[ -z "$LSATTR_BIN" ]]; then
    attr_policy_failures=$((attr_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_attr_policy=%s status=lsattr_missing\n' "$label"
    fi
    return
  fi

  checks=$((checks + 1))
  if [[ "$path_type" == "dir" ]]; then
    output="$($LSATTR_BIN -d "$path" 2>/dev/null || true)"
  else
    output="$($LSATTR_BIN "$path" 2>/dev/null || true)"
  fi
  if [[ -z "$output" ]]; then
    attr_policy_failures=$((attr_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_attr_policy=%s status=unreadable\n' "$label"
    fi
    return
  fi
  flags="${output%%[[:space:]]*}"
  unexpected="${flags//-/}"
  unexpected="${unexpected//e/}"
  checks=$((checks + 1))
  if [[ -n "$unexpected" ]]; then
    attr_policy_failures=$((attr_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_attr_policy=%s status=unexpected flags=%s unexpected=%s\n' "$label" "$flags" "$unexpected"
    fi
    return
  fi
  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_attr_policy=%s status=ok flags=%s\n' "$label" "$flags"
  fi
}

check_parent_directory_policy() {
  local path="$1"
  local label="$2"
  local strict_mode="$3"
  local mode owner group

  # Scope note: project:systemd follows the project tree owner/group. The
  # root:root requirement is intentionally limited to the direct installed
  # /etc/systemd parents checked below. Vendor units below /usr/lib/systemd,
  # runtime units below /run/systemd and user units are outside this BR-Wissen
  # direct-unit guard because the project installs its managed units directly
  # into /etc/systemd/system/<unit>.

  checks=$((checks + 1))
  if [[ -L "$path" ]]; then
    parent_policy_failures=$((parent_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_parent_policy=%s status=symlink\n' "$label"
    fi
    return
  fi

  checks=$((checks + 1))
  if [[ ! -d "$path" ]]; then
    parent_policy_failures=$((parent_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_parent_policy=%s status=not_directory\n' "$label"
    fi
    return
  fi

  mode="$(stat -c '%a' "$path")"
  owner="$(stat -c '%U' "$path")"
  group="$(stat -c '%G' "$path")"

  checks=$((checks + 1))
  if [[ "$mode" =~ [0-7][0-7][2367]$ ]]; then
    parent_policy_failures=$((parent_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_parent_policy=%s status=world_writable mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
    fi
    return
  fi

  checks=$((checks + 1))
  if [[ "$strict_mode" == "installed" && ( "$owner" != "root" || "$group" != "root" ) ]]; then
    parent_policy_failures=$((parent_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_parent_policy=%s status=owner_unexpected mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
    fi
    return
  fi

  if [[ "$strict_mode" == "installed" && ( "$mode" =~ [2367][0-7]$ || "$mode" =~ [0-7][2367]$ ) ]]; then
    parent_policy_failures=$((parent_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_parent_policy=%s status=writable mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
    fi
    return
  fi

  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_parent_policy=%s status=ok mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
  fi
  check_attr_policy "$path" "$label" "dir"
}

check_unit_file_policy() {
  local path="$1"
  local label="$2"
  local strict_mode="$3"
  local mode owner group

  # Scope note: this checks only the direct project unit source files and the
  # direct /etc/systemd/system/<unit> files listed above. Normal systemd
  # enablement links below *.wants/ are not part of this guard's path set.

  checks=$((checks + 1))
  if [[ -L "$path" ]]; then
    unit_policy_failures=$((unit_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_unit_policy=%s status=symlink\n' "$label"
    fi
    return
  fi

  checks=$((checks + 1))
  if [[ ! -f "$path" ]]; then
    unit_policy_failures=$((unit_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_unit_policy=%s status=not_regular\n' "$label"
    fi
    return
  fi

  mode="$(stat -c '%a' "$path")"
  owner="$(stat -c '%U' "$path")"
  group="$(stat -c '%G' "$path")"

  checks=$((checks + 1))
  if [[ "$strict_mode" == "installed" && ( "$mode" =~ [2367][0-7]$ || "$mode" =~ [0-7][2367]$ ) ]]; then
    unit_policy_failures=$((unit_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_unit_policy=%s status=writable mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
    fi
    return
  fi

  if [[ "$mode" =~ [0-7][0-7][2367]$ ]]; then
    unit_policy_failures=$((unit_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_unit_policy=%s status=world_writable mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
    fi
    return
  fi

  checks=$((checks + 1))
  if [[ "$strict_mode" == "installed" && ( "$owner" != "root" || "$group" != "root" ) ]]; then
    unit_policy_failures=$((unit_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_unit_policy=%s status=owner_unexpected mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
    fi
    return
  fi

  if [[ "$strict_mode" == "project" && ( "$owner" != "$project_unit_owner" || "$group" != "$project_unit_group" ) ]]; then
    unit_policy_failures=$((unit_policy_failures + 1))
    if [[ "$summary" -eq 0 ]]; then
      printf 'systemd_unit_policy=%s status=project_owner_unexpected mode=%s owner=%s group=%s expected_owner=%s expected_group=%s\n' "$label" "$mode" "$owner" "$group" "$project_unit_owner" "$project_unit_group"
    fi
    return
  fi

  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_unit_policy=%s status=ok mode=%s owner=%s group=%s\n' "$label" "$mode" "$owner" "$group"
  fi
  check_attr_policy "$path" "$label" "file"
}

if [[ "$summary" -eq 0 ]]; then
  echo "# Systemd Unit Guard"
fi

check_parent_directory_policy "${ROOT}/systemd" "project:systemd" "project"
check_parent_directory_policy "/etc/systemd" "installed:/etc/systemd" "installed"
check_parent_directory_policy "/etc/systemd/system" "installed:/etc/systemd/system" "installed"

for unit in "${units[@]}"; do
  src="${ROOT}/systemd/${unit}"
  dst="/etc/systemd/system/${unit}"
  status="ok"
  checks=$((checks + 1))
  if [[ ! -f "$src" || ! -f "$dst" ]]; then
    status="missing"
    unit_missing=$((unit_missing + 1))
  elif ! cmp -s "$src" "$dst"; then
    status="diff"
    sync_failures=$((sync_failures + 1))
  fi
  if [[ -e "$src" ]]; then
    check_unit_file_policy "$src" "project:${unit}" "project"
  fi
  if [[ -e "$dst" ]]; then
    check_unit_file_policy "$dst" "installed:${unit}" "installed"
  fi
  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_unit_sync=%s status=%s\n' "$unit" "$status"
  fi
done

for timer in "${timers[@]}"; do
  checks=$((checks + 1))
  timer_status="$(systemctl is-active "$timer" 2>/dev/null || true)"
  if [[ "$timer_status" != "active" ]]; then
    timer_failures=$((timer_failures + 1))
  fi
  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_timer=%s active=%s\n' "$timer" "$timer_status"
  fi
done

for service in "${services[@]}"; do
  checks=$((checks + 1))
  service_state="$(systemctl is-failed "$service" 2>/dev/null || true)"
  if [[ "$service_state" == "failed" ]]; then
    failed_services=$((failed_services + 1))
  fi
  if [[ "$summary" -eq 0 ]]; then
    printf 'systemd_service=%s failed_state=%s\n' "$service" "$service_state"
  fi
done

violations=$((sync_failures + timer_failures + unit_missing + unit_policy_failures + parent_policy_failures + attr_policy_failures + failed_services))
if [[ "$violations" -eq 0 ]]; then
  printf 'systemd_unit_guard_status=ok checks=%d units=%d timers=%d services=%d sync_failures=0 missing_units=0 unit_policy_failures=0 parent_policy_failures=0 attr_policy_failures=0 lsattr_available=%d acl_tool_available=%d xattr_tool_available=%d inactive_timers=0 failed_services=0\n' \
    "$checks" "${#units[@]}" "${#timers[@]}" "${#services[@]}" "$([[ -n "$LSATTR_BIN" ]] && printf 1 || printf 0)" "$([[ -n "$GETFACL_BIN" ]] && printf 1 || printf 0)" "$([[ -n "$GETFATTR_BIN" ]] && printf 1 || printf 0)"
  exit 0
fi

printf 'systemd_unit_guard_status=fail checks=%d units=%d timers=%d services=%d sync_failures=%d missing_units=%d unit_policy_failures=%d parent_policy_failures=%d attr_policy_failures=%d lsattr_available=%d acl_tool_available=%d xattr_tool_available=%d inactive_timers=%d failed_services=%d\n' \
  "$checks" "${#units[@]}" "${#timers[@]}" "${#services[@]}" "$sync_failures" "$unit_missing" "$unit_policy_failures" "$parent_policy_failures" "$attr_policy_failures" "$([[ -n "$LSATTR_BIN" ]] && printf 1 || printf 0)" "$([[ -n "$GETFACL_BIN" ]] && printf 1 || printf 0)" "$([[ -n "$GETFATTR_BIN" ]] && printf 1 || printf 0)" "$timer_failures" "$failed_services"
exit 1
