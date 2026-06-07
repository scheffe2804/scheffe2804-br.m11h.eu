#!/usr/bin/env bash
set -euo pipefail

# Backup wrapper for the Betriebsrat knowledge base.
# Uses project-specific encrypted restic repo config where available.
# Secret values are expected in /etc/web-backup and are never printed.

ROOT="${BR_STORAGE_ROOT:-/srv/br-wissensdatenbank}"
PROJECT="br-wissensdatenbank"
DATE_BIN="/usr/bin/date"
MKDIR_BIN="/usr/bin/mkdir"
TOUCH_BIN="/usr/bin/touch"
CHMOD_BIN="/usr/bin/chmod"
DOCKER_BIN="/usr/bin/docker"
FIND_BIN="/usr/bin/find"
SORT_BIN="/usr/bin/sort"
AWK_BIN="/usr/bin/awk"
RM_BIN="/usr/bin/rm"
TEE_BIN="/usr/bin/tee"
STAMP="$($DATE_BIN -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${ROOT}/logs"
LOG_FILE="${LOG_DIR}/backup-${STAMP}.log"
BACKUP_ENV="${BR_BACKUP_ENV:-/etc/web-backup/repos.d/m11h-br-wissen.env}"
APP_DIR="${BR_APP_DIR:-/home/chris/web/br.m11h.eu}"
PROTOCOL_FILE="${BR_PROTOCOL_FILE:-/home/chris/web/diverses/betriebsrat.md}"
BACKUP_DIR="${ROOT}/backups"
DB_DUMP="${BACKUP_DIR}/postgres-${STAMP}.sql"
LOCAL_DUMP_KEEP="${BR_LOCAL_DUMP_KEEP:-20}"
BACKUP_LOG_KEEP="${BR_BACKUP_LOG_KEEP:-50}"
ALLOWED_RESTIC_PATHS=(/usr/bin/restic /usr/local/bin/restic)
RESTIC_BIN=""

run_preflight() {
  local label="$1"
  shift
  echo "${label}_preflight=running"
  if ! "$@"; then
    echo "status=${label}_preflight_failed"
    exit 1
  fi
}

umask 027
"$MKDIR_BIN" -p "$LOG_DIR" "$BACKUP_DIR"
"$TOUCH_BIN" "$LOG_FILE"
"$CHMOD_BIN" 640 "$LOG_FILE"

{
  echo "# BR Wissensdatenbank Backup"
  echo "timestamp=${STAMP}"
  echo "root=${ROOT}"
  echo "project=${PROJECT}"
  echo
  if [[ ! -f "$BACKUP_ENV" ]]; then
    echo "status=missing_backup_env"
    echo "backup_env=${BACKUP_ENV}"
    exit 1
  fi
  for candidate in "${ALLOWED_RESTIC_PATHS[@]}"; do
    if [[ -f "$candidate" && -x "$candidate" && ! -L "$candidate" ]]; then
      RESTIC_BIN="$candidate"
      break
    fi
  done
  if [[ -z "$RESTIC_BIN" ]]; then
    echo "status=missing_restic"
    exit 1
  fi
  echo "restic_bin=${RESTIC_BIN}"
  if ! [[ "$LOCAL_DUMP_KEEP" =~ ^[0-9]+$ ]] || [[ "$LOCAL_DUMP_KEEP" -lt 1 ]]; then
    echo "status=invalid_local_dump_keep"
    echo "local_dump_keep=${LOCAL_DUMP_KEEP}"
    exit 1
  fi
  if ! [[ "$BACKUP_LOG_KEEP" =~ ^[0-9]+$ ]] || [[ "$BACKUP_LOG_KEEP" -lt 1 ]]; then
    echo "status=invalid_backup_log_keep"
    echo "backup_log_keep=${BACKUP_LOG_KEEP}"
    exit 1
  fi
  if [[ ! -f "$PROTOCOL_FILE" ]]; then
    echo "status=missing_protocol_file"
    echo "protocol_file=${PROTOCOL_FILE}"
    exit 1
  fi
  if [[ -L "$PROTOCOL_FILE" ]]; then
    echo "status=protocol_file_is_symlink"
    echo "protocol_file=${PROTOCOL_FILE}"
    exit 1
  fi
  echo "protocol_file=${PROTOCOL_FILE}"
  echo "protocol_file_status=included"
  run_preflight host_context "${APP_DIR}/scripts/check-host-context.py" --summary
  run_preflight time_sync "${APP_DIR}/scripts/check-time-sync.py" --summary
  run_preflight compose_service "${APP_DIR}/scripts/check-compose-services.py" --summary
  run_preflight privilege_policy "${APP_DIR}/scripts/check-privilege-policy.py" --summary
  run_preflight privilege_risk_review "${APP_DIR}/scripts/check-privilege-risk-review.py" --summary --allow-accepted-risk
  run_preflight privilege_least_privilege_plan "${APP_DIR}/scripts/check-privilege-least-privilege-plan.py" --summary
  run_preflight privilege_remediation_gate "${APP_DIR}/scripts/check-privilege-remediation-gate.py" --summary
  run_preflight privilege_no_sudoers_change "${APP_DIR}/scripts/check-privilege-no-sudoers-change.py" --summary
  run_preflight core_source_hardening "${APP_DIR}/scripts/check-core-source-hardening.py" --summary
  run_preflight container_hardening "${APP_DIR}/scripts/check-container-hardening.py" --summary
  run_preflight container_source_hardening "${APP_DIR}/scripts/check-container-source-hardening.py" --summary
  run_preflight compose_source_hardening "${APP_DIR}/scripts/check-compose-source-hardening.py" --summary
  run_preflight network_source_hardening "${APP_DIR}/scripts/check-network-source-hardening.py" --summary
  run_preflight network_exposure "${APP_DIR}/scripts/check-network-exposure.py" --summary
  run_preflight public_dns_exposure "${APP_DIR}/scripts/check-public-dns-exposure.py" --summary
  run_preflight public_dns_multiresolver "${APP_DIR}/scripts/check-public-dns-multiresolver.py" --summary
  run_preflight public_dns_authoritative "${APP_DIR}/scripts/check-public-dns-authoritative.py" --summary
  run_preflight public_dns_caa "${APP_DIR}/scripts/check-public-dns-caa.py" --summary
  run_preflight direct_origin_bypass "${APP_DIR}/scripts/check-direct-origin-bypass.py" --summary
  run_preflight direct_origin_port_exposure "${APP_DIR}/scripts/check-direct-origin-port-exposure.py" --summary
  run_preflight host_udp_exposure "${APP_DIR}/scripts/check-host-udp-exposure.py" --summary
  run_preflight host_firewall_br_ports "${APP_DIR}/scripts/check-host-firewall-br-ports.py" --summary
  run_preflight host_nft_br_ports "${APP_DIR}/scripts/check-host-nft-br-ports.py" --summary
  run_preflight network_policy_consistency "${APP_DIR}/scripts/check-network-policy-consistency.py" --summary
  run_preflight network_policy_runtime_env "${APP_DIR}/scripts/check-network-policy-runtime-env.py" --summary
  run_preflight network_policy_runtime_summary "${APP_DIR}/scripts/check-network-policy-runtime-summary.py" --summary
  run_preflight artifact "${APP_DIR}/scripts/check-project-artifacts.sh" --summary
  run_preflight image_pinning "${APP_DIR}/scripts/check-image-pinning-guard.sh" --summary
  run_preflight systemd_unit "${APP_DIR}/scripts/check-systemd-units.sh" --summary
  run_preflight systemd_loaded_unit "${APP_DIR}/scripts/check-systemd-loaded-units.py" --summary
  run_preflight systemd_source_hardening "${APP_DIR}/scripts/check-systemd-source-hardening.py" --summary
  run_preflight status_source_hardening "${APP_DIR}/scripts/check-status-source-hardening.py" --summary
  run_preflight healthcheck_source_hardening "${APP_DIR}/scripts/check-healthcheck-source-hardening.py" --summary
  run_preflight operational_wrapper_source_hardening "${APP_DIR}/scripts/check-operational-wrapper-source-hardening.py" --summary
  run_preflight script_permission_policy "${APP_DIR}/scripts/check-script-permission-policy.py" --summary
  run_preflight python_syntax "${APP_DIR}/scripts/check-python-syntax.sh" --summary
  run_preflight shell_syntax "${APP_DIR}/scripts/check-shell-syntax.sh" --summary
  run_preflight guard_coverage "${APP_DIR}/scripts/check-guard-coverage.py" --summary
  run_preflight meta_source_hardening "${APP_DIR}/scripts/check-meta-source-hardening.py" --summary
  run_preflight doc_source_hardening "${APP_DIR}/scripts/check-doc-source-hardening.py" --summary
  run_preflight source_hardening_coverage "${APP_DIR}/scripts/check-source-hardening-coverage.py" --summary
  run_preflight summary_contract "${APP_DIR}/scripts/check-summary-contracts.py" --summary
  run_preflight surface_registry "${APP_DIR}/scripts/check-surface-registry.py" --summary
  run_preflight guard_registry_integrity "${APP_DIR}/scripts/check-guard-registry-integrity.py" --summary
  run_preflight protocol_integrity "${APP_DIR}/scripts/check-protocol-integrity.py" --summary
  run_preflight git_remote_readiness "${APP_DIR}/scripts/check-git-remote-readiness.py" --summary
  run_preflight access_runtime_source_hardening "${APP_DIR}/scripts/check-access-runtime-source-hardening.py" --summary
  run_preflight runtime_http_security "${APP_DIR}/scripts/check-runtime-http-security.py" --summary
  run_preflight external_access_surface "${APP_DIR}/scripts/check-external-access-surface.py" --summary
  run_preflight external_cookie_security "${APP_DIR}/scripts/check-external-cookie-security.py" --summary
  run_preflight tls_certificate "${APP_DIR}/scripts/check-tls-certificate.py" --summary
  run_preflight app_auth_surface "${APP_DIR}/scripts/check-app-auth-surface.py" --summary
  run_preflight import_pipeline "${APP_DIR}/scripts/check-import-pipeline.py" --summary
  run_preflight import_source_hardening "${APP_DIR}/scripts/check-import-source-hardening.py" --summary
  run_preflight answer_export_safety "${APP_DIR}/scripts/check-answer-export-safety.py" --summary
  run_preflight data_integrity_source_hardening "${APP_DIR}/scripts/check-data-integrity-source-hardening.py" --summary
  run_preflight audit_trail "${APP_DIR}/scripts/check-audit-trail.py" --summary
  run_preflight db_schema "${APP_DIR}/scripts/check-db-schema.py" --summary
  run_preflight backup_scope "${APP_DIR}/scripts/check-backup-scope.py" --summary
  run_preflight backup_runtime_policy "${APP_DIR}/scripts/check-backup-runtime-policy.py" --summary
  run_preflight restic_repository_check "${APP_DIR}/scripts/check-restic-repository-check.py" --summary
  run_preflight backup_source_hardening "${APP_DIR}/scripts/check-backup-source-hardening.py" --summary
  run_preflight restore_source_hardening "${APP_DIR}/scripts/check-restore-source-hardening.py" --summary
  run_preflight restore_runtime_policy "${APP_DIR}/scripts/check-restore-runtime-policy.py" --summary
  run_preflight freshness_source_hardening "${APP_DIR}/scripts/check-freshness-source-hardening.py" --summary
  run_preflight storage_source_hardening "${APP_DIR}/scripts/check-storage-source-hardening.py" --summary
  run_preflight storage_permission "${APP_DIR}/scripts/check-storage-permissions.py" --summary
  run_preflight storage_capacity "${APP_DIR}/scripts/check-storage-capacity.py" --summary
  run_preflight readiness_doc "${APP_DIR}/scripts/check-readiness-doc.py" --summary
  run_preflight regression_freshness "${APP_DIR}/scripts/check-regression-freshness.py" --summary
  run_preflight regression_source_hardening "${APP_DIR}/scripts/check-regression-source-hardening.py" --summary
  echo "backup_env=${BACKUP_ENV}"
  echo "creating_db_dump=${DB_DUMP}"
  "$DOCKER_BIN" compose -f "${APP_DIR}/docker-compose.yml" exec -T db pg_dump -U br_app -d br_wissen > "$DB_DUMP"
  "$CHMOD_BIN" 640 "$DB_DUMP"
  echo "local_dump_keep=${LOCAL_DUMP_KEEP}"
  mapfile -t old_dumps < <("$FIND_BIN" "$BACKUP_DIR" -maxdepth 1 -type f -name 'postgres-*.sql' -printf '%T@ %p\n' | "$SORT_BIN" -rn | "$AWK_BIN" -v keep="$LOCAL_DUMP_KEEP" 'NR>keep {sub(/^[^ ]+ /, ""); print}')
  if [[ "${#old_dumps[@]}" -gt 0 ]]; then
    printf 'removing_old_local_dumps=%d\n' "${#old_dumps[@]}"
    "$RM_BIN" -f -- "${old_dumps[@]}"
  else
    echo "removing_old_local_dumps=0"
  fi
  set -a
  # shellcheck disable=SC1090
  . "$BACKUP_ENV"
  set +a
  "$RESTIC_BIN" backup --host m11h --tag br-wissen --tag includes-internal-sources "$APP_DIR" "$ROOT" "$PROTOCOL_FILE"
  "$RESTIC_BIN" forget --host m11h --tag br-wissen --keep-last 20 --keep-daily 14 --keep-weekly 8 --keep-monthly 6 --prune
  echo "backup_log_keep=${BACKUP_LOG_KEEP}"
  mapfile -t old_logs < <("$FIND_BIN" "$LOG_DIR" -maxdepth 1 -type f -name 'backup-*.log' -printf '%T@ %p\n' | "$SORT_BIN" -rn | "$AWK_BIN" -v keep="$BACKUP_LOG_KEEP" 'NR>keep {sub(/^[^ ]+ /, ""); print}')
  if [[ "${#old_logs[@]}" -gt 0 ]]; then
    printf 'removing_old_backup_logs=%d\n' "${#old_logs[@]}"
    "$RM_BIN" -f -- "${old_logs[@]}"
  else
    echo "removing_old_backup_logs=0"
  fi
  echo "status=backup_done"
} | "$TEE_BIN" "$LOG_FILE"

"$CHMOD_BIN" 640 "$LOG_FILE"
