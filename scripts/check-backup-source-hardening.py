#!/usr/bin/env python3
"""Read-only source hardening guard for the BR-Wissen backup wrapper.

The guard validates the backup script source for expected fail-fast, preflight,
permission, dump, restic and retention markers. It only reads the backup wrapper
source and never reads backup env contents, dumps, logs, answers or source
documents. It does not run backups, restic, docker or systemctl.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
BACKUP_SCRIPT = ROOT / "scripts" / "backup-br-wissen.sh"


REQUIRED_LITERALS = [
    "set -euo pipefail",
    "umask 027",
    "DATE_BIN=\"/usr/bin/date\"",
    "MKDIR_BIN=\"/usr/bin/mkdir\"",
    "TOUCH_BIN=\"/usr/bin/touch\"",
    "CHMOD_BIN=\"/usr/bin/chmod\"",
    "DOCKER_BIN=\"/usr/bin/docker\"",
    "FIND_BIN=\"/usr/bin/find\"",
    "SORT_BIN=\"/usr/bin/sort\"",
    "AWK_BIN=\"/usr/bin/awk\"",
    "RM_BIN=\"/usr/bin/rm\"",
    "TEE_BIN=\"/usr/bin/tee\"",
    "BACKUP_ENV=\"${BR_BACKUP_ENV:-/etc/web-backup/repos.d/m11h-br-wissen.env}\"",
    "PROTOCOL_FILE=\"${BR_PROTOCOL_FILE:-/home/chris/web/diverses/betriebsrat.md}\"",
    "LOCAL_DUMP_KEEP=\"${BR_LOCAL_DUMP_KEEP:-20}\"",
    "BACKUP_LOG_KEEP=\"${BR_BACKUP_LOG_KEEP:-50}\"",
    "ALLOWED_RESTIC_PATHS=(/usr/bin/restic /usr/local/bin/restic)",
    "RESTIC_BIN=\"\"",
    "echo \"status=${label}_preflight_failed\"",
    "if [[ ! -f \"$BACKUP_ENV\" ]]; then",
    "status=missing_backup_env",
    "for candidate in \"${ALLOWED_RESTIC_PATHS[@]}\"; do",
    "if [[ -f \"$candidate\" && -x \"$candidate\" && ! -L \"$candidate\" ]]; then",
    "RESTIC_BIN=\"$candidate\"",
    "if [[ -z \"$RESTIC_BIN\" ]]; then",
    "status=missing_restic",
    "echo \"restic_bin=${RESTIC_BIN}\"",
    "status=invalid_local_dump_keep",
    "status=invalid_backup_log_keep",
    "status=missing_protocol_file",
    "status=protocol_file_is_symlink",
    "protocol_file_status=included",
    "\"$DOCKER_BIN\" compose -f \"${APP_DIR}/docker-compose.yml\" exec -T db pg_dump -U br_app -d br_wissen > \"$DB_DUMP\"",
    "\"$CHMOD_BIN\" 640 \"$DB_DUMP\"",
    "set -a",
    ". \"$BACKUP_ENV\"",
    "set +a",
    "\"$RESTIC_BIN\" backup --host m11h --tag br-wissen --tag includes-internal-sources \"$APP_DIR\" \"$ROOT\" \"$PROTOCOL_FILE\"",
    "\"$RESTIC_BIN\" forget --host m11h --tag br-wissen --keep-last 20 --keep-daily 14 --keep-weekly 8 --keep-monthly 6 --prune",
    "\"$FIND_BIN\" \"$BACKUP_DIR\" -maxdepth 1 -type f -name 'postgres-*.sql'",
    "\"$FIND_BIN\" \"$LOG_DIR\" -maxdepth 1 -type f -name 'backup-*.log'",
    "\"$RM_BIN\" -f -- \"${old_dumps[@]}\"",
    "\"$RM_BIN\" -f -- \"${old_logs[@]}\"",
    "echo \"status=backup_done\"",
    "} | \"$TEE_BIN\" \"$LOG_FILE\"",
    "\"$CHMOD_BIN\" 640 \"$LOG_FILE\"",
]


EXPECTED_PREFLIGHTS = [
    ("host_context", "check-host-context.py", "--summary"),
    ("time_sync", "check-time-sync.py", "--summary"),
    ("compose_service", "check-compose-services.py", "--summary"),
    ("privilege_policy", "check-privilege-policy.py", "--summary"),
    ("privilege_risk_review", "check-privilege-risk-review.py", "--summary --allow-accepted-risk"),
    ("privilege_least_privilege_plan", "check-privilege-least-privilege-plan.py", "--summary"),
    ("privilege_remediation_gate", "check-privilege-remediation-gate.py", "--summary"),
    ("privilege_no_sudoers_change", "check-privilege-no-sudoers-change.py", "--summary"),
    ("core_source_hardening", "check-core-source-hardening.py", "--summary"),
    ("container_hardening", "check-container-hardening.py", "--summary"),
    ("container_source_hardening", "check-container-source-hardening.py", "--summary"),
    ("compose_source_hardening", "check-compose-source-hardening.py", "--summary"),
    ("network_source_hardening", "check-network-source-hardening.py", "--summary"),
    ("network_exposure", "check-network-exposure.py", "--summary"),
    ("public_dns_exposure", "check-public-dns-exposure.py", "--summary"),
    ("public_dns_multiresolver", "check-public-dns-multiresolver.py", "--summary"),
    ("public_dns_authoritative", "check-public-dns-authoritative.py", "--summary"),
    ("public_dns_caa", "check-public-dns-caa.py", "--summary"),
    ("direct_origin_bypass", "check-direct-origin-bypass.py", "--summary"),
    ("direct_origin_port_exposure", "check-direct-origin-port-exposure.py", "--summary"),
    ("host_udp_exposure", "check-host-udp-exposure.py", "--summary"),
    ("host_firewall_br_ports", "check-host-firewall-br-ports.py", "--summary"),
    ("host_nft_br_ports", "check-host-nft-br-ports.py", "--summary"),
    ("network_policy_consistency", "check-network-policy-consistency.py", "--summary"),
    ("network_policy_runtime_env", "check-network-policy-runtime-env.py", "--summary"),
    ("network_policy_runtime_summary", "check-network-policy-runtime-summary.py", "--summary"),
    ("artifact", "check-project-artifacts.sh", "--summary"),
    ("image_pinning", "check-image-pinning-guard.sh", "--summary"),
    ("systemd_unit", "check-systemd-units.sh", "--summary"),
    ("systemd_source_hardening", "check-systemd-source-hardening.py", "--summary"),
    ("status_source_hardening", "check-status-source-hardening.py", "--summary"),
    ("healthcheck_source_hardening", "check-healthcheck-source-hardening.py", "--summary"),
    ("operational_wrapper_source_hardening", "check-operational-wrapper-source-hardening.py", "--summary"),
    ("python_syntax", "check-python-syntax.sh", "--summary"),
    ("shell_syntax", "check-shell-syntax.sh", "--summary"),
    ("guard_coverage", "check-guard-coverage.py", "--summary"),
    ("meta_source_hardening", "check-meta-source-hardening.py", "--summary"),
    ("doc_source_hardening", "check-doc-source-hardening.py", "--summary"),
    ("source_hardening_coverage", "check-source-hardening-coverage.py", "--summary"),
    ("summary_contract", "check-summary-contracts.py", "--summary"),
    ("surface_registry", "check-surface-registry.py", "--summary"),
    ("guard_registry_integrity", "check-guard-registry-integrity.py", "--summary"),
    ("protocol_integrity", "check-protocol-integrity.py", "--summary"),
    ("git_remote_readiness", "check-git-remote-readiness.py", "--summary"),
    ("access_runtime_source_hardening", "check-access-runtime-source-hardening.py", "--summary"),
    ("runtime_http_security", "check-runtime-http-security.py", "--summary"),
    ("external_access_surface", "check-external-access-surface.py", "--summary"),
    ("external_cookie_security", "check-external-cookie-security.py", "--summary"),
    ("tls_certificate", "check-tls-certificate.py", "--summary"),
    ("app_auth_surface", "check-app-auth-surface.py", "--summary"),
    ("import_pipeline", "check-import-pipeline.py", "--summary"),
    ("import_source_hardening", "check-import-source-hardening.py", "--summary"),
    ("answer_export_safety", "check-answer-export-safety.py", "--summary"),
    ("data_integrity_source_hardening", "check-data-integrity-source-hardening.py", "--summary"),
    ("audit_trail", "check-audit-trail.py", "--summary"),
    ("db_schema", "check-db-schema.py", "--summary"),
    ("backup_scope", "check-backup-scope.py", "--summary"),
    ("backup_runtime_policy", "check-backup-runtime-policy.py", "--summary"),
    ("restic_repository_check", "check-restic-repository-check.py", "--summary"),
    ("backup_source_hardening", "check-backup-source-hardening.py", "--summary"),
    ("restore_source_hardening", "check-restore-source-hardening.py", "--summary"),
    ("restore_runtime_policy", "check-restore-runtime-policy.py", "--summary"),
    ("freshness_source_hardening", "check-freshness-source-hardening.py", "--summary"),
    ("storage_source_hardening", "check-storage-source-hardening.py", "--summary"),
    ("storage_permission", "check-storage-permissions.py", "--summary"),
    ("storage_capacity", "check-storage-capacity.py", "--summary"),
    ("readiness_doc", "check-readiness-doc.py", "--summary"),
    ("regression_freshness", "check-regression-freshness.py", "--summary"),
    ("regression_source_hardening", "check-regression-source-hardening.py", "--summary"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen backup source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    if not BACKUP_SCRIPT.exists():
        findings.append("backup_script_missing")
        text = ""
    else:
        text = BACKUP_SCRIPT.read_text(encoding="utf-8", errors="replace")
    checks += 1

    for literal in REQUIRED_LITERALS:
        checks += 1
        if literal not in text:
            findings.append("missing_literal=%s" % re.sub(r"[^A-Za-z0-9_]+", "_", literal).strip("_"))

    actual_preflights = re.findall(r'^\s*run_preflight\s+([A-Za-z0-9_]+)\s+"\$\{APP_DIR\}/scripts/([^" ]+)"\s+(--summary(?:\s+--allow-accepted-risk)?)\s*$', text, re.MULTILINE)
    checks += 1
    if actual_preflights != EXPECTED_PREFLIGHTS:
        findings.append("preflight_chain_unexpected_count_%d" % len(actual_preflights))

    for label, script, args_value in EXPECTED_PREFLIGHTS:
        checks += 1
        expected_line = 'run_preflight %s "${APP_DIR}/scripts/%s" %s' % (label, script, args_value)
        if expected_line not in text:
            findings.append("missing_preflight=%s" % label)

    checks += 1
    if text.find("run_preflight host_context") > text.find("creating_db_dump="):
        findings.append("preflights_not_before_dump")
    checks += 1
    if text.find("creating_db_dump=") > text.find("\"$RESTIC_BIN\" backup"):
        findings.append("dump_not_before_restic")

    status = "ok" if not findings else "failed"
    summary = "backup_source_hardening_status=%s checks=%d findings=%d preflights=%d required_literals=%d" % (
        status,
        checks,
        len(findings),
        len(EXPECTED_PREFLIGHTS),
        len(REQUIRED_LITERALS),
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
