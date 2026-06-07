#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen restore-smoke scripts.

The guard validates the restore-smoke wrapper and restore script source for
expected fail-fast, permission, isolation, cleanup, marker and retention markers.
It only reads project source files and never reads backup env contents, dumps,
logs, answers, restored files or source documents. It does not run restores,
restic, docker, sudo or systemctl.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
WRAPPER_SCRIPT = ROOT / "scripts" / "run-restore-smoke-drill.sh"
RESTORE_SCRIPT = ROOT / "scripts" / "restore-smoke-br-wissen.sh"


WRAPPER_LITERALS = [
    "set -euo pipefail",
    "ROOT=\"${BR_STORAGE_ROOT:-/srv/br-wissensdatenbank}\"",
    "APP_DIR=\"${BR_APP_DIR:-/home/chris/web/br.m11h.eu}\"",
    "LOG_FILE=\"${LOG_DIR}/restore-smoke-${STAMP}.log\"",
    "SNAPSHOT=\"${BR_RESTORE_SMOKE_SNAPSHOT:-latest}\"",
    "RESTORE_LOG_KEEP=\"${BR_RESTORE_LOG_KEEP:-20}\"",
    "restore_drill_status=invalid_restore_log_keep",
    "umask 027",
    "CHMOD_BIN=\"/usr/bin/chmod\"",
    "FIND_BIN=\"/usr/bin/find\"",
    "SORT_BIN=\"/usr/bin/sort\"",
    "AWK_BIN=\"/usr/bin/awk\"",
    "RM_BIN=\"/usr/bin/rm\"",
    "TEE_BIN=\"/usr/bin/tee\"",
    "\"$CHMOD_BIN\" 640 \"$LOG_FILE\"",
    "storage_capacity_preflight=running",
    "${APP_DIR}/scripts/check-storage-capacity.py\" --summary",
    "${APP_DIR}/scripts/restore-smoke-br-wissen.sh\" --snapshot \"$SNAPSHOT\" --db",
    "\"$FIND_BIN\" \"$LOG_DIR\" -maxdepth 1 -type f -name 'restore-smoke-*.log'",
    "\"$RM_BIN\" -f -- \"${old_logs[@]}\"",
    "restore_drill_status=ok",
    "} | \"$TEE_BIN\" \"$LOG_FILE\"",
]


RESTORE_LITERALS = [
    "set -euo pipefail",
    "APP_DIR=\"${BR_APP_DIR:-/home/chris/web/br.m11h.eu}\"",
    "BACKUP_ENV=\"${BR_BACKUP_ENV:-/etc/web-backup/repos.d/m11h-br-wissen.env}\"",
    "TARGET=\"/tmp/br-wissen-restore-smoke-${STAMP}\"",
    "PGVECTOR_IMAGE=\"pgvector/pgvector:pg16@sha256:",
    "DB_CONTAINER=\"br-wissen-restore-smoke-db-${STAMP}\"",
    "DB_VOLUME=\"br_wissen_restore_smoke_pgdata_${STAMP}\"",
    "DB_LOG=\"/tmp/br-wissen-restore-smoke-db-${STAMP}.log\"",
    "SQL_READY_WAIT=\"${BR_RESTORE_SQL_READY_WAIT:-15}\"",
    "DOCKER_BIN=\"/usr/bin/docker\"",
    "GREP_BIN=\"/usr/bin/grep\"",
    "RM_BIN=\"/usr/bin/rm\"",
    "SUDO_BIN=\"/usr/bin/sudo\"",
    "TEST_BIN=\"/usr/bin/test\"",
    "BASH_BIN=\"/usr/bin/bash\"",
    "RESTIC_BIN=\"/usr/bin/restic\"",
    "PYTHON_BIN=\"/usr/bin/python3.13\"",
    "FIND_BIN=\"/usr/bin/find\"",
    "WC_BIN=\"/usr/bin/wc\"",
    "TR_BIN=\"/usr/bin/tr\"",
    "STAT_BIN=\"/usr/bin/stat\"",
    "SORT_BIN=\"/usr/bin/sort\"",
    "AWK_BIN=\"/usr/bin/awk\"",
    "BASENAME_BIN=\"/usr/bin/basename\"",
    "SLEEP_BIN=\"/usr/bin/sleep\"",
    "SEQ_BIN=\"/usr/bin/seq\"",
    "PRINTF_BIN=\"/usr/bin/printf\"",
    "restore_status=invalid_snapshot",
    "restore_status=unsafe_target",
    "restore_status=missing_backup_env",
    "restore_status=missing_restic",
    "restore_status=target_exists",
    "restore_status=invalid_sql_ready_wait",
    "restore_sql_ready_wait=$SQL_READY_WAIT",
    "\"$3\" snapshots \"$2\" --host m11h --tag br-wissen --json",
    "restore_resolved_snapshot=$resolved_snapshot",
    "\"$DOCKER_BIN\" rm -f \"$DB_CONTAINER\"",
    "\"$DOCKER_BIN\" volume rm \"$DB_VOLUME\"",
    "\"$RM_BIN\" -f -- \"$DB_LOG\"",
    "\"$SUDO_BIN\" \"$RM_BIN\" -rf -- \"$TARGET\"",
    "/tmp/br-wissen-restore-*) \"$SUDO_BIN\" \"$RM_BIN\" -rf -- \"$TARGET\" ;;",
    "\"$SUDO_BIN\" \"$BASH_BIN\" -c 'set -euo pipefail; set -a; source \"$1\"; set +a; \"$4\" restore \"$2\" --host m11h --tag br-wissen --target \"$3\"'",
    "required_files=(",
    "restore_artifact_findings=",
    "restore_protocol_markers=yes",
    "restore_required_missing=$missing_required",
    "restore_latest_dump=$dump_name",
    "restore_latest_dump_size=$dump_size",
    "dump_marker_",
    "\"$DOCKER_BIN\" run -d --name \"$DB_CONTAINER\" --network none",
    "POSTGRES_PASSWORD=restore_test_password",
    "psql -v ON_ERROR_STOP=1",
    "restore_network_mode={{.HostConfig.NetworkMode}} restore_ports={{json .NetworkSettings.Ports}}",
    "db_restore_status=ok",
    "restore_cleanup=scheduled",
    "restore_status=ok",
]


EXPECTED_REQUIRED_FILES = [
    "$APP_RESTORE/docker-compose.yml",
    "$APP_RESTORE/app/main.py",
    "$APP_RESTORE/scripts/restore-smoke-br-wissen.sh",
    "$APP_RESTORE/scripts/check-answer-export-safety.py",
    "$APP_RESTORE/scripts/check-db-schema.py",
    "$APP_RESTORE/scripts/backup-br-wissen.sh",
    "$APP_RESTORE/scripts/status-br-wissen.sh",
    "$APP_RESTORE/systemd/br-wissen-healthcheck.service",
    "$APP_RESTORE/docs/READINESS.md",
    "$PROTOCOL_RESTORE",
]


EXPECTED_DUMP_MARKERS = [
    "PostgreSQL database dump",
    "CREATE TABLE",
    "COPY",
    "public.audit_log",
    "public.answers",
    "public.answer_statements",
    "public.answer_citations",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str]) -> str:
    if not path.exists():
        findings.append("missing_script=%s" % path.name)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require_literals(text: str, literals: list[str], label: str, findings: list[str]) -> int:
    checks = 0
    for literal in literals:
        checks += 1
        if literal not in text:
            findings.append("%s_missing_literal=%s" % (label, safe(literal)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen restore-smoke source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    checks = 0

    wrapper_text = read_source(WRAPPER_SCRIPT, findings)
    restore_text = read_source(RESTORE_SCRIPT, findings)
    checks += 2

    checks += require_literals(wrapper_text, WRAPPER_LITERALS, "wrapper", findings)
    checks += require_literals(restore_text, RESTORE_LITERALS, "restore", findings)

    checks += 1
    if 'case "$TARGET" in' not in restore_text or "/tmp/br-wissen-restore-*) ;;" not in restore_text:
        findings.append("restore_target_prefix_guard_missing")

    checks += 1
    if restore_text.find('restore_status=unsafe_target') > restore_text.find('"$SUDO_BIN" "$RM_BIN" -rf -- "$TARGET"'):
        findings.append("restore_unsafe_target_guard_after_cleanup")

    checks += 1
    if "trap cleanup EXIT" not in restore_text:
        findings.append("restore_cleanup_trap_missing")

    checks += 1
    if "--network none" not in restore_text:
        findings.append("restore_db_network_isolation_missing")

    checks += 1
    if '"$DOCKER_BIN" inspect "$DB_CONTAINER"' not in restore_text:
        findings.append("restore_db_network_metadata_missing")

    for required_file in EXPECTED_REQUIRED_FILES:
        checks += 1
        if required_file not in restore_text:
            findings.append("restore_required_file_missing=%s" % safe(required_file))

    for marker in EXPECTED_DUMP_MARKERS:
        checks += 1
        if marker not in restore_text:
            findings.append("restore_dump_marker_missing=%s" % safe(marker))

    checks += 1
    if wrapper_text.find("storage_capacity_preflight=running") > wrapper_text.find("restore_drill_status=ok"):
        findings.append("wrapper_preflight_not_before_restore")

    checks += 1
    if restore_text.find("sudo bash -c 'set -euo pipefail") > restore_text.find("restore_app_exists="):
        findings.append("restore_structure_checks_before_restore")

    status = "ok" if not findings else "failed"
    summary = "restore_source_hardening_status=%s checks=%d findings=%d scripts=2 wrapper_literals=%d restore_literals=%d required_files=%d dump_markers=%d" % (
        status,
        checks,
        len(findings),
        len(WRAPPER_LITERALS),
        len(RESTORE_LITERALS),
        len(EXPECTED_REQUIRED_FILES),
        len(EXPECTED_DUMP_MARKERS),
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
