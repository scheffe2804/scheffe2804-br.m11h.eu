#!/usr/bin/env python3
"""Read-only protocol integrity guard for the BR-Wissen project log.

The guard validates the project protocol file for expected structure, recent
guardrail block markers, backup inclusion markers and obvious credential/header
leak markers. It only reads the protocol file and backup wrapper source; it does
not run guards, Docker, systemctl, backups, restores, imports, regressions or
database queries and never reads secrets, dumps, logs, answers, exports or source
documents.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
PROTOCOL = Path(os.getenv("BR_PROTOCOL", "/home/chris/web/diverses/betriebsrat.md"))
BACKUP_SCRIPT = ROOT / "scripts" / "backup-br-wissen.sh"


REQUIRED_PROTOCOL_MARKERS: list[tuple[str, str]] = [
    ("title", "# betriebsrat"),
    ("protocol_heading", "## Protokoll"),
    ("br_wissen_project", "/home/chris/web/br.m11h.eu"),
    ("root_backup_context", "Root-Kontext-Backup"),
    ("no_container_restart", "Keine produktiven Container"),
    ("no_real_imports", "Keine echten Importlaeufe"),
    ("no_regressions", "keine neuen Regressionen"),
    ("summary_contract_block", "## Wartung 2026-06-05 Summary-Contract-Guard"),
    ("surface_registry_block", "## Wartung 2026-06-05 Surface-Registry-Guard"),
    ("guard_registry_integrity_block", "## Wartung 2026-06-05 Guard-Registry-Integrity"),
    ("protocol_integrity_block", "## Wartung 2026-06-05 Protocol-Integrity-Guard"),
    ("backup_scope_block", "## Wartung 2026-06-05 Backup-Scope-Guard"),
    ("backup_runtime_policy_block", "## Wartung 2026-06-05 Backup-Runtime-Policy-Guard"),
    ("restore_runtime_policy_block", "## Wartung 2026-06-05 Restore-Runtime-Policy-Guard"),
    ("protocol_integrity_status", "protocol_integrity_status=ok"),
    ("backup_scope_status", "backup_scope_status=ok"),
    ("backup_runtime_policy_status", "backup_runtime_policy_status=ok"),
    ("restore_runtime_policy_status", "restore_runtime_policy_status=ok"),
    ("surface_registry_status", "surface_registry_status=ok"),
    ("guard_registry_integrity_status", "guard_registry_integrity_status=ok"),
    ("backup_done", "status=backup_done"),
    ("backup_freshness", "backup_freshness_status=ok"),
    ("restore_freshness", "restore_freshness_status=ok"),
    ("healthcheck_success", "ExecMainStatus=0"),
]


REQUIRED_BACKUP_MARKERS: list[tuple[str, str]] = [
    ("protocol_default", "PROTOCOL_FILE=\"${BR_PROTOCOL_FILE:-/home/chris/web/diverses/betriebsrat.md}\""),
    ("protocol_missing_status", "status=missing_protocol_file"),
    ("protocol_symlink_status", "status=protocol_file_is_symlink"),
    ("protocol_included", "protocol_file_status=included"),
    ("restic_includes_protocol", "\"$RESTIC_BIN\" backup --host m11h --tag br-wissen --tag includes-internal-sources \"$APP_DIR\" \"$ROOT\" \"$PROTOCOL_FILE\""),
]


FORBIDDEN_PROTOCOL_MARKERS = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "password=",
    "passwd=",
    "token=",
    "secret=",
    "DATABASE_URL=postgres",
    "MATOMO_AUTH_TOKEN",
    "MATOMO_TOKEN_AUTH",
    "GOOGLE_APPLICATION_CREDENTIALS=",
    "Authorization:",
    "Cookie:",
    "Set-Cookie:",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_text(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    if path.is_symlink():
        findings.append("symlink_file=%s" % label)
        return ""
    if not path.is_file():
        findings.append("not_regular_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def check_markers(findings: list[str], text: str, markers: list[tuple[str, str]], prefix: str) -> int:
    checks = 0
    for label, marker in markers:
        checks += 1
        if marker not in text:
            findings.append("%s_missing=%s" % (prefix, safe(label)))
    return checks


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen project protocol integrity")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    protocol_text = read_text(PROTOCOL, findings, "protocol")
    backup_text = read_text(BACKUP_SCRIPT, findings, "backup_script")
    checks += 2

    if protocol_text:
        st = PROTOCOL.stat()
        mode = stat.S_IMODE(st.st_mode)
        checks += 4
        if mode & 0o002:
            findings.append("protocol_world_writable")
        if len(protocol_text) < 10_000:
            findings.append("protocol_too_small")
        if not protocol_text.startswith("# betriebsrat\n"):
            findings.append("protocol_title_not_first")
        if protocol_text.count("## Wartung 2026-06-05") < 5:
            findings.append("recent_wartung_blocks_too_few")

    checks += check_markers(findings, protocol_text, REQUIRED_PROTOCOL_MARKERS, "protocol")
    checks += check_markers(findings, backup_text, REQUIRED_BACKUP_MARKERS, "backup")
    checks += check_forbidden(findings, protocol_text, FORBIDDEN_PROTOCOL_MARKERS, "protocol")

    checks += 1
    if protocol_text.find("## Wartung 2026-06-05 Guard-Registry-Integrity") < protocol_text.find("## Wartung 2026-06-05 Surface-Registry-Guard"):
        findings.append("protocol_registry_integrity_before_surface_registry")
    checks += 1
    if protocol_text.find("## Wartung 2026-06-05 Backup-Scope-Guard") < protocol_text.find("## Wartung 2026-06-05 Protocol-Integrity-Guard"):
        findings.append("protocol_backup_scope_before_protocol_integrity")
    checks += 1
    if protocol_text.find("## Wartung 2026-06-05 Backup-Runtime-Policy-Guard") < protocol_text.find("## Wartung 2026-06-05 Backup-Scope-Guard"):
        findings.append("protocol_backup_runtime_policy_before_backup_scope")
    checks += 1
    if protocol_text.find("## Wartung 2026-06-05 Restore-Runtime-Policy-Guard") < protocol_text.find("## Wartung 2026-06-05 Backup-Runtime-Policy-Guard"):
        findings.append("protocol_restore_runtime_policy_before_backup_runtime_policy")

    status = "ok" if not findings else "failed"
    summary = "protocol_integrity_status=%s checks=%d findings=%d protocol_markers=%d backup_markers=%d forbidden_markers=%d protocol_bytes=%d" % (
        status,
        checks,
        len(findings),
        len(REQUIRED_PROTOCOL_MARKERS),
        len(REQUIRED_BACKUP_MARKERS),
        len(FORBIDDEN_PROTOCOL_MARKERS),
        len(protocol_text.encode("utf-8")) if protocol_text else 0,
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
