#!/usr/bin/env python3
"""Read-only restore-smoke freshness guard for BR-Wissen.

The guard prints only log-derived metadata and counters. It never prints
restore log bodies, dump contents, secret values or credential file contents.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
APP_DIR = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
BACKUP_ENV = Path(os.getenv("BR_BACKUP_ENV", "/etc/web-backup/repos.d/m11h-br-wissen.env"))
PROTOCOL_FILE = Path(os.getenv("BR_PROTOCOL_FILE", "/home/chris/web/diverses/betriebsrat.md"))
LOG_DIR = ROOT / "logs"
RESTORE_LOG_KEEP = int(os.getenv("BR_RESTORE_LOG_KEEP", "20"))
MIN_DUMP_BYTES = int(os.getenv("BR_MIN_DUMP_BYTES", str(1_000_000)))
EXPECTED_TAGS = {"br-wissen", "includes-internal-sources"}
EXPECTED_PATHS = {str(APP_DIR), str(ROOT), str(PROTOCOL_FILE)}
SCRIPT = Path(__file__).resolve()
SELF_PARENT_DIRS = (APP_DIR, SCRIPT.parent)
SELF_SCRIPT_MIN_BYTES = 10_000
SUDO = Path("/usr/bin/sudo")
TEST = Path("/usr/bin/test")
BASH = Path("/usr/bin/bash")
ALLOWED_PYTHON_PATHS = (
    Path("/usr/bin/python3.13"),
    Path("/usr/bin/python3.12"),
    Path("/usr/bin/python3.11"),
    Path("/usr/local/bin/python3.13"),
    Path("/usr/local/bin/python3.12"),
    Path("/usr/local/bin/python3.11"),
)
ALLOWED_RESTIC_PATHS = (Path("/usr/bin/restic"), Path("/usr/local/bin/restic"))


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def collect_restore_info() -> dict[str, Any]:
    logs = sorted(LOG_DIR.glob("restore-smoke-*.log"), key=lambda p: p.stat().st_mtime, reverse=True) if LOG_DIR.exists() else []
    latest = logs[0] if logs else None
    text = latest.read_text(encoding="utf-8", errors="replace") if latest else ""

    def match(pattern: str) -> str:
        found = re.search(pattern, text, re.MULTILINE)
        return found.group(1) if found else ""

    def int_match(pattern: str) -> int:
        value = match(pattern)
        try:
            return int(value)
        except ValueError:
            return 0

    return {
        "log_count": len(logs),
        "latest_log_path": str(latest) if latest else "",
        "latest_log_mtime": latest.stat().st_mtime if latest else 0,
        "latest_log_size": latest.stat().st_size if latest else 0,
        "latest_log_mode": stat.S_IMODE(latest.stat().st_mode) if latest else 0,
        "restore_drill_done": "restore_drill_status=ok" in text,
        "restore_status_ok": "restore_status=ok" in text,
        "db_restore_status_ok": "db_restore_status=ok" in text,
        "storage_capacity_status_ok": "storage_capacity_status=ok" in text,
        "restore_snapshot": match(r"^snapshot=(.+)$"),
        "restore_resolved_snapshot": match(r"^restore_resolved_snapshot=([0-9a-f]+)$"),
        "restore_sql_ready_wait": int_match(r"^restore_sql_ready_wait=([0-9]+)$"),
        "restore_latest_dump": match(r"^restore_latest_dump=(.+)$"),
        "restore_latest_dump_size": int_match(r"^restore_latest_dump_size=([0-9]+)$"),
        "restore_required_missing": int_match(r"^restore_required_missing=([0-9]+)$"),
        "restore_artifact_findings": int_match(r"^restore_artifact_findings=([0-9]+)$"),
        "restore_protocol_exists": "restore_protocol_exists=yes" in text,
        "restore_protocol_markers": "restore_protocol_markers=yes" in text,
        "restore_protocol_size": int_match(r"^restore_protocol_size=([0-9]+)$"),
        "restore_manifest_json": int_match(r"^restore_manifest_json=([0-9]+)$"),
        "restore_export_dirs": int_match(r"^restore_export_dirs=([0-9]+)$"),
        "restore_answers_without_statements": int_match(r"^restore_answers_without_statements=([0-9]+)$"),
        "restore_statements_without_citation": int_match(r"^restore_statements_without_citation=([0-9]+)$"),
        "restore_vector_extension": int_match(r"^restore_vector_extension=([0-9]+)$"),
        "restore_operational_indexes": int_match(r"^restore_operational_indexes=([0-9]+)$"),
        "restore_network_isolated": "restore_network_mode=none" in text,
        "restore_ports_empty": "restore_ports={}" in text,
        "dump_marker_count": len(re.findall(r"^dump_marker_.+=yes$", text, re.MULTILINE)),
    }


def stat_info(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {
        "exists": path.exists(),
        "is_symlink": path.is_symlink(),
        "is_file": False,
        "is_dir": False,
        "uid": -1,
        "gid": -1,
        "mode": -1,
        "size": -1,
    }
    if not info["exists"] and not info["is_symlink"]:
        return info
    st = path.lstat()
    info.update(
        {
            "is_file": stat.S_ISREG(st.st_mode),
            "is_dir": stat.S_ISDIR(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode),
            "size": st.st_size,
        }
    )
    return info


def int_value(info: dict[str, Any], key: str, default: int = -1) -> int:
    value = info.get(key)
    return default if value is None else int(value)


def check_helper_binary_policy(findings: list[str], label: str, path: Path, require_setuid: bool = False) -> int:
    info = stat_info(path)
    checks = 0
    checks += 1
    if not info.get("exists"):
        findings.append("helper_%s_missing" % label)
    checks += 1
    if info.get("is_symlink"):
        findings.append("helper_%s_is_symlink" % label)
    checks += 1
    if not info.get("is_file"):
        findings.append("helper_%s_not_regular_file" % label)
    checks += 1
    if int_value(info, "uid") != 0 or int_value(info, "gid") != 0:
        findings.append("helper_%s_not_root_owned" % label)
    mode = int_value(info, "mode")
    checks += 1
    if mode < 0 or mode & 0o022:
        findings.append("helper_%s_group_or_other_writable" % label)
    checks += 1
    if mode < 0 or not mode & 0o111:
        findings.append("helper_%s_not_executable" % label)
    checks += 1
    if require_setuid:
        if mode < 0 or not mode & stat.S_ISUID:
            findings.append("helper_%s_missing_setuid" % label)
        if mode >= 0 and mode & stat.S_ISGID:
            findings.append("helper_%s_setgid_unexpected" % label)
    elif mode >= 0 and mode & (stat.S_ISUID | stat.S_ISGID):
        findings.append("helper_%s_special_bits_unexpected" % label)
    return checks


def check_self_script_policy(findings: list[str]) -> int:
    info = stat_info(SCRIPT)
    checks = 0
    checks += 1
    if not info.get("exists"):
        findings.append("self_script_missing")
    checks += 1
    if info.get("is_symlink"):
        findings.append("self_script_is_symlink")
    checks += 1
    if not info.get("is_file"):
        findings.append("self_script_not_regular_file")
    mode = int_value(info, "mode")
    checks += 1
    if mode < 0 or mode & 0o022:
        findings.append("self_script_group_or_other_writable")
    checks += 1
    if mode < 0 or not mode & 0o111:
        findings.append("self_script_not_executable")
    checks += 1
    if int_value(info, "size") < SELF_SCRIPT_MIN_BYTES:
        findings.append("self_script_too_small")
    return checks


def check_self_parent_directory_policy(findings: list[str]) -> int:
    script_info = stat_info(SCRIPT)
    expected_uid = int_value(script_info, "uid")
    expected_gid = int_value(script_info, "gid")
    checks = 0
    for label, path in [("app_dir", APP_DIR), ("scripts_dir", SCRIPT.parent)]:
        info = stat_info(path)
        checks += 1
        if not info.get("exists"):
            findings.append("self_parent_%s_missing" % label)
        checks += 1
        if info.get("is_symlink"):
            findings.append("self_parent_%s_is_symlink" % label)
        checks += 1
        if not info.get("is_dir"):
            findings.append("self_parent_%s_not_directory" % label)
        checks += 1
        if int_value(info, "uid") != expected_uid or int_value(info, "gid") != expected_gid:
            findings.append("self_parent_%s_owner_mismatch" % label)
        mode = int_value(info, "mode")
        checks += 1
        if mode < 0 or mode & 0o022:
            findings.append("self_parent_%s_group_or_other_writable" % label)
        checks += 1
        if mode < 0 or not mode & 0o111:
            findings.append("self_parent_%s_not_searchable" % label)
    return checks


def helper_binary_is_usable(path: Path) -> bool:
    info = stat_info(path)
    mode = int_value(info, "mode")
    return bool(
        info.get("exists")
        and not info.get("is_symlink")
        and info.get("is_file")
        and int_value(info, "uid") == 0
        and int_value(info, "gid") == 0
        and mode >= 0
        and not mode & 0o022
        and mode & 0o111
        and not mode & (stat.S_ISUID | stat.S_ISGID)
    )


def python_binary() -> Path | None:
    for path in ALLOWED_PYTHON_PATHS:
        if helper_binary_is_usable(path):
            return path
    return None


def sudo_restore_info(python_path: Path | None) -> dict[str, Any] | None:
    if python_path is None:
        return None
    proc = run([str(SUDO), "-n", str(python_path), str(SCRIPT), "--scan-json"])
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def age_hours(mtime: float) -> float:
    if not mtime:
        return 999999.0
    return max(0.0, (datetime.now(timezone.utc).timestamp() - float(mtime)) / 3600.0)


def restic_binary() -> Path | None:
    for path in ALLOWED_RESTIC_PATHS:
        if run([str(SUDO), "-n", str(TEST), "-x", str(path)]).returncode == 0:
            return path
    return None


def restic_resolved_snapshot_info(snapshot_id: str, restic_path: Path | None) -> dict[str, Any] | None:
    if not re.fullmatch(r"[0-9a-f]{8,64}", snapshot_id):
        return None
    if run([str(SUDO), "-n", str(TEST), "-f", str(BACKUP_ENV)]).returncode != 0:
        return None
    if restic_path is None:
        return None
    command = "set -a; source %s; set +a; %s snapshots %s --host m11h --tag br-wissen --json" % (
        shlex.quote(str(BACKUP_ENV)),
        shlex.quote(str(restic_path)),
        shlex.quote(snapshot_id),
    )
    proc = run([str(SUDO), "-n", str(BASH), "-lc", command])
    if proc.returncode != 0:
        return None
    try:
        snapshots = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(snapshots, list) or not snapshots:
        return None
    candidates = [item for item in snapshots if isinstance(item, dict)]
    if not candidates:
        return None
    selected = None
    for item in candidates:
        full_id = str(item.get("id") or "")
        short_id = str(item.get("short_id") or "")
        if full_id.startswith(snapshot_id) or short_id.startswith(snapshot_id) or snapshot_id.startswith(short_id):
            selected = item
            break
    if selected is None:
        selected = candidates[0]
    return {
        "id": str(selected.get("id") or ""),
        "short_id": str(selected.get("short_id") or "")[:8],
        "tags": [str(tag) for tag in (selected.get("tags") or []) if isinstance(tag, str)],
        "paths": [str(path) for path in (selected.get("paths") or []) if isinstance(path, str)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen restore-smoke freshness")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument("--scan-json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--max-age-hours", type=float, default=float(os.getenv("BR_RESTORE_MAX_AGE_HOURS", "170")))
    args = parser.parse_args()

    if args.scan_json:
        if os.geteuid() != 0:
            return 1
        print(json.dumps(collect_restore_info(), sort_keys=True))
        return 0

    findings: list[str] = []
    checks = 0
    selected_python_path = python_binary()
    info = sudo_restore_info(selected_python_path)
    if info is None:
        info = {}
        findings.append("restore_info_unavailable")
    checks += 1

    log_count = int(info.get("log_count") or 0)
    latest_log_age_h = age_hours(float(info.get("latest_log_mtime") or 0))
    latest_log_mode = int(info.get("latest_log_mode") or 0)
    latest_dump_size = int(info.get("restore_latest_dump_size") or 0)
    resolved_snapshot = str(info.get("restore_resolved_snapshot") or "")
    selected_restic_path = restic_binary()
    restic_snapshot = restic_resolved_snapshot_info(resolved_snapshot, selected_restic_path) if resolved_snapshot else None
    resolved_snapshot_present = 0
    resolved_snapshot_paths = 0
    helper_binary_count = 3 + (1 if selected_python_path is not None else 0) + (1 if selected_restic_path is not None else 0)
    self_script_findings_before = len(findings)
    self_parent_findings_before = len(findings)

    checks += check_self_script_policy(findings)
    self_script_policy = 1 if len(findings) == self_script_findings_before else 0
    self_parent_findings_before = len(findings)
    checks += check_self_parent_directory_policy(findings)
    self_parent_policy = 1 if len(findings) == self_parent_findings_before else 0

    checks += check_helper_binary_policy(findings, "sudo", SUDO, require_setuid=True)
    checks += check_helper_binary_policy(findings, "test", TEST)
    checks += check_helper_binary_policy(findings, "bash", BASH)
    if selected_python_path is None:
        checks += 1
        findings.append("helper_python_unavailable")
    else:
        checks += check_helper_binary_policy(findings, "python", selected_python_path)
    if selected_restic_path is None:
        checks += 1
        findings.append("helper_restic_unavailable")
    else:
        checks += check_helper_binary_policy(findings, "restic", selected_restic_path)

    checks += 24
    if log_count < 1:
        findings.append("missing_restore_logs")
    if log_count > RESTORE_LOG_KEEP:
        findings.append("restore_log_retention_exceeded=%d" % log_count)
    if latest_log_age_h > args.max_age_hours:
        findings.append("latest_restore_too_old_h=%.1f" % latest_log_age_h)
    if latest_log_mode & 0o137:
        findings.append("latest_restore_log_bad_mode=%03o" % latest_log_mode)
    if not bool(info.get("restore_drill_done")):
        findings.append("latest_restore_missing_drill_done")
    if not bool(info.get("restore_status_ok")):
        findings.append("latest_restore_status_not_ok")
    if not bool(info.get("db_restore_status_ok")):
        findings.append("latest_db_restore_status_not_ok")
    if not bool(info.get("storage_capacity_status_ok")):
        findings.append("latest_restore_missing_storage_capacity_ok")
    if not str(info.get("restore_snapshot") or ""):
        findings.append("latest_restore_missing_snapshot")
    if not re.fullmatch(r"[0-9a-f]{8,64}", resolved_snapshot):
        findings.append("latest_restore_missing_resolved_snapshot")
    if not str(info.get("restore_latest_dump") or ""):
        findings.append("latest_restore_missing_dump_name")
    if int(info.get("restore_sql_ready_wait") or 0) < 1:
        findings.append("restore_sql_ready_wait_missing_or_invalid")
    if latest_dump_size < MIN_DUMP_BYTES:
        findings.append("latest_restore_dump_too_small")
    if int(info.get("restore_required_missing") or 0) != 0:
        findings.append("restore_required_missing=%d" % int(info.get("restore_required_missing") or 0))
    if int(info.get("restore_artifact_findings") or 0) != 0:
        findings.append("restore_artifact_findings=%d" % int(info.get("restore_artifact_findings") or 0))
    if not bool(info.get("restore_protocol_exists")):
        findings.append("restore_protocol_missing")
    if not bool(info.get("restore_protocol_markers")):
        findings.append("restore_protocol_markers_missing")
    if int(info.get("restore_protocol_size") or 0) < 1000:
        findings.append("restore_protocol_too_small")
    if int(info.get("restore_manifest_json") or 0) < 1:
        findings.append("restore_manifest_json_missing")
    if int(info.get("restore_export_dirs") or 0) < int(info.get("restore_manifest_json") or 0):
        findings.append("restore_manifest_count_exceeds_exports")
    if int(info.get("restore_answers_without_statements") or 0) != 0:
        findings.append("restore_answers_without_statements=%d" % int(info.get("restore_answers_without_statements") or 0))
    if int(info.get("restore_statements_without_citation") or 0) != 0:
        findings.append("restore_statements_without_citation=%d" % int(info.get("restore_statements_without_citation") or 0))
    if int(info.get("restore_vector_extension") or 0) != 1:
        findings.append("restore_vector_extension=%d" % int(info.get("restore_vector_extension") or 0))
    if int(info.get("restore_operational_indexes") or 0) < 14:
        findings.append("restore_operational_indexes=%d" % int(info.get("restore_operational_indexes") or 0))
    if not bool(info.get("restore_network_isolated")) or not bool(info.get("restore_ports_empty")):
        findings.append("restore_db_isolation_missing")
    if int(info.get("dump_marker_count") or 0) < 7:
        findings.append("restore_dump_markers_incomplete")

    checks += 5
    if restic_snapshot is None:
        findings.append("restore_resolved_snapshot_unavailable")
    else:
        resolved_snapshot_present = 1
        resolved_tags = set(restic_snapshot.get("tags") or [])
        resolved_paths = set(restic_snapshot.get("paths") or [])
        resolved_snapshot_paths = len(resolved_paths)
        missing_tags = sorted(EXPECTED_TAGS - resolved_tags)
        if missing_tags:
            findings.append("restore_resolved_snapshot_tags_missing=%s" % ",".join(missing_tags))
        extra_tags = sorted(resolved_tags - EXPECTED_TAGS)
        if extra_tags:
            findings.append("restore_resolved_snapshot_tags_unexpected=%s" % ",".join(extra_tags))
        missing_paths = sorted(EXPECTED_PATHS - resolved_paths)
        if missing_paths:
            findings.append("restore_resolved_snapshot_paths_missing=%d" % len(missing_paths))
        unexpected_paths = sorted(resolved_paths - EXPECTED_PATHS)
        if unexpected_paths:
            findings.append("restore_resolved_snapshot_paths_unexpected=%d" % len(unexpected_paths))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "restore_freshness_status=%s checks=%d findings=%d latest_restore_age_h=%.1f log_count=%d restore_snapshot=%s restore_resolved_snapshot=%s restore_resolved_snapshot_present=%d restore_resolved_snapshot_paths=%d helper_binaries=%d python_binary=%s self_script_policy=%d self_parent_policy=%d restore_dump=%s db_restore=%s sql_ready_wait=%d manifests=%d"
            % (
                status,
                checks,
                len(findings),
                latest_log_age_h,
                log_count,
                str(info.get("restore_snapshot") or "none"),
                resolved_snapshot or "none",
                resolved_snapshot_present,
                resolved_snapshot_paths,
                helper_binary_count,
                str(selected_python_path) if selected_python_path is not None else "none",
                self_script_policy,
                self_parent_policy,
                str(info.get("restore_latest_dump") or "none"),
                "ok" if bool(info.get("db_restore_status_ok")) else "not_ok",
                int(info.get("restore_sql_ready_wait") or 0),
                int(info.get("restore_manifest_json") or 0),
            )
        )
    else:
        print("restore_freshness_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("latest_restore_age_h=%.1f" % latest_log_age_h)
        print("log_count=%d" % log_count)
        print("restore_snapshot=%s" % str(info.get("restore_snapshot") or "none"))
        print("restore_resolved_snapshot=%s" % (resolved_snapshot or "none"))
        print("restore_resolved_snapshot_present=%d" % resolved_snapshot_present)
        print("restore_resolved_snapshot_paths=%d" % resolved_snapshot_paths)
        print("helper_binaries=%d" % helper_binary_count)
        print("python_binary=%s" % (str(selected_python_path) if selected_python_path is not None else "none"))
        print("self_script_policy=%d" % self_script_policy)
        print("self_parent_policy=%d" % self_parent_policy)
        print("restore_sql_ready_wait=%d" % int(info.get("restore_sql_ready_wait") or 0))
        print("restore_dump=%s" % str(info.get("restore_latest_dump") or "none"))
        print("restore_dump_size=%d" % latest_dump_size)
        print("db_restore=%s" % ("ok" if bool(info.get("db_restore_status_ok")) else "not_ok"))
        print("restore_manifest_json=%d" % int(info.get("restore_manifest_json") or 0))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
