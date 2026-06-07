#!/usr/bin/env python3
"""Read-only backup freshness and retention guard for BR-Wissen.

The guard prints only counters and marker-derived metadata. It never prints
backup secret values, dump contents, log bodies or credential file contents.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
BACKUP_ENV = Path(os.getenv("BR_BACKUP_ENV", "/etc/web-backup/repos.d/m11h-br-wissen.env"))
PROTOCOL_FILE = Path(os.getenv("BR_PROTOCOL_FILE", "/home/chris/web/diverses/betriebsrat.md"))
LOG_DIR = ROOT / "logs"
BACKUP_DIR = ROOT / "backups"
LOCAL_DUMP_KEEP = int(os.getenv("BR_LOCAL_DUMP_KEEP", "20"))
BACKUP_LOG_KEEP = int(os.getenv("BR_BACKUP_LOG_KEEP", "50"))
MIN_DUMP_BYTES = int(os.getenv("BR_MIN_DUMP_BYTES", str(1_000_000)))
PROTOCOL_SNAPSHOT_SKEW_SECONDS = float(os.getenv("BR_PROTOCOL_SNAPSHOT_SKEW_SECONDS", "60"))
SCRIPT = Path(__file__).resolve()
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


def stat_info(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {
        "exists": path.exists(),
        "is_symlink": path.is_symlink(),
        "is_file": False,
        "uid": -1,
        "gid": -1,
        "mode": -1,
    }
    if not info["exists"] and not info["is_symlink"]:
        return info
    st = path.lstat()
    info.update(
        {
            "is_file": stat.S_ISREG(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode),
        }
    )
    return info


def int_info_value(info: dict[str, Any], key: str, default: int = -1) -> int:
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
    if int_info_value(info, "uid") != 0 or int_info_value(info, "gid") != 0:
        findings.append("helper_%s_not_root_owned" % label)
    mode = int_info_value(info, "mode")
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


def helper_binary_is_usable(path: Path) -> bool:
    info = stat_info(path)
    mode = int_info_value(info, "mode")
    return bool(
        info.get("exists")
        and not info.get("is_symlink")
        and info.get("is_file")
        and int_info_value(info, "uid") == 0
        and int_info_value(info, "gid") == 0
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


def restic_binary() -> Path | None:
    for path in ALLOWED_RESTIC_PATHS:
        if helper_binary_is_usable(path):
            return path
    return None


def collect_local_info() -> dict[str, Any]:
    logs = sorted(LOG_DIR.glob("backup-*.log"), key=lambda p: p.stat().st_mtime, reverse=True) if LOG_DIR.exists() else []
    dumps = sorted(BACKUP_DIR.glob("postgres-*.sql"), key=lambda p: p.stat().st_mtime, reverse=True) if BACKUP_DIR.exists() else []
    latest_log = logs[0] if logs else None
    latest_dump = dumps[0] if dumps else None
    text = latest_log.read_text(encoding="utf-8", errors="replace") if latest_log else ""
    snapshot_match = re.search(r"^snapshot\s+([0-9a-f]+)\s+saved$", text, re.MULTILINE)
    creating_match = re.search(r"^creating_db_dump=(.+)$", text, re.MULTILINE)
    required_preflights = [
        "host_context_status=ok",
        "time_sync_status=ok",
        "compose_service_status=ok",
        "privilege_policy_status=ok",
        "privilege_risk_review_status=accepted_risk",
        "critical_privilege_risk=1",
        "privilege_least_privilege_plan_status=planned",
        "core_source_hardening_status=ok",
        "container_hardening_status=ok",
        "container_source_hardening_status=ok",
        "compose_source_hardening_status=ok",
        "network_source_hardening_status=ok",
        "network_exposure_status=ok",
        "public_dns_exposure_status=ok",
        "public_dns_multiresolver_status=ok",
        "public_dns_authoritative_status=ok",
        "public_dns_caa_status=ok",
        "direct_origin_bypass_status=ok",
        "direct_origin_port_exposure_status=ok",
        "host_udp_exposure_status=ok",
        "host_firewall_br_ports_status=ok",
        "host_nft_br_ports_status=ok",
        "network_policy_consistency_status=ok",
        "network_policy_runtime_env_status=ok",
        "network_policy_runtime_summary_status=ok",
        "artifact_status=ok",
        "image_pinning_guard_status=ok",
        "systemd_unit_guard_status=ok",
        "meta_source_hardening_status=ok",
        "doc_source_hardening_status=ok",
        "source_hardening_coverage_status=ok",
        "summary_contract_status=ok",
        "surface_registry_status=ok",
        "guard_registry_integrity_status=ok",
        "protocol_integrity_status=ok",
        "access_runtime_source_hardening_status=ok",
        "status_source_hardening_status=ok",
        "healthcheck_source_hardening_status=ok",
        "runtime_http_security_status=ok",
        "external_access_surface_status=ok",
        "external_cookie_security_status=ok",
        "tls_certificate_status=ok",
        "app_auth_surface_status=ok",
        "import_pipeline_status=ok",
        "import_source_hardening_status=ok",
        "answer_export_safety_status=ok",
        "data_integrity_source_hardening_status=ok",
        "audit_trail_status=ok",
        "db_schema_status=ok",
        "backup_scope_status=ok",
        "backup_runtime_policy_status=ok",
        "backup_source_hardening_status=ok",
        "restore_source_hardening_status=ok",
        "restore_runtime_policy_status=ok",
        "freshness_source_hardening_status=ok",
        "storage_source_hardening_status=ok",
        "storage_permission_status=ok",
        "storage_capacity_status=ok",
        "readiness_doc_status=ok",
        "regression_freshness_status=ok",
        "regression_source_hardening_status=ok",
        "protocol_file_status=included",
    ]
    return {
        "log_count": len(logs),
        "dump_count": len(dumps),
        "latest_log_path": str(latest_log) if latest_log else "",
        "latest_dump_path": str(latest_dump) if latest_dump else "",
        "latest_log_mtime": latest_log.stat().st_mtime if latest_log else 0,
        "latest_dump_mtime": latest_dump.stat().st_mtime if latest_dump else 0,
        "latest_log_size": latest_log.stat().st_size if latest_log else 0,
        "latest_dump_size": latest_dump.stat().st_size if latest_dump else 0,
        "log_status_done": "status=backup_done" in text,
        "log_snapshot": snapshot_match.group(1) if snapshot_match else "",
        "log_creating_dump": creating_match.group(1) if creating_match else "",
        "preflight_ok_count": sum(1 for item in required_preflights if item in text),
        "preflight_expected": len(required_preflights),
    }


def sudo_local_info(python_path: Path | None) -> dict[str, Any] | None:
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


def collect_backup_env_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "exists": BACKUP_ENV.exists(),
        "is_symlink": BACKUP_ENV.is_symlink(),
        "is_file": False,
        "uid": -1,
        "gid": -1,
        "mode": -1,
    }
    if not info["exists"]:
        return info
    st = BACKUP_ENV.lstat()
    info.update(
        {
            "is_file": stat.S_ISREG(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode),
        }
    )
    return info


def sudo_backup_env_info(python_path: Path | None) -> dict[str, Any] | None:
    if python_path is None:
        return None
    proc = run([str(SUDO), "-n", str(python_path), str(SCRIPT), "--backup-env-json"])
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def parse_restic_time(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    match = re.match(r"^(.*\.)(\d{6})\d+([+-]\d\d:\d\d)$", normalized)
    if match:
        normalized = "%s%s%s" % (match.group(1), match.group(2), match.group(3))
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def restic_latest(restic_path: Path | None) -> dict[str, Any] | None:
    if restic_path is None:
        return None
    if run([str(SUDO), "-n", str(TEST), "-f", str(BACKUP_ENV)]).returncode != 0:
        return None
    command = "set -a; source %s; set +a; %s snapshots --host m11h --tag br-wissen --json" % (
        shlex.quote(str(BACKUP_ENV)),
        shlex.quote(str(restic_path)),
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
    def key(item: dict[str, Any]) -> datetime:
        return parse_restic_time(str(item.get("time") or "")) or datetime.fromtimestamp(0, timezone.utc)
    latest = max((item for item in snapshots if isinstance(item, dict)), key=key)
    return {
        "count": len(snapshots),
        "short_id": str(latest.get("short_id") or ""),
        "id": str(latest.get("id") or ""),
        "time": str(latest.get("time") or ""),
        "time_utc": key(latest),
        "paths": [str(path) for path in (latest.get("paths") or []) if isinstance(path, str)],
    }


def restic_lock_info(restic_path: Path | None) -> dict[str, int] | None:
    if restic_path is None:
        return None
    if run([str(SUDO), "-n", str(TEST), "-f", str(BACKUP_ENV)]).returncode != 0:
        return None
    command = "set -a; source %s; set +a; LC_ALL=C %s list locks" % (
        shlex.quote(str(BACKUP_ENV)),
        shlex.quote(str(restic_path)),
    )
    proc = run([str(SUDO), "-n", str(BASH), "-lc", command])
    if proc.returncode != 0:
        return None
    lines = [
        line
        for line in proc.stdout.splitlines()
        if line.strip() and "no locks" not in line.lower()
    ]
    return {
        "total": len(lines),
        "stale": sum(1 for line in lines if "stale" in line.lower()),
    }


def age_hours(mtime: float) -> float:
    if not mtime:
        return 999999.0
    return max(0.0, (datetime.now(timezone.utc).timestamp() - float(mtime)) / 3600.0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen backup freshness")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument("--scan-json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--backup-env-json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--max-age-hours", type=float, default=float(os.getenv("BR_BACKUP_MAX_AGE_HOURS", "30")))
    args = parser.parse_args()

    if args.backup_env_json:
        if os.geteuid() != 0:
            return 1
        print(json.dumps(collect_backup_env_info(), sort_keys=True))
        return 0

    if args.scan_json:
        if os.geteuid() != 0:
            return 1
        print(json.dumps(collect_local_info(), sort_keys=True))
        return 0

    checks = 0
    findings: list[str] = []
    selected_python_path = python_binary()
    selected_restic_path = restic_binary()
    info = sudo_local_info(selected_python_path)
    backup_env_info = sudo_backup_env_info(selected_python_path)
    restic = restic_latest(selected_restic_path)
    restic_locks = restic_lock_info(selected_restic_path)
    helper_binary_count = 3 + (1 if selected_python_path is not None else 0) + (1 if selected_restic_path is not None else 0)

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

    if info is None:
        info = {}
        findings.append("local_backup_info_unavailable")
    checks += 1

    log_count = int(info.get("log_count") or 0)
    dump_count = int(info.get("dump_count") or 0)
    latest_log_age_h = age_hours(float(info.get("latest_log_mtime") or 0))
    latest_dump_age_h = age_hours(float(info.get("latest_dump_mtime") or 0))
    latest_dump_size = int(info.get("latest_dump_size") or 0)
    latest_snapshot = str(info.get("log_snapshot") or "")
    protocol_mtime = 0.0
    protocol_snapshot_current = 0

    preflight_expected = int(info.get("preflight_expected") or 14)
    checks += preflight_expected
    if log_count < 1:
        findings.append("missing_backup_logs")
    if dump_count < 1:
        findings.append("missing_local_dumps")
    if log_count > BACKUP_LOG_KEEP:
        findings.append("backup_log_retention_exceeded=%d" % log_count)
    if dump_count > LOCAL_DUMP_KEEP:
        findings.append("dump_retention_exceeded=%d" % dump_count)
    if latest_log_age_h > args.max_age_hours:
        findings.append("latest_log_too_old_h=%.1f" % latest_log_age_h)
    if latest_dump_age_h > args.max_age_hours:
        findings.append("latest_dump_too_old_h=%.1f" % latest_dump_age_h)
    if not bool(info.get("log_status_done")):
        findings.append("latest_log_missing_backup_done")
    if not latest_snapshot:
        findings.append("latest_log_missing_snapshot")
    if latest_dump_size < MIN_DUMP_BYTES:
        findings.append("latest_dump_too_small")
    if int(info.get("preflight_ok_count") or 0) < preflight_expected:
        findings.append(
            "latest_log_preflight_markers_incomplete=%d/%d"
            % (int(info.get("preflight_ok_count") or 0), preflight_expected)
        )
    if str(info.get("latest_dump_path") or "") != str(info.get("log_creating_dump") or ""):
        findings.append("latest_dump_not_referenced_by_latest_log")

    checks += 5
    if backup_env_info is None:
        findings.append("backup_env_info_unavailable")
        backup_env_mode = -1
    else:
        backup_env_mode = int_info_value(backup_env_info, "mode")
        if not bool(backup_env_info.get("exists")):
            findings.append("backup_env_missing")
        if bool(backup_env_info.get("is_symlink")):
            findings.append("backup_env_is_symlink")
        if not bool(backup_env_info.get("is_file")):
            findings.append("backup_env_not_regular_file")
        if int_info_value(backup_env_info, "uid") != 0 or int_info_value(backup_env_info, "gid") != 0:
            findings.append("backup_env_bad_owner")
        if backup_env_mode != 0o600:
            findings.append("backup_env_bad_mode=%03o" % max(backup_env_mode, 0))

    restic_age_h = 999999.0
    restic_short = ""
    restic_count = 0
    if restic is None:
        findings.append("restic_snapshots_unavailable")
    else:
        checks += 3
        restic_short = str(restic.get("short_id") or "")
        restic_count = int(restic.get("count") or 0)
        restic_time = restic.get("time_utc")
        if isinstance(restic_time, datetime):
            restic_age_h = max(0.0, (datetime.now(timezone.utc) - restic_time).total_seconds() / 3600.0)
        if restic_age_h > args.max_age_hours:
            findings.append("restic_snapshot_too_old_h=%.1f" % restic_age_h)
        if latest_snapshot and restic_short and latest_snapshot != restic_short:
            findings.append("latest_log_snapshot_mismatch")
        if restic_count < 1:
            findings.append("missing_restic_snapshots")
        paths = set(str(path) for path in (restic.get("paths") or []) if isinstance(path, str))
        checks += 1
        if str(PROTOCOL_FILE) not in paths:
            findings.append("restic_protocol_path_missing")
        checks += 4
        if not PROTOCOL_FILE.exists():
            findings.append("protocol_file_missing")
        elif PROTOCOL_FILE.is_symlink():
            findings.append("protocol_file_is_symlink")
        elif not PROTOCOL_FILE.is_file():
            findings.append("protocol_file_not_regular")
        else:
            protocol_mtime = PROTOCOL_FILE.stat().st_mtime
            if isinstance(restic_time, datetime):
                snapshot_timestamp = restic_time.timestamp()
                if protocol_mtime > snapshot_timestamp + PROTOCOL_SNAPSHOT_SKEW_SECONDS:
                    findings.append(
                        "protocol_newer_than_restic_snapshot_h=%.1f"
                        % ((protocol_mtime - snapshot_timestamp) / 3600.0)
                    )
                else:
                    protocol_snapshot_current = 1

    checks += 1
    if restic_locks is None:
        findings.append("restic_locks_unavailable")
        restic_lock_count_value = -1
        restic_stale_lock_count_value = -1
    else:
        restic_lock_count_value = int(restic_locks.get("total") or 0)
        restic_stale_lock_count_value = int(restic_locks.get("stale") or 0)
        if restic_stale_lock_count_value != 0:
            findings.append("restic_stale_locks_present=%d" % restic_stale_lock_count_value)

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "backup_freshness_status=%s checks=%d findings=%d latest_snapshot=%s restic_latest=%s restic_locks=%d restic_stale_locks=%d backup_env_mode=%03o helper_binaries=%d python_binary=%s restic_binary=%s latest_log_age_h=%.1f latest_dump_age_h=%.1f restic_age_h=%.1f log_count=%d dump_count=%d protocol_snapshot_current=%d"
            % (status, checks, len(findings), latest_snapshot or "none", restic_short or "none", restic_lock_count_value, restic_stale_lock_count_value, max(backup_env_mode, 0), helper_binary_count, str(selected_python_path) if selected_python_path is not None else "none", str(selected_restic_path) if selected_restic_path is not None else "none", latest_log_age_h, latest_dump_age_h, restic_age_h, log_count, dump_count, protocol_snapshot_current)
        )
    else:
        print("backup_freshness_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("latest_snapshot=%s" % (latest_snapshot or "none"))
        print("restic_latest=%s" % (restic_short or "none"))
        print("restic_locks=%d" % restic_lock_count_value)
        print("restic_stale_locks=%d" % restic_stale_lock_count_value)
        print("backup_env_mode=%03o" % max(backup_env_mode, 0))
        print("helper_binaries=%d" % helper_binary_count)
        print("python_binary=%s" % (str(selected_python_path) if selected_python_path is not None else "none"))
        print("restic_binary=%s" % (str(selected_restic_path) if selected_restic_path is not None else "none"))
        print("latest_log_age_h=%.1f" % latest_log_age_h)
        print("latest_dump_age_h=%.1f" % latest_dump_age_h)
        print("restic_age_h=%.1f" % restic_age_h)
        print("log_count=%d" % log_count)
        print("dump_count=%d" % dump_count)
        print("latest_dump_size=%d" % latest_dump_size)
        print("preflight_ok_count=%d" % int(info.get("preflight_ok_count") or 0))
        print("protocol_snapshot_current=%d" % protocol_snapshot_current)
        print("protocol_mtime=%d" % int(protocol_mtime))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
