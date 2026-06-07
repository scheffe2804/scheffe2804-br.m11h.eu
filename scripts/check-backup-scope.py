#!/usr/bin/env python3
"""Read-only Restic backup scope guard for BR-Wissen.

The guard validates the latest BR-Wissen Restic snapshot metadata for expected
host, tags and backup paths. It only reads Restic snapshot metadata via the
root-only backup environment; it does not run backups, restores, Docker,
systemctl, imports, regressions or database queries and never prints secret
values, dump contents, log bodies, answers, exports or source documents.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


APP_DIR = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
PROTOCOL_FILE = Path(os.getenv("BR_PROTOCOL_FILE", "/home/chris/web/diverses/betriebsrat.md"))
BACKUP_ENV = Path(os.getenv("BR_BACKUP_ENV", "/etc/web-backup/repos.d/m11h-br-wissen.env"))
EXPECTED_HOST = os.getenv("BR_RESTIC_HOST", "m11h")
EXPECTED_TAGS = {"br-wissen", "includes-internal-sources"}
EXPECTED_PATHS = {str(APP_DIR), str(STORAGE_ROOT), str(PROTOCOL_FILE)}
SUDO = Path("/usr/bin/sudo")
TEST = Path("/usr/bin/test")
BASH = Path("/usr/bin/bash")
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


def restic_binary() -> Path | None:
    for path in ALLOWED_RESTIC_PATHS:
        if helper_binary_is_usable(path):
            return path
    return None


def parse_restic_time(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def snapshot_sort_key(snapshot: dict[str, Any]) -> datetime:
    return parse_restic_time(str(snapshot.get("time") or "")) or datetime.fromtimestamp(0, timezone.utc)


def load_snapshots(restic_path: Path | None) -> list[dict[str, Any]] | None:
    if restic_path is None:
        return None
    if run([str(SUDO), "-n", str(TEST), "-f", str(BACKUP_ENV)]).returncode != 0:
        return None
    command = ("set -a; source %s; set +a; %s snapshots --host %s --tag br-wissen --json") % (
        shlex.quote(str(BACKUP_ENV)),
        shlex.quote(str(restic_path)),
        shlex.quote(EXPECTED_HOST),
    )
    proc = run([str(SUDO), "-n", str(BASH), "-lc", command])
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list):
        return None
    return [item for item in data if isinstance(item, dict)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen Restic backup scope")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    checks += check_helper_binary_policy(findings, "sudo", SUDO, require_setuid=True)
    checks += check_helper_binary_policy(findings, "test", TEST)
    checks += check_helper_binary_policy(findings, "bash", BASH)
    selected_restic_path = restic_binary()
    if selected_restic_path is None:
        findings.append("helper_restic_unavailable")
    else:
        checks += check_helper_binary_policy(findings, "restic", selected_restic_path)
    helper_binary_count = 3 + (1 if selected_restic_path is not None else 0)

    snapshots = load_snapshots(selected_restic_path)
    checks += 1
    if snapshots is None:
        snapshots = []
        findings.append("restic_snapshots_unavailable")
    if not snapshots:
        findings.append("restic_snapshots_empty")

    latest: dict[str, Any] = max(snapshots, key=snapshot_sort_key) if snapshots else {}
    latest_id = str(latest.get("short_id") or latest.get("id") or "")[:8]
    host = str(latest.get("hostname") or "")
    tags = set(str(tag) for tag in (latest.get("tags") or []) if isinstance(tag, str))
    paths = set(str(path) for path in (latest.get("paths") or []) if isinstance(path, str))

    checks += 1
    if host != EXPECTED_HOST:
        findings.append("snapshot_host_unexpected")
    checks += 1
    missing_tags = sorted(EXPECTED_TAGS - tags)
    if missing_tags:
        findings.append("snapshot_tags_missing=%s" % ",".join(missing_tags))
    checks += 1
    extra_tags = sorted(tags - EXPECTED_TAGS)
    if extra_tags:
        findings.append("snapshot_tags_unexpected=%s" % ",".join(extra_tags))
    checks += 1
    missing_paths = sorted(EXPECTED_PATHS - paths)
    if missing_paths:
        findings.append("snapshot_paths_missing=%d" % len(missing_paths))
    checks += 1
    unexpected_paths = sorted(paths - EXPECTED_PATHS)
    if unexpected_paths:
        findings.append("snapshot_paths_unexpected=%d" % len(unexpected_paths))
    checks += 1
    if not latest_id:
        findings.append("snapshot_id_missing")
    checks += 1
    latest_time = snapshot_sort_key(latest) if latest else None
    now = datetime.now(timezone.utc)
    if latest_time is None or latest_time.year < 2026 or latest_time > now + timedelta(hours=24):
        findings.append("snapshot_time_unexpected")

    status = "ok" if not findings else "failed"
    summary = "backup_scope_status=%s checks=%d findings=%d snapshots=%d latest_snapshot=%s tags=%d paths=%d expected_paths=%d helper_binaries=%d restic_binary=%s" % (
        status,
        checks,
        len(findings),
        len(snapshots),
        latest_id or "none",
        len(tags),
        len(paths),
        len(EXPECTED_PATHS),
        helper_binary_count,
        str(selected_restic_path) if selected_restic_path is not None else "none",
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
