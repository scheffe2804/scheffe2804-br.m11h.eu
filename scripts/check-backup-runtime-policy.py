#!/usr/bin/env python3
"""Read-only backup runtime policy guard for BR-Wissen.

The guard validates metadata-only runtime policy around the root-only backup
environment, the Restic executable and the installed backup service. It never
prints backup secret values, environment contents, dump contents, log bodies,
answers, exports or source documents. It does not run backups, restores, Docker,
imports, regressions or database queries.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any


BACKUP_ENV = Path(os.getenv("BR_BACKUP_ENV", "/etc/web-backup/repos.d/m11h-br-wissen.env"))
BACKUP_SERVICE = Path(os.getenv("BR_BACKUP_SERVICE", "/etc/systemd/system/br-wissen-backup.service"))
EXPECTED_RESTIC_BASENAME = "restic"
SUDO = Path("/usr/bin/sudo")
ALLOWED_RESTIC_PATHS = (Path("/usr/bin/restic"), Path("/usr/local/bin/restic"))


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def stat_info(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {
        "exists": path.exists(),
        "is_symlink": path.is_symlink(),
        "is_file": False,
        "is_dir": False,
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
            "is_dir": stat.S_ISDIR(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode),
        }
    )
    return info


def int_value(info: dict[str, Any], key: str, default: int = -1) -> int:
    value = info.get(key)
    return default if value is None else int(value)


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


def restic_binary() -> Path | None:
    for path in ALLOWED_RESTIC_PATHS:
        if helper_binary_is_usable(path):
            return path
    return None


def collect_root_info() -> dict[str, Any]:
    restic_path = restic_binary()
    parent = BACKUP_ENV.parent
    service_text = BACKUP_SERVICE.read_text(encoding="utf-8", errors="replace") if BACKUP_SERVICE.exists() and BACKUP_SERVICE.is_file() else ""
    return {
        "backup_env": stat_info(BACKUP_ENV),
        "backup_env_parent": stat_info(parent),
        "backup_service": stat_info(BACKUP_SERVICE),
        "restic_path": str(restic_path) if restic_path is not None else "",
        "restic": stat_info(restic_path) if restic_path is not None else {},
        "service_user_root": "User=root" in service_text,
        "service_exec_backup": "ExecStart=/home/chris/web/br.m11h.eu/scripts/backup-br-wissen.sh" in service_text,
        "service_workdir": "WorkingDirectory=/home/chris/web/br.m11h.eu" in service_text,
    }


def sudo_root_info() -> dict[str, Any] | None:
    proc = run([str(SUDO), "-n", str(Path(__file__).resolve()), "--root-json"])
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def check_file_policy(findings: list[str], info: dict[str, Any], label: str, max_mode: int, require_root: bool = True) -> int:
    checks = 0
    checks += 1
    if not info.get("exists"):
        findings.append("%s_missing" % label)
    checks += 1
    if info.get("is_symlink"):
        findings.append("%s_is_symlink" % label)
    checks += 1
    if not info.get("is_file"):
        findings.append("%s_not_regular_file" % label)
    checks += 1
    if require_root and (int_value(info, "uid") != 0 or int_value(info, "gid") != 0):
        findings.append("%s_not_root_owned" % label)
    checks += 1
    mode = int_value(info, "mode")
    if mode < 0 or mode & ~max_mode:
        findings.append("%s_mode_too_open" % label)
    return checks


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen backup runtime policy")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument("--root-json", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.root_json:
        if os.geteuid() != 0:
            return 1
        print(json.dumps(collect_root_info(), sort_keys=True))
        return 0

    checks = 0
    findings: list[str] = []
    checks += check_helper_binary_policy(findings, "sudo", SUDO, require_setuid=True)
    info = sudo_root_info()
    checks += 1
    if info is None:
        info = {}
        findings.append("root_metadata_unavailable")

    backup_env = info.get("backup_env") if isinstance(info.get("backup_env"), dict) else {}
    backup_env_parent = info.get("backup_env_parent") if isinstance(info.get("backup_env_parent"), dict) else {}
    backup_service = info.get("backup_service") if isinstance(info.get("backup_service"), dict) else {}
    restic_info = info.get("restic") if isinstance(info.get("restic"), dict) else {}
    restic_path = str(info.get("restic_path") or "")

    checks += check_file_policy(findings, backup_env, "backup_env", 0o600)

    checks += 1
    if not backup_env_parent.get("exists"):
        findings.append("backup_env_parent_missing")
    checks += 1
    if backup_env_parent.get("is_symlink"):
        findings.append("backup_env_parent_is_symlink")
    checks += 1
    if not backup_env_parent.get("is_dir"):
        findings.append("backup_env_parent_not_directory")
    checks += 1
    if int_value(backup_env_parent, "uid") != 0 or int_value(backup_env_parent, "gid") != 0:
        findings.append("backup_env_parent_not_root_owned")
    checks += 1
    parent_mode = int_value(backup_env_parent, "mode")
    if parent_mode < 0 or parent_mode & ~0o700:
        findings.append("backup_env_parent_mode_too_open")

    checks += 1
    if not restic_path or Path(restic_path).name != EXPECTED_RESTIC_BASENAME:
        findings.append("restic_path_unexpected")
    checks += 1
    if Path(restic_path) not in ALLOWED_RESTIC_PATHS:
        findings.append("restic_path_not_allowed")
    checks += check_file_policy(findings, restic_info, "restic_binary", 0o755)
    checks += 1
    restic_mode = int_value(restic_info, "mode")
    if restic_mode >= 0 and restic_mode & (stat.S_ISUID | stat.S_ISGID):
        findings.append("restic_binary_setuid_or_setgid")
    helper_binary_count = 1 + (1 if restic_path else 0)

    checks += check_file_policy(findings, backup_service, "backup_service", 0o644)
    checks += 1
    if not bool(info.get("service_user_root")):
        findings.append("backup_service_user_not_root")
    checks += 1
    if not bool(info.get("service_exec_backup")):
        findings.append("backup_service_exec_unexpected")
    checks += 1
    if not bool(info.get("service_workdir")):
        findings.append("backup_service_workdir_unexpected")

    status = "ok" if not findings else "failed"
    summary = "backup_runtime_policy_status=%s checks=%d findings=%d backup_env_mode=%03o backup_env_parent_mode=%03o restic_mode=%03o service_mode=%03o service_user_root=%d helper_binaries=%d restic_binary=%s" % (
        status,
        checks,
        len(findings),
        int_value(backup_env, "mode", 0),
        int_value(backup_env_parent, "mode", 0),
        int_value(restic_info, "mode", 0),
        int_value(backup_service, "mode", 0),
        1 if bool(info.get("service_user_root")) else 0,
        helper_binary_count,
        restic_path or "none",
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
