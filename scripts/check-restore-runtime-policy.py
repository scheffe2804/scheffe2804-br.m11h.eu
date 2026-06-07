#!/usr/bin/env python3
"""Read-only restore runtime policy guard for BR-Wissen.

The guard validates metadata-only runtime policy around the automated restore-smoke
drill: installed service/timer policy, restore scripts, Restic/Docker executables,
backup environment permissions and temporary directory policy. It never prints
backup secret values, environment contents, dump contents, log bodies, answers,
exports or source documents. It does not run backups, restores, Docker, imports,
regressions or database queries.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
BACKUP_ENV = Path(os.getenv("BR_BACKUP_ENV", "/etc/web-backup/repos.d/m11h-br-wissen.env"))
RESTORE_WRAPPER = ROOT / "scripts" / "run-restore-smoke-drill.sh"
RESTORE_SCRIPT = ROOT / "scripts" / "restore-smoke-br-wissen.sh"
RESTORE_SERVICE = Path(os.getenv("BR_RESTORE_SERVICE", "/etc/systemd/system/br-wissen-restore-smoke.service"))
RESTORE_TIMER = Path(os.getenv("BR_RESTORE_TIMER", "/etc/systemd/system/br-wissen-restore-smoke.timer"))
TMP_DIR = Path(os.getenv("BR_RESTORE_TMP_DIR", "/tmp"))
ALLOWED_RESTIC_PATHS = {"/usr/bin/restic", "/usr/local/bin/restic"}
ALLOWED_DOCKER_PATHS = {"/usr/bin/docker", "/usr/local/bin/docker"}


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


def read_text(path: Path) -> str:
    if not path.exists() or path.is_symlink() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def collect_root_info() -> dict[str, Any]:
    restic_path = Path(shutil.which("restic") or "")
    docker_path = Path(shutil.which("docker") or "")
    service_text = read_text(RESTORE_SERVICE)
    timer_text = read_text(RESTORE_TIMER)
    return {
        "backup_env": stat_info(BACKUP_ENV),
        "backup_env_parent": stat_info(BACKUP_ENV.parent),
        "restore_wrapper": stat_info(RESTORE_WRAPPER),
        "restore_script": stat_info(RESTORE_SCRIPT),
        "restore_service": stat_info(RESTORE_SERVICE),
        "restore_timer": stat_info(RESTORE_TIMER),
        "tmp_dir": stat_info(TMP_DIR),
        "restic_path": str(restic_path) if restic_path else "",
        "restic": stat_info(restic_path) if restic_path else {},
        "docker_path": str(docker_path) if docker_path else "",
        "docker": stat_info(docker_path) if docker_path else {},
        "service_user_root": "User=root" in service_text,
        "service_exec_restore": "ExecStart=/home/chris/web/br.m11h.eu/scripts/run-restore-smoke-drill.sh" in service_text,
        "service_workdir": "WorkingDirectory=/home/chris/web/br.m11h.eu" in service_text,
        "service_type_oneshot": "Type=oneshot" in service_text,
        "service_wants_docker": "Wants=network-online.target docker.service" in service_text,
        "service_after_docker": "After=network-online.target docker.service" in service_text,
        "timer_calendar": "OnCalendar=Sun *-*-* 06:10:00" in timer_text,
        "timer_persistent": "Persistent=true" in timer_text,
        "timer_randomized": "RandomizedDelaySec=45m" in timer_text,
        "timer_wanted_by": "WantedBy=timers.target" in timer_text,
    }


def sudo_root_info() -> dict[str, Any] | None:
    proc = run(["sudo", "-n", str(Path(__file__).resolve()), "--root-json"])
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def int_value(info: dict[str, Any], key: str, default: int = -1) -> int:
    value = info.get(key)
    return default if value is None else int(value)


def check_file_policy(findings: list[str], info: dict[str, Any], label: str, max_mode: int, require_root: bool = True, require_exec: bool = False) -> int:
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
    checks += 1
    if require_exec and (mode < 0 or not mode & 0o111):
        findings.append("%s_not_executable" % label)
    return checks


def check_dir_policy(findings: list[str], info: dict[str, Any], label: str, expected_mode: int, require_root: bool = True) -> int:
    checks = 0
    checks += 1
    if not info.get("exists"):
        findings.append("%s_missing" % label)
    checks += 1
    if info.get("is_symlink"):
        findings.append("%s_is_symlink" % label)
    checks += 1
    if not info.get("is_dir"):
        findings.append("%s_not_directory" % label)
    checks += 1
    if require_root and int_value(info, "uid") != 0:
        findings.append("%s_not_root_owned" % label)
    checks += 1
    mode = int_value(info, "mode")
    if mode != expected_mode:
        findings.append("%s_mode_unexpected" % label)
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen restore runtime policy")
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
    info = sudo_root_info()
    checks += 1
    if info is None:
        info = {}
        findings.append("root_metadata_unavailable")

    backup_env = info.get("backup_env") if isinstance(info.get("backup_env"), dict) else {}
    backup_env_parent = info.get("backup_env_parent") if isinstance(info.get("backup_env_parent"), dict) else {}
    restore_wrapper = info.get("restore_wrapper") if isinstance(info.get("restore_wrapper"), dict) else {}
    restore_script = info.get("restore_script") if isinstance(info.get("restore_script"), dict) else {}
    restore_service = info.get("restore_service") if isinstance(info.get("restore_service"), dict) else {}
    restore_timer = info.get("restore_timer") if isinstance(info.get("restore_timer"), dict) else {}
    tmp_dir = info.get("tmp_dir") if isinstance(info.get("tmp_dir"), dict) else {}
    restic_info = info.get("restic") if isinstance(info.get("restic"), dict) else {}
    docker_info = info.get("docker") if isinstance(info.get("docker"), dict) else {}
    restic_path = str(info.get("restic_path") or "")
    docker_path = str(info.get("docker_path") or "")

    checks += check_file_policy(findings, backup_env, "backup_env", 0o600)
    checks += check_dir_policy(findings, backup_env_parent, "backup_env_parent", 0o700)
    checks += check_file_policy(findings, restore_wrapper, "restore_wrapper", 0o755, require_root=False, require_exec=True)
    checks += check_file_policy(findings, restore_script, "restore_script", 0o755, require_root=False, require_exec=True)

    checks += 1
    if not restic_path or restic_path not in ALLOWED_RESTIC_PATHS:
        findings.append("restic_path_not_allowed")
    checks += check_file_policy(findings, restic_info, "restic_binary", 0o755)
    checks += 1
    restic_mode = int_value(restic_info, "mode")
    if restic_mode >= 0 and restic_mode & (stat.S_ISUID | stat.S_ISGID):
        findings.append("restic_binary_setuid_or_setgid")

    checks += 1
    if not docker_path or docker_path not in ALLOWED_DOCKER_PATHS:
        findings.append("docker_path_not_allowed")
    checks += check_file_policy(findings, docker_info, "docker_binary", 0o755)
    checks += 1
    docker_mode = int_value(docker_info, "mode")
    if docker_mode >= 0 and docker_mode & (stat.S_ISUID | stat.S_ISGID):
        findings.append("docker_binary_setuid_or_setgid")

    checks += check_file_policy(findings, restore_service, "restore_service", 0o644)
    checks += check_file_policy(findings, restore_timer, "restore_timer", 0o644)
    checks += check_dir_policy(findings, tmp_dir, "tmp_dir", 0o1777)

    for key, finding in [
        ("service_user_root", "restore_service_user_not_root"),
        ("service_exec_restore", "restore_service_exec_unexpected"),
        ("service_workdir", "restore_service_workdir_unexpected"),
        ("service_type_oneshot", "restore_service_type_unexpected"),
        ("service_wants_docker", "restore_service_wants_unexpected"),
        ("service_after_docker", "restore_service_after_unexpected"),
        ("timer_calendar", "restore_timer_calendar_unexpected"),
        ("timer_persistent", "restore_timer_persistent_unexpected"),
        ("timer_randomized", "restore_timer_randomized_unexpected"),
        ("timer_wanted_by", "restore_timer_wanted_by_unexpected"),
    ]:
        checks += 1
        if not bool(info.get(key)):
            findings.append(finding)

    status = "ok" if not findings else "failed"
    summary = "restore_runtime_policy_status=%s checks=%d findings=%d backup_env_mode=%03o tmp_mode=%04o restic_mode=%03o docker_mode=%03o service_mode=%03o timer_mode=%03o service_user_root=%d timer_persistent=%d" % (
        status,
        checks,
        len(findings),
        int_value(backup_env, "mode", 0),
        int_value(tmp_dir, "mode", 0),
        int_value(restic_info, "mode", 0),
        int_value(docker_info, "mode", 0),
        int_value(restore_service, "mode", 0),
        int_value(restore_timer, "mode", 0),
        1 if bool(info.get("service_user_root")) else 0,
        1 if bool(info.get("timer_persistent")) else 0,
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
