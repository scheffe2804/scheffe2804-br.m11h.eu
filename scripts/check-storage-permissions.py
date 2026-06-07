#!/usr/bin/env python3
"""Read-only storage/project permission guard for BR-Wissen.

The guard checks only metadata: modes, ownership classes, symlink counts and
secret-candidate counts. It never prints secret values or file contents.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any


APP_DIR = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
SUDO = Path("/usr/bin/sudo")


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


def scan_metadata() -> dict[str, Any]:
    app = APP_DIR
    root = STORAGE_ROOT
    secrets = root / "secrets"
    cloudflared = secrets / "cloudflared"
    backups = root / "backups"
    logs = root / "logs"
    exports = root / "exports"

    def mode(path: Path) -> int | None:
        try:
            return stat.S_IMODE(path.lstat().st_mode)
        except FileNotFoundError:
            return None

    def owner_uid(path: Path) -> int | None:
        try:
            return path.lstat().st_uid
        except FileNotFoundError:
            return None

    def group_gid(path: Path) -> int | None:
        try:
            return path.lstat().st_gid
        except FileNotFoundError:
            return None

    def count_walk(base: Path, predicate: Any) -> int:
        if not base.exists():
            return 0
        count = 0
        for dirpath, _dirnames, filenames in os.walk(base):
            directory = Path(dirpath)
            try:
                if predicate(directory):
                    count += 1
            except FileNotFoundError:
                pass
            for name in filenames:
                candidate = Path(dirpath) / name
                try:
                    if predicate(candidate):
                        count += 1
                except FileNotFoundError:
                    pass
        return count

    def any_group_world_bits(path: Path) -> bool:
        path_mode = mode(path)
        return bool(path_mode is not None and (path_mode & 0o077))

    def any_world_bits(path: Path) -> bool:
        path_mode = mode(path)
        return bool(path_mode is not None and (path_mode & 0o007))

    def world_writable(path: Path) -> bool:
        path_mode = mode(path)
        return bool(path_mode is not None and (path_mode & 0o002))

    def group_writable(path: Path) -> bool:
        path_mode = mode(path)
        return bool(path_mode is not None and (path_mode & 0o020))

    def is_symlink(path: Path) -> bool:
        return path.is_symlink()

    def secret_candidate(path: Path) -> bool:
        rel = str(path.relative_to(app)) if str(path).startswith(str(app)) else path.name
        name = path.name.lower()
        return (
            path.name == ".env"
            or path.name.endswith(".env")
            or "credential" in name
            or "token" in name
            or (rel.startswith("cloudflared/") and path.name.endswith(".json"))
        )

    cloud_json = list(cloudflared.glob("*.json")) if cloudflared.exists() else []
    cloud_bad_owner = 0
    cloud_bad_mode = 0
    for path in cloud_json:
        if owner_uid(path) != 65532 or group_gid(path) != 65532:
            cloud_bad_owner += 1
        path_mode = mode(path)
        if path_mode is None or (path_mode & 0o077):
            cloud_bad_mode += 1

    return {
        "storage_root_exists": root.exists(),
        "storage_root_mode": mode(root),
        "storage_root_group_world_writable": bool(mode(root) is not None and (mode(root) & 0o022)),
        "secrets_dir_exists": secrets.exists(),
        "secrets_dir_mode": mode(secrets),
        "secrets_dir_group_world_bits": bool(mode(secrets) is not None and (mode(secrets) & 0o077)),
        "cloudflared_dir_exists": cloudflared.exists(),
        "cloudflared_dir_mode": mode(cloudflared),
        "cloudflared_dir_uid": owner_uid(cloudflared),
        "cloudflared_dir_gid": group_gid(cloudflared),
        "cloudflared_json_count": len(cloud_json),
        "cloudflared_json_bad_owner": cloud_bad_owner,
        "cloudflared_json_bad_mode": cloud_bad_mode,
        "secrets_files_group_world_bits": count_walk(secrets, lambda p: p.is_file() and any_group_world_bits(p)),
        "storage_world_writable": count_walk(root, world_writable),
        "storage_symlinks": count_walk(root, is_symlink),
        "project_symlinks": count_walk(app, is_symlink),
        "project_secret_candidates": count_walk(app, lambda p: p.is_file() and secret_candidate(p)),
        "project_world_writable": count_walk(app, world_writable),
        "project_group_writable": count_walk(app, group_writable),
        "sensitive_world_readable": count_walk(secrets, lambda p: p.is_file() and any_world_bits(p))
        + count_walk(backups, lambda p: p.is_file() and any_world_bits(p))
        + count_walk(logs, lambda p: p.is_file() and any_world_bits(p))
        + count_walk(exports, lambda p: p.is_file() and any_world_bits(p)),
        "backup_dump_bad_mode": count_walk(
            backups,
            lambda p: p.is_file() and p.name.startswith("postgres-") and (mode(p) is None or (mode(p) & 0o137)),
        ),
        "backup_log_bad_mode": count_walk(
            logs,
            lambda p: p.is_file() and p.name.startswith("backup-") and (mode(p) is None or (mode(p) & 0o137)),
        ),
    }


def sudo_scan() -> dict[str, Any] | None:
    if not helper_available(SUDO):
        return None
    proc = run([str(SUDO), "-n", str(APP_DIR / "scripts/check-storage-permissions.py"), "--scan-json"])
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen storage/project permissions")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument("--scan-json", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.scan_json:
        if os.geteuid() != 0:
            return 1
        print(json.dumps(scan_metadata(), sort_keys=True))
        return 0

    findings: list[str] = []
    info = sudo_scan()
    checks = 0
    if info is None:
        info = {}
        findings.append("permission_scan_unavailable")
    checks += 1

    expected_zero_keys = [
        "storage_world_writable",
        "storage_symlinks",
        "project_symlinks",
        "project_secret_candidates",
        "project_world_writable",
        "secrets_files_group_world_bits",
        "sensitive_world_readable",
        "cloudflared_json_bad_owner",
        "cloudflared_json_bad_mode",
        "backup_dump_bad_mode",
        "backup_log_bad_mode",
    ]
    for key in expected_zero_keys:
        checks += 1
        value = int(info.get(key) or 0)
        if value != 0:
            findings.append("%s=%d" % (key, value))

    checks += 8
    if not bool(info.get("storage_root_exists")):
        findings.append("missing_storage_root")
    if bool(info.get("storage_root_group_world_writable")):
        findings.append("storage_root_group_world_writable")
    if not bool(info.get("secrets_dir_exists")):
        findings.append("missing_secrets_dir")
    if bool(info.get("secrets_dir_group_world_bits")):
        findings.append("secrets_dir_group_world_bits")
    if not bool(info.get("cloudflared_dir_exists")):
        findings.append("missing_cloudflared_secret_dir")
    if int(info.get("cloudflared_dir_uid") or -1) != 65532 or int(info.get("cloudflared_dir_gid") or -1) != 65532:
        findings.append("cloudflared_dir_owner_mismatch")
    if int(info.get("cloudflared_dir_mode") or 0) & 0o077:
        findings.append("cloudflared_dir_group_world_bits")
    if int(info.get("cloudflared_json_count") or 0) < 1:
        findings.append("missing_cloudflared_credentials_file")

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "storage_permission_status=%s checks=%d findings=%d storage_world_writable=%d storage_symlinks=%d project_secret_candidates=%d sensitive_world_readable=%d cloudflared_json=%d"
            % (
                status,
                checks,
                len(findings),
                int(info.get("storage_world_writable") or 0),
                int(info.get("storage_symlinks") or 0),
                int(info.get("project_secret_candidates") or 0),
                int(info.get("sensitive_world_readable") or 0),
                int(info.get("cloudflared_json_count") or 0),
            )
        )
    else:
        print("storage_permission_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        for key in sorted(info):
            if key.endswith("_mode") and info[key] is not None:
                print("%s=%03o" % (key, int(info[key])))
            else:
                print("%s=%s" % (key, info[key]))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
