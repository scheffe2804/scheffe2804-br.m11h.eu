#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen storage guards.

The guard validates storage permission and capacity guard sources for expected
metadata-only permission, symlink, secret-candidate, dump/log mode, filesystem,
inode and Docker capacity markers. It only reads project source files; it does
not run storage checks, sudo, Docker, backups, restores, imports or database
queries and never reads secrets, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
PERMISSIONS = ROOT / "scripts" / "check-storage-permissions.py"
CAPACITY = ROOT / "scripts" / "check-storage-capacity.py"


PERMISSION_MARKERS: list[tuple[str, str]] = [
    ("docstring_metadata_only", "The guard checks only metadata: modes, ownership classes, symlink counts and\nsecret-candidate counts."),
    ("app_dir", "APP_DIR = Path(os.getenv(\"BR_APP_DIR\", \"/home/chris/web/br.m11h.eu\"))"),
    ("storage_root", "STORAGE_ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))"),
    ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
    ("helper_available", "def helper_available(path: Path) -> bool:"),
    ("scan_metadata", "def scan_metadata()"),
    ("secrets_path", "secrets = root / \"secrets\""),
    ("cloudflared_path", "cloudflared = secrets / \"cloudflared\""),
    ("backups_path", "backups = root / \"backups\""),
    ("logs_path", "logs = root / \"logs\""),
    ("exports_path", "exports = root / \"exports\""),
    ("mode", "stat.S_IMODE(path.lstat().st_mode)"),
    ("owner_uid", "path.lstat().st_uid"),
    ("group_gid", "path.lstat().st_gid"),
    ("count_walk", "def count_walk(base: Path, predicate: Any)"),
    ("group_world_bits", "def any_group_world_bits(path: Path)"),
    ("world_bits", "def any_world_bits(path: Path)"),
    ("world_writable", "def world_writable(path: Path)"),
    ("group_writable", "def group_writable(path: Path)"),
    ("symlink", "def is_symlink(path: Path)"),
    ("secret_candidate", "def secret_candidate(path: Path)"),
    ("env_candidate", "path.name == \".env\""),
    ("env_suffix", "path.name.endswith(\".env\")"),
    ("credential_candidate", "\"credential\" in name"),
    ("token_candidate", "\"token\" in name"),
    ("cloudflared_json_candidate", "rel.startswith(\"cloudflared/\") and path.name.endswith(\".json\")"),
    ("cloudflared_json_glob", "cloudflared.glob(\"*.json\")"),
    ("cloudflared_uid", "owner_uid(path) != 65532"),
    ("cloudflared_gid", "group_gid(path) != 65532"),
    ("cloudflared_mode", "path_mode is None or (path_mode & 0o077)"),
    ("storage_root_exists", "storage_root_exists"),
    ("secrets_dir_exists", "secrets_dir_exists"),
    ("storage_world_writable", "storage_world_writable"),
    ("storage_symlinks", "storage_symlinks"),
    ("project_symlinks", "project_symlinks"),
    ("project_secret_candidates", "project_secret_candidates"),
    ("project_world_writable", "project_world_writable"),
    ("sensitive_world_readable", "sensitive_world_readable"),
    ("backup_dump_bad_mode", "backup_dump_bad_mode"),
    ("backup_log_bad_mode", "backup_log_bad_mode"),
    ("sudo_scan", "def sudo_scan()"),
    ("scan_json", "--scan-json"),
    ("geteuid_gate", "if os.geteuid() != 0:"),
    ("expected_zero_keys", "expected_zero_keys = ["),
    ("missing_storage_root", "missing_storage_root"),
    ("secrets_bits", "secrets_dir_group_world_bits"),
    ("missing_cloudflared", "missing_cloudflared_credentials_file"),
    ("summary", "storage_permission_status=%s checks=%d findings=%d storage_world_writable=%d storage_symlinks=%d project_secret_candidates=%d sensitive_world_readable=%d cloudflared_json=%d"),
]


CAPACITY_MARKERS: list[tuple[str, str]] = [
    ("docstring_metadata_only", "The guard checks only filesystem and Docker capacity metadata."),
    ("app_dir", "APP_DIR = Path(os.getenv(\"BR_APP_DIR\", \"/home/chris/web/br.m11h.eu\"))"),
    ("storage_root", "STORAGE_ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))"),
    ("tmp_dir", "TMP_DIR = Path(os.getenv(\"BR_TMP_DIR\", \"/tmp\"))"),
    ("docker_root", "DOCKER_ROOT = Path(os.getenv(\"BR_DOCKER_ROOT\", \"/var/lib/docker\"))"),
    ("docker_helper", "DOCKER = Path(\"/usr/bin/docker\")"),
    ("gib", "GIB = 1024 ** 3"),
    ("min_free", "BR_CAPACITY_MIN_FREE_GIB"),
    ("min_tmp", "BR_CAPACITY_MIN_TMP_FREE_GIB"),
    ("min_docker", "BR_CAPACITY_MIN_DOCKER_FREE_GIB"),
    ("max_used", "BR_CAPACITY_MAX_USED_PERCENT"),
    ("max_inode", "BR_CAPACITY_MAX_INODE_USED_PERCENT"),
    ("stat_path", "def stat_path(label: str, path: Path, min_free_gib: float)"),
    ("disk_usage", "shutil.disk_usage(path)"),
    ("statvfs", "os.statvfs(path)"),
    ("total_inodes", "total_inodes = int(statvfs.f_files)"),
    ("free_inodes", "free_inodes = int(statvfs.f_favail)"),
    ("used_percent", "used_percent"),
    ("inode_used_percent", "inode_used_percent"),
    ("docker_summary", "def docker_summary()"),
    ("helper_available", "def helper_available(path: Path) -> bool:"),
    ("docker_df", 'str(DOCKER), "system", "df", "--format", "json"'),
    ("parse_size", "def parse_size(value: str)"),
    ("gb_unit", '("GB", 1000 ** 3)'),
    ("gib_unit", '("GiB", 1024 ** 3)'),
    ("path_specs", "path_specs = ["),
    ("root_path", '("root", Path("/"), MIN_FREE_DEFAULT_GIB)'),
    ("app_path", '("app", APP_DIR, MIN_FREE_DEFAULT_GIB)'),
    ("storage_path", '("storage", STORAGE_ROOT, MIN_FREE_DEFAULT_GIB)'),
    ("tmp_path", '("tmp", TMP_DIR, MIN_TMP_FREE_GIB)'),
    ("docker_path", '("docker", DOCKER_ROOT, MIN_DOCKER_FREE_GIB)'),
    ("seen_devices", "seen_devices: set[tuple[int, int]]"),
    ("missing_path", "missing_path_%s"),
    ("stat_failed", "stat_failed_%s"),
    ("low_free", "low_free_%s_gib"),
    ("high_used", "high_used_%s_pct"),
    ("high_inode", "high_inode_%s_pct"),
    ("docker_unavailable", "docker_system_df_unavailable"),
    ("summary", "storage_capacity_status=%s checks=%d findings=%d min_free_gib=%.1f max_used_pct=%.1f max_inode_pct=%.1f docker_size_gib=%.1f docker_reclaimable_gib=%.1f"),
]


FORBIDDEN_PERMISSION_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
    "COMMIT",
    "conn.commit",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
    "open(",
    ".read_text(",
]


FORBIDDEN_CAPACITY_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
    "COMMIT",
    "conn.commit",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
    "open(",
    ".read_text(",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
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
    parser = argparse.ArgumentParser(description="Check BR-Wissen storage source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    permission_text = read_source(PERMISSIONS, findings, "storage_permissions")
    capacity_text = read_source(CAPACITY, findings, "storage_capacity")
    checks += 2

    checks += check_markers(findings, permission_text, PERMISSION_MARKERS, "permission")
    checks += check_markers(findings, capacity_text, CAPACITY_MARKERS, "capacity")
    checks += check_forbidden(findings, permission_text, FORBIDDEN_PERMISSION_MARKERS, "permission")
    checks += check_forbidden(findings, capacity_text, FORBIDDEN_CAPACITY_MARKERS, "capacity")

    checks += 1
    if permission_text.find("def scan_metadata") > permission_text.find("def sudo_scan"):
        findings.append("permission_scan_after_sudo_wrapper")
    checks += 1
    if permission_text.find("expected_zero_keys") > permission_text.find("status = \"ok\""):
        findings.append("permission_expected_zero_after_status")
    checks += 1
    if capacity_text.find("path_specs = [") > capacity_text.find("for label, path, min_free_gib in path_specs"):
        findings.append("capacity_path_specs_after_loop")
    checks += 1
    if capacity_text.find("docker_summary()") > capacity_text.find("status = \"ok\""):
        findings.append("capacity_docker_summary_after_status")

    status = "ok" if not findings else "failed"
    summary = "storage_source_hardening_status=%s checks=%d findings=%d permission_markers=%d capacity_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(PERMISSION_MARKERS),
        len(CAPACITY_MARKERS),
        len(FORBIDDEN_PERMISSION_MARKERS) + len(FORBIDDEN_CAPACITY_MARKERS),
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
