#!/usr/bin/env python3
"""Read-only script/unit/documentation permission policy guard for BR-Wissen.

The guard checks only filesystem metadata: file type, mode, ownership,
executability, group-writable policy and symlink/world-writable drift for
project scripts, systemd unit sources, documentation sources and selected
top-level project source files. It never reads or prints secret values, dump
contents, log contents, answer texts, imports, exports or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SCRIPTS = ROOT / "scripts"
SYSTEMD_DIR = ROOT / "systemd"
DOCS_DIR = ROOT / "docs"

EXPECTED_PROJECT_DIRS = [ROOT, SCRIPTS, SYSTEMD_DIR, DOCS_DIR]
EXPECTED_SYSTEMD_FILES = {
    "README.md",
    "br-wissen-backup.service",
    "br-wissen-backup.timer",
    "br-wissen-healthcheck.service",
    "br-wissen-healthcheck.timer",
    "br-wissen-import-bag.service",
    "br-wissen-import-bag.timer",
    "br-wissen-import-m00h.service",
    "br-wissen-import-m00h.timer",
    "br-wissen-restore-smoke.service",
    "br-wissen-restore-smoke.timer",
}
EXPECTED_DOC_FILES = {
    "ARCHITECTURE.md",
    "PRIVILEGE-LEAST-PRIVILEGE-PLAN.md",
    "PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md",
    "PRIVILEGE-REMEDIATION-GATE.md",
    "PRIVILEGE-RISK-REVIEW.md",
    "READINESS.md",
    "RUNBOOK.md",
    "SOURCE-RULES.md",
}
NON_EXECUTABLE_SCRIPT_SOURCES = {
    "backfill-export-manifests.py",
    "chunk-imported-texts.py",
    "export-answer.py",
    "import-betrvg-xml.py",
    "import-evg-member-downloads.py",
    "import-evg-public-sources.py",
    "import-gii-law.py",
    "repair-short-text-sources.py",
}
TOP_LEVEL_SOURCE_NAMES = {
    # Deliberately narrow source-only top-level scope. Runtime artifacts,
    # secrets, dumps, logs, exports and generated files are excluded and covered
    # by separate artifact, Git and storage guards.
    ".env.example",
    ".gitignore",
    "Dockerfile",
    "README.md",
    "docker-compose.yml",
    "requirements.txt",
}


def safe_label(path: Path) -> str:
    try:
        value = str(path.relative_to(ROOT))
    except ValueError:
        value = path.name
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def mode_of(st_mode: int) -> int:
    return stat.S_IMODE(st_mode)


def direct_files(path: Path) -> list[Path]:
    if not path.exists() or not path.is_dir():
        return []
    return sorted(entry for entry in path.iterdir() if entry.is_file() or entry.is_symlink())


def check_common_file_policy(
    findings: list[str],
    path: Path,
    owner_uid: int,
    owner_gid: int,
    counters: dict[str, int],
) -> int:
    checks = 0
    label = safe_label(path)
    checks += 1
    try:
        st = path.lstat()
    except FileNotFoundError:
        findings.append("missing_file=%s" % label)
        return checks

    checks += 1
    if stat.S_ISLNK(st.st_mode):
        counters["symlinks"] += 1
        findings.append("symlink_file=%s" % label)
        return checks

    checks += 1
    if not stat.S_ISREG(st.st_mode):
        findings.append("not_regular_file=%s" % label)
        return checks

    mode = mode_of(st.st_mode)
    checks += 1
    if mode & 0o002:
        counters["world_writable"] += 1
        findings.append("world_writable_file=%s" % label)
    checks += 1
    if st.st_uid != owner_uid or st.st_gid != owner_gid:
        counters["owner_mismatches"] += 1
        findings.append("owner_mismatch_file=%s" % label)
    checks += 1
    if mode & 0o020:
        counters["group_writable_sources"] += 1
    return checks


def check_directory_policy(findings: list[str], path: Path, owner_uid: int, owner_gid: int, counters: dict[str, int]) -> int:
    checks = 0
    label = safe_label(path)
    checks += 1
    try:
        st = path.lstat()
    except FileNotFoundError:
        findings.append("missing_directory=%s" % label)
        return checks

    checks += 1
    if stat.S_ISLNK(st.st_mode):
        counters["symlinks"] += 1
        findings.append("symlink_directory=%s" % label)
        return checks

    checks += 1
    if not stat.S_ISDIR(st.st_mode):
        findings.append("not_directory=%s" % label)
        return checks

    mode = mode_of(st.st_mode)
    checks += 1
    if mode & 0o002:
        counters["world_writable"] += 1
        findings.append("world_writable_directory=%s" % label)
    checks += 1
    if st.st_uid != owner_uid or st.st_gid != owner_gid:
        counters["owner_mismatches"] += 1
        findings.append("owner_mismatch_directory=%s" % label)
    checks += 1
    if mode & 0o020:
        counters["group_writable_sources"] += 1
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen project script/unit/documentation permission policy")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    counters = {
        "world_writable": 0,
        "symlinks": 0,
        "owner_mismatches": 0,
        "executable_policy_failures": 0,
        "group_writable_sources": 0,
    }

    checks += 1
    try:
        root_stat = ROOT.lstat()
    except FileNotFoundError:
        findings.append("missing_project_root")
        root_stat = None

    owner_uid = root_stat.st_uid if root_stat else -1
    owner_gid = root_stat.st_gid if root_stat else -1

    for directory in EXPECTED_PROJECT_DIRS:
        checks += check_directory_policy(findings, directory, owner_uid, owner_gid, counters)

    script_files = direct_files(SCRIPTS)
    systemd_files = direct_files(SYSTEMD_DIR)
    docs_files = direct_files(DOCS_DIR)
    top_level_sources = sorted(path for path in (ROOT / name for name in TOP_LEVEL_SOURCE_NAMES) if path.exists() or path.is_symlink())

    checks += 3
    missing_systemd = sorted(EXPECTED_SYSTEMD_FILES - {path.name for path in systemd_files})
    missing_docs = sorted(EXPECTED_DOC_FILES - {path.name for path in docs_files})
    missing_non_exec = sorted(NON_EXECUTABLE_SCRIPT_SOURCES - {path.name for path in script_files})
    if missing_systemd:
        findings.append("missing_systemd_files=%d" % len(missing_systemd))
    if missing_docs:
        findings.append("missing_doc_files=%d" % len(missing_docs))
    if missing_non_exec:
        findings.append("missing_non_executable_script_sources=%d" % len(missing_non_exec))

    executable_scripts = 0
    non_executable_script_sources = 0
    for path in script_files:
        checks += check_common_file_policy(findings, path, owner_uid, owner_gid, counters)
        try:
            st = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            continue
        mode = mode_of(st.st_mode)
        checks += 1
        if path.name in NON_EXECUTABLE_SCRIPT_SOURCES:
            non_executable_script_sources += 1
            if mode & 0o111:
                counters["executable_policy_failures"] += 1
                findings.append("non_executable_source_is_executable=%s" % safe_label(path))
        else:
            executable_scripts += 1
            if not (mode & 0o111):
                counters["executable_policy_failures"] += 1
                findings.append("script_not_executable=%s" % safe_label(path))

    for path in systemd_files:
        checks += check_common_file_policy(findings, path, owner_uid, owner_gid, counters)
        try:
            mode = mode_of(path.lstat().st_mode)
        except FileNotFoundError:
            continue
        checks += 1
        if mode & 0o111:
            counters["executable_policy_failures"] += 1
            findings.append("systemd_source_executable=%s" % safe_label(path))

    for path in docs_files:
        checks += check_common_file_policy(findings, path, owner_uid, owner_gid, counters)
        try:
            mode = mode_of(path.lstat().st_mode)
        except FileNotFoundError:
            continue
        checks += 1
        if mode & 0o111:
            counters["executable_policy_failures"] += 1
            findings.append("doc_source_executable=%s" % safe_label(path))

    for path in top_level_sources:
        checks += check_common_file_policy(findings, path, owner_uid, owner_gid, counters)

    checks += 1
    if len(script_files) < len(NON_EXECUTABLE_SCRIPT_SOURCES):
        findings.append("script_inventory_too_small")

    status = "ok" if not findings else "failed"
    summary = (
        "script_permission_policy_status=%s checks=%d findings=%d script_files=%d executable_scripts=%d "
        "non_executable_script_sources=%d systemd_files=%d docs_files=%d top_level_sources=%d "
        "world_writable=%d symlinks=%d owner_mismatches=%d executable_policy_failures=%d group_writable_sources=%d"
        % (
            status,
            checks,
            len(findings),
            len(script_files),
            executable_scripts,
            non_executable_script_sources,
            len(systemd_files),
            len(docs_files),
            len(top_level_sources),
            counters["world_writable"],
            counters["symlinks"],
            counters["owner_mismatches"],
            counters["executable_policy_failures"],
            counters["group_writable_sources"],
        )
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
