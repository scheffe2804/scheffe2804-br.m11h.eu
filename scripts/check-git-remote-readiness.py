#!/usr/bin/env python3
"""Read-only Git/GitHub remote readiness guard for BR-Wissen.

The guard validates that the project source tree is a clean Git repository on the
expected branch, tracks the expected GitHub SSH remote and that the tracked index
does not contain common local secret, dump, credential, backup or runtime
artifacts. It uses Git metadata only; it does not print commit contents, does not
read secret files, does not push, pull, fetch, commit, modify files or contact any
non-GitHub services.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
EXPECTED_BRANCH = os.getenv("BR_GIT_EXPECTED_BRANCH", "main")
EXPECTED_REMOTE = os.getenv("BR_GIT_EXPECTED_REMOTE", "git@github.com:scheffe2804/scheffe2804-br.m11h.eu.git")
EXPECTED_REMOTE_HEAD = os.getenv("BR_GIT_EXPECTED_REMOTE_HEAD", "refs/heads/main")
SUDO = Path("/usr/bin/sudo")
ALLOWED_TRACKED_ENV = {".env.example"}
REQUIRED_IGNORES = [
    ".env",
    "*.env",
    "!.env.example",
    "*.local",
    "*.log",
    "secrets/",
    "storage/",
    "tmp/",
    "backups/",
    "dumps/",
    "exports/",
    "*.dump",
    "*.sql.gz",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.pem",
    "*.key",
    "*.crt",
    "*.p12",
    "*.pfx",
    "*.gpg",
    "*.pgp",
    "cloudflared/*.json",
    "cloudflared/config.yml",
]

SENSITIVE_TRACKED_PATTERNS = [
    re.compile(r"(^|/)\.env$"),
    re.compile(r"\.env$"),
    re.compile(r"\.local$"),
    re.compile(r"(^|/)secrets/"),
    re.compile(r"(^|/)storage/"),
    re.compile(r"(^|/)tmp/"),
    re.compile(r"(^|/)backups/"),
    re.compile(r"(^|/)dumps/"),
    re.compile(r"(^|/)exports/"),
    re.compile(r"\.log$"),
    re.compile(r"\.(dump|sqlite|sqlite3|db)$"),
    re.compile(r"\.sql\.gz$"),
    re.compile(r"\.(pem|key|crt|csr|p12|pfx|gpg|pgp)$"),
    re.compile(r"^cloudflared/config\.yml$"),
    re.compile(r"^cloudflared/.*\.json$"),
]


def project_owner() -> str | None:
    try:
        st = ROOT.stat()
    except OSError:
        return None
    if st.st_uid == os.geteuid():
        return None
    if st.st_uid == 0:
        return None
    try:
        import pwd

        return pwd.getpwuid(st.st_uid).pw_name
    except (KeyError, ImportError):
        return None


def sudo_is_usable() -> bool:
    if not SUDO.exists() or SUDO.is_symlink() or not SUDO.is_file():
        return False
    st = SUDO.lstat()
    mode = stat.S_IMODE(st.st_mode)
    return bool(st.st_uid == 0 and st.st_gid == 0 and not mode & 0o022 and mode & 0o111 and mode & stat.S_ISUID)


def run_git(args: list[str]) -> tuple[int, str]:
    command = ["git", *args]
    owner = project_owner()
    if owner and sudo_is_usable():
        command = [str(SUDO), "-n", "-u", owner, *command]
    proc = subprocess.run(
        command,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


def read_text(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    if path.is_symlink():
        findings.append("symlink_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def tracked_sensitive(path: str) -> bool:
    if path in ALLOWED_TRACKED_ENV:
        return False
    return any(pattern.search(path) for pattern in SENSITIVE_TRACKED_PATTERNS)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen Git/GitHub remote readiness")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    checks += 1
    if not (ROOT / ".git").is_dir():
        findings.append("git_dir_missing")

    code, branch = run_git(["branch", "--show-current"])
    checks += 1
    owner = project_owner() or "self"
    if code != 0 or not branch:
        findings.append("git_branch_unavailable")
        branch = "unknown"
    elif branch != EXPECTED_BRANCH:
        findings.append("git_branch_unexpected=%s" % branch)

    code, status = run_git(["status", "--porcelain"])
    checks += 1
    dirty = 1 if status else 0
    if code != 0:
        findings.append("git_status_unavailable")
    elif dirty:
        findings.append("git_worktree_dirty")

    code, remote = run_git(["remote", "get-url", "origin"])
    checks += 1
    if code != 0 or not remote:
        findings.append("git_origin_unavailable")
        remote = "unknown"
    elif remote != EXPECTED_REMOTE:
        findings.append("git_origin_unexpected")

    code, upstream = run_git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    checks += 1
    tracking = 1 if code == 0 and upstream else 0
    if not tracking:
        findings.append("git_upstream_missing")
    elif upstream != "origin/%s" % EXPECTED_BRANCH:
        findings.append("git_upstream_unexpected=%s" % upstream)

    code, head = run_git(["rev-parse", "HEAD"])
    checks += 1
    local_head = head if code == 0 else "unknown"
    if code != 0 or not head:
        findings.append("git_head_unavailable")

    code, remote_head = run_git(["ls-remote", "--heads", "origin", EXPECTED_BRANCH])
    checks += 1
    remote_commit = "unknown"
    remote_head_present = 0
    if code != 0 or not remote_head:
        findings.append("git_remote_head_unavailable")
    else:
        parts = remote_head.split()
        if len(parts) >= 2:
            remote_commit = parts[0]
            remote_ref = parts[1]
            remote_head_present = 1 if remote_ref == EXPECTED_REMOTE_HEAD else 0
            if remote_ref != EXPECTED_REMOTE_HEAD:
                findings.append("git_remote_ref_unexpected")
            if local_head != "unknown" and remote_commit != local_head:
                findings.append("git_remote_head_mismatch")
        else:
            findings.append("git_remote_head_parse_failed")

    code, tracked = run_git(["ls-files"])
    checks += 1
    tracked_files = [line for line in tracked.splitlines() if line]
    if code != 0:
        findings.append("git_ls_files_unavailable")
    sensitive_tracked = [path for path in tracked_files if tracked_sensitive(path)]
    checks += len(tracked_files)
    if sensitive_tracked:
        findings.append("git_sensitive_tracked=%d" % len(sensitive_tracked))

    gitignore = read_text(ROOT / ".gitignore", findings, "gitignore")
    checks += 1
    missing_ignores = [pattern for pattern in REQUIRED_IGNORES if pattern not in gitignore]
    checks += len(REQUIRED_IGNORES)
    if missing_ignores:
        findings.append("gitignore_missing_patterns=%d" % len(missing_ignores))

    code, ignored = run_git(["status", "--ignored", "--short"])
    checks += 1
    ignored_count = 0
    if code != 0:
        findings.append("git_ignored_status_unavailable")
    else:
        ignored_count = len([line for line in ignored.splitlines() if line.startswith("!! ")])

    commit_short = local_head[:8] if local_head != "unknown" else "unknown"
    remote_short = remote_commit[:8] if remote_commit != "unknown" else "unknown"
    status_value = "ok" if not findings else "failed"
    summary = (
        "git_remote_readiness_status=%s checks=%d findings=%d branch=%s tracking=%d dirty=%d "
        "remote_head_present=%d local_head=%s remote_head=%s tracked_files=%d ignored_entries=%d sensitive_tracked=%d git_user=%s"
        % (
            status_value,
            checks,
            len(findings),
            branch,
            tracking,
            dirty,
            remote_head_present,
            commit_short,
            remote_short,
            len(tracked_files),
            ignored_count,
            len(sensitive_tracked),
            owner,
        )
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status_value == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
