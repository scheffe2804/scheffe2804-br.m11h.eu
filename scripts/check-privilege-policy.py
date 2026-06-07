#!/usr/bin/env python3
"""Read-only sudo privilege policy visibility guard for BR-Wissen.

The guard runs `sudo -n -l` only to inspect the current user's effective sudo
policy shape. It prints only counters and policy-class flags, never sudoers file
contents, command lists beyond aggregate counts, secrets, dumps, logs, answers or
source documents. Broad sudo rights are reported as risk metadata, not as a
failing finding, because tightening sudoers is a separate system-wide change that
must be explicitly planned to avoid lockout or workflow breakage.
"""

from __future__ import annotations

import argparse
import re
import os
import stat
import subprocess
from pathlib import Path


TARGET_USER = os.getenv("BR_PRIVILEGE_POLICY_USER", "chris")
SUDO = Path("/usr/bin/sudo")


def sudo_is_usable() -> bool:
    if not SUDO.exists() or SUDO.is_symlink() or not SUDO.is_file():
        return False
    st = SUDO.lstat()
    mode = stat.S_IMODE(st.st_mode)
    return bool(st.st_uid == 0 and st.st_gid == 0 and not mode & 0o022 and mode & 0o111 and mode & stat.S_ISUID)


def run_sudo_list() -> subprocess.CompletedProcess[str]:
    if not sudo_is_usable():
        return subprocess.CompletedProcess(args=[str(SUDO), "-n", "-l", "-U", TARGET_USER], returncode=127, stdout="", stderr="sudo helper unavailable")
    return subprocess.run([str(SUDO), "-n", "-l", "-U", TARGET_USER], text=True, capture_output=True, check=False)


def parse_policy(text: str) -> dict[str, int | str]:
    command_lines = [line.strip() for line in text.splitlines() if re.match(r"^\s*\([^)]*\)\s+", line)]
    nopasswd_all = 0
    unrestricted_all = 0
    nopasswd_entries = 0
    password_entries = 0
    command_entries = 0
    for line in command_lines:
        command_entries += 1
        if "NOPASSWD:" in line:
            nopasswd_entries += 1
        else:
            password_entries += 1
        if re.search(r"\)\s+NOPASSWD:\s+ALL\s*$", line):
            nopasswd_all = 1
        if re.search(r"\)\s+ALL\s*$", line):
            unrestricted_all = 1
    return {
        "command_entries": command_entries,
        "nopasswd_entries": nopasswd_entries,
        "password_entries": password_entries,
        "nopasswd_all": nopasswd_all,
        "unrestricted_all": unrestricted_all,
        "sudo_list_lines": len(text.splitlines()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen sudo privilege policy visibility")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    proc = run_sudo_list()
    checks += 1
    if proc.returncode != 0:
        findings.append("sudo_list_unavailable")
    checks += 1
    if proc.stderr and "password" in proc.stderr.lower():
        findings.append("sudo_list_password_prompt")

    policy = parse_policy(proc.stdout if proc.returncode == 0 else "")
    command_entries = int(policy.get("command_entries") or 0)
    nopasswd_entries = int(policy.get("nopasswd_entries") or 0)
    password_entries = int(policy.get("password_entries") or 0)
    nopasswd_all = int(policy.get("nopasswd_all") or 0)
    unrestricted_all = int(policy.get("unrestricted_all") or 0)
    sudo_list_lines = int(policy.get("sudo_list_lines") or 0)

    checks += 3
    if proc.returncode == 0 and command_entries < 1:
        findings.append("sudo_command_entries_missing")
    if nopasswd_entries > command_entries:
        findings.append("sudo_nopasswd_count_invalid")
    if password_entries > command_entries:
        findings.append("sudo_password_count_invalid")

    broad_sudo = 1 if (nopasswd_all or unrestricted_all) else 0
    status = "ok" if not findings else "failed"
    summary = "privilege_policy_status=%s checks=%d findings=%d target_user=%s sudo_list_lines=%d command_entries=%d nopasswd_entries=%d password_entries=%d nopasswd_all=%d unrestricted_all=%d broad_sudo=%d" % (
        status,
        checks,
        len(findings),
        TARGET_USER,
        sudo_list_lines,
        command_entries,
        nopasswd_entries,
        password_entries,
        nopasswd_all,
        unrestricted_all,
        broad_sudo,
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
