#!/usr/bin/env python3
"""Read-only least-privilege follow-up plan guard for BR-Wissen.

The guard validates that the accepted critical sudo risk has a concrete,
time-bound least-privilege follow-up plan with lockout protection, rollback,
backup and validation markers. It never reads or prints sudoers contents, full
command lists, secrets, dumps, logs, answers or source documents and it does not
change sudoers or other system configuration.
"""

from __future__ import annotations

import argparse
import os
from datetime import date
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
PLAN_DOC = ROOT / "docs" / "PRIVILEGE-LEAST-PRIVILEGE-PLAN.md"
EXPECTED_TARGET_USER = os.getenv("BR_PRIVILEGE_POLICY_USER", "chris")

REQUIRED_PLAN_MARKERS = [
    "# Privilege Least-Privilege Plan",
    "scope=br-wissen",
    "target_user=chris",
    "plan_status=planned",
    "plan_owner=chris",
    "plan_created=",
    "target_due=",
    "remediation_complete=0",
    "sudoers_auto_change_allowed=0",
    "requires_explicit_approval=1",
    "requires_lockout_protection=1",
    "requires_rollback_plan=1",
    "requires_visudo_validation=1",
    "requires_active_root_session=1",
    "requires_secondary_ssh_session=1",
    "requires_backup_before_change=1",
    "requires_restore_path_awareness=1",
    "requires_command_inventory=1",
    "requires_staged_rollout=1",
    "no_sudoers_contents",
]

FORBIDDEN_PLAN_MARKERS = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "password=",
    "token=",
    "secret=",
    "Authorization:",
    "Cookie:",
    "Set-Cookie:",
]


def safe_label(value: str) -> str:
    return value.replace(" ", "_").replace("/", "_").replace("=", "_")


def marker_value(text: str, key: str) -> str:
    prefix = "%s=" % key
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip()
    return ""


def parse_iso_date(value: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen least-privilege follow-up plan")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    text = ""

    checks += 1
    if not PLAN_DOC.exists():
        findings.append("plan_doc_missing")
    elif PLAN_DOC.is_symlink():
        findings.append("plan_doc_is_symlink")
    else:
        text = PLAN_DOC.read_text(encoding="utf-8", errors="replace")

    for marker in REQUIRED_PLAN_MARKERS:
        checks += 1
        if marker not in text:
            findings.append("plan_marker_missing=%s" % safe_label(marker))

    for marker in FORBIDDEN_PLAN_MARKERS:
        checks += 1
        if marker in text:
            findings.append("plan_forbidden_marker=%s" % safe_label(marker))

    target_user = marker_value(text, "target_user") or "unknown"
    plan_status_value = marker_value(text, "plan_status") or "unknown"
    remediation_complete = int(marker_value(text, "remediation_complete") or 0)
    plan_created = parse_iso_date(marker_value(text, "plan_created"))
    target_due = parse_iso_date(marker_value(text, "target_due"))
    today = date.today()
    due_overdue = 1 if target_due is None or target_due < today else 0
    days_until_due = (target_due - today).days if target_due is not None else -1

    checks += 7
    if target_user != EXPECTED_TARGET_USER:
        findings.append("target_user_unexpected")
    if plan_status_value != "planned":
        findings.append("plan_status_unexpected")
    if remediation_complete != 0:
        findings.append("remediation_complete_unexpected")
    if plan_created is None:
        findings.append("plan_created_missing_or_invalid")
    elif plan_created > today:
        findings.append("plan_created_in_future")
    if target_due is None:
        findings.append("target_due_missing_or_invalid")
    elif plan_created is not None and target_due <= plan_created:
        findings.append("target_due_not_after_plan_created")
    elif due_overdue:
        findings.append("target_due_overdue")

    plan_ready = 1 if text and not findings else 0
    status = "planned" if plan_ready else "failed"
    summary = "privilege_least_privilege_plan_status=%s checks=%d findings=%d target_user=%s plan_ready=%d remediation_complete=%d due_overdue=%d days_until_due=%d lockout_protection=1 rollback_plan=1 command_inventory=1 staged_rollout=1" % (
        status,
        checks,
        len(findings),
        target_user,
        plan_ready,
        remediation_complete,
        due_overdue,
        days_until_due,
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "planned" else 1


if __name__ == "__main__":
    raise SystemExit(main())
