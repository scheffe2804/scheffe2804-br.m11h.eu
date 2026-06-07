#!/usr/bin/env python3
"""Read-only privilege risk review guard for BR-Wissen.

The guard links the current aggregate privilege-policy summary with a documented
risk acceptance and follow-up review marker. It never prints sudoers contents,
full command lists, secrets, dumps, logs, answers or source documents and it does
not change sudoers or other system configuration.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from datetime import date
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
REVIEW_DOC = ROOT / "docs" / "PRIVILEGE-RISK-REVIEW.md"
POLICY_SCRIPT = ROOT / "scripts" / "check-privilege-policy.py"
EXPECTED_TARGET_USER = os.getenv("BR_PRIVILEGE_POLICY_USER", "chris")

REQUIRED_REVIEW_MARKERS = [
    "# Privilege Risk Review",
    "scope=br-wissen",
    "target_user=chris",
    "risk_acceptance_status=accepted",
    "review_cadence=monthly",
    "last_review_date=",
    "next_review_due=",
    "least_privilege_followup=required",
    "sudoers_auto_change_allowed=0",
    "no_sudoers_contents",
    "broad_sudo=1",
]

FORBIDDEN_REVIEW_MARKERS = [
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


def parse_key_values(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for part in line.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        values[key] = value
    return values


def run_policy_summary() -> dict[str, str]:
    proc = subprocess.run([str(POLICY_SCRIPT), "--summary"], cwd=str(ROOT), text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        return {"policy_summary_status": "unavailable"}
    values = parse_key_values(proc.stdout.strip())
    values["policy_summary_status"] = "ok"
    return values


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
    parser = argparse.ArgumentParser(description="Check BR-Wissen privilege risk review documentation")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument(
        "--allow-accepted-risk",
        action="store_true",
        help="return success for documented accepted critical privilege risk in operational preflights",
    )
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    text = ""
    checks += 1
    if not REVIEW_DOC.exists():
        findings.append("review_doc_missing")
    elif REVIEW_DOC.is_symlink():
        findings.append("review_doc_is_symlink")
    else:
        text = REVIEW_DOC.read_text(encoding="utf-8", errors="replace")

    for marker in REQUIRED_REVIEW_MARKERS:
        checks += 1
        if marker not in text:
            findings.append("review_marker_missing=%s" % safe_label(marker))

    for marker in FORBIDDEN_REVIEW_MARKERS:
        checks += 1
        if marker in text:
            findings.append("review_forbidden_marker=%s" % safe_label(marker))

    policy = run_policy_summary()
    checks += 1
    if policy.get("policy_summary_status") != "ok":
        findings.append("policy_summary_unavailable")

    target_user = policy.get("target_user", "unknown")
    broad_sudo = int(policy.get("broad_sudo") or 0)
    nopasswd_all = int(policy.get("nopasswd_all") or 0)
    unrestricted_all = int(policy.get("unrestricted_all") or 0)
    acceptance = 1 if "risk_acceptance_status=accepted" in text else 0
    least_privilege_followup = 1 if "least_privilege_followup=required" in text else 0
    review_doc = 1 if text else 0
    today = date.today()
    last_review = parse_iso_date(marker_value(text, "last_review_date"))
    next_review = parse_iso_date(marker_value(text, "next_review_due"))
    review_overdue = 1 if next_review is None or next_review < today else 0
    days_until_review = (next_review - today).days if next_review is not None else -1

    checks += 8
    if target_user != EXPECTED_TARGET_USER:
        findings.append("target_user_unexpected")
    if broad_sudo and not acceptance:
        findings.append("broad_sudo_without_acceptance")
    if broad_sudo and not least_privilege_followup:
        findings.append("broad_sudo_without_least_privilege_followup")
    if broad_sudo and "sudoers_auto_change_allowed=0" not in text:
        findings.append("broad_sudo_without_no_auto_change_marker")
    if last_review is None:
        findings.append("last_review_date_missing_or_invalid")
    elif last_review > today:
        findings.append("last_review_date_in_future")
    if next_review is None:
        findings.append("next_review_due_missing_or_invalid")
    elif last_review is not None and next_review <= last_review:
        findings.append("next_review_due_not_after_last_review")
    elif review_overdue:
        findings.append("next_review_due_overdue")

    critical_privilege_risk = 1 if (broad_sudo or nopasswd_all or unrestricted_all) else 0
    status = "accepted_risk" if critical_privilege_risk and not findings else ("ok" if not findings else "failed")
    summary = "privilege_risk_review_status=%s checks=%d findings=%d target_user=%s critical_privilege_risk=%d broad_sudo=%d nopasswd_all=%d unrestricted_all=%d acceptance=%d least_privilege_followup=%d review_doc=%d review_cadence=monthly review_overdue=%d days_until_review=%d" % (
        status,
        checks,
        len(findings),
        target_user,
        critical_privilege_risk,
        broad_sudo,
        nopasswd_all,
        unrestricted_all,
        acceptance,
        least_privilege_followup,
        review_doc,
        review_overdue,
        days_until_review,
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    if status == "failed":
        return 1
    if status == "accepted_risk" and not args.allow_accepted_risk:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
