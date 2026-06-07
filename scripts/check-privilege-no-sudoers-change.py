#!/usr/bin/env python3
"""Read-only no-sudoers-change policy guard for BR-Wissen.

The guard verifies the explicit user decision that this BR-Wissen workstream must
not change sudoers. It checks the policy document plus current risk/gate summaries,
prints only compact markers, never reads or prints sudoers contents, full command
lists, secrets, dumps, logs, answers or source documents and does not change
system configuration.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
POLICY_DOC = ROOT / "docs" / "PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md"
RISK_SCRIPT = ROOT / "scripts" / "check-privilege-risk-review.py"
GATE_SCRIPT = ROOT / "scripts" / "check-privilege-remediation-gate.py"
EXPECTED_TARGET_USER = os.getenv("BR_PRIVILEGE_POLICY_USER", "chris")

REQUIRED_POLICY_MARKERS = [
    "# Privilege No-Sudoers-Change Policy",
    "scope=br-wissen",
    "target_user=chris",
    "policy_status=active",
    "sudoers_change_policy=forbidden",
    "sudoers_changes_allowed=0",
    "sudoers_remediation_requested=0",
    "sudoers_auto_change_allowed=0",
    "actual_sudoers_change_allowed=0",
    "remediation_complete=0",
    "accepted_risk_continues=1",
    "least_privilege_planning_only=1",
    "requires_new_explicit_user_request_before_sudoers_change=1",
    "no_sudoers_contents",
]

FORBIDDEN_POLICY_MARKERS = [
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


def parse_key_values(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for part in line.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        values[key] = value
    return values


def run_summary(script: Path, *extra_args: str) -> tuple[int, dict[str, str]]:
    proc = subprocess.run(
        [str(script), "--summary", *extra_args],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return proc.returncode, {}
    return proc.returncode, parse_key_values(proc.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen no-sudoers-change policy")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    text = ""

    checks += 1
    if not POLICY_DOC.exists():
        findings.append("policy_doc_missing")
    elif POLICY_DOC.is_symlink():
        findings.append("policy_doc_is_symlink")
    else:
        text = POLICY_DOC.read_text(encoding="utf-8", errors="replace")

    for marker in REQUIRED_POLICY_MARKERS:
        checks += 1
        if marker not in text:
            findings.append("policy_marker_missing=%s" % safe_label(marker))

    for marker in FORBIDDEN_POLICY_MARKERS:
        checks += 1
        if marker in text:
            findings.append("policy_forbidden_marker=%s" % safe_label(marker))

    risk_code, risk = run_summary(RISK_SCRIPT, "--allow-accepted-risk")
    gate_code, gate = run_summary(GATE_SCRIPT)
    checks += 2
    if risk_code != 0:
        findings.append("risk_summary_unavailable")
    if gate_code != 0:
        findings.append("gate_summary_unavailable")

    target_user = marker_value(text, "target_user") or risk.get("target_user") or gate.get("target_user") or "unknown"
    policy_status_value = marker_value(text, "policy_status") or "unknown"
    sudoers_changes_allowed = int(marker_value(text, "sudoers_changes_allowed") or -1)
    sudoers_remediation_requested = int(marker_value(text, "sudoers_remediation_requested") or -1)
    actual_sudoers_change_allowed = int(marker_value(text, "actual_sudoers_change_allowed") or -1)
    remediation_complete = int(marker_value(text, "remediation_complete") or -1)
    accepted_risk_continues = int(marker_value(text, "accepted_risk_continues") or 0)
    risk_status = risk.get("privilege_risk_review_status", "unknown")
    gate_status = gate.get("privilege_remediation_gate_status", "unknown")
    critical_privilege_risk = int(risk.get("critical_privilege_risk") or 0)
    broad_sudo = int(risk.get("broad_sudo") or 0)

    checks += 10
    if target_user != EXPECTED_TARGET_USER:
        findings.append("target_user_unexpected")
    if policy_status_value != "active":
        findings.append("policy_status_not_active")
    if sudoers_changes_allowed != 0:
        findings.append("sudoers_changes_allowed_not_zero")
    if sudoers_remediation_requested != 0:
        findings.append("sudoers_remediation_requested_not_zero")
    if actual_sudoers_change_allowed != 0:
        findings.append("actual_sudoers_change_allowed_not_zero")
    if remediation_complete != 0:
        findings.append("remediation_complete_not_zero")
    if accepted_risk_continues != 1:
        findings.append("accepted_risk_continues_not_one")
    if risk_status != "accepted_risk" or not critical_privilege_risk:
        findings.append("accepted_critical_risk_not_visible")
    if gate_status != "closed":
        findings.append("remediation_gate_not_closed")
    if not broad_sudo:
        findings.append("broad_sudo_not_visible")

    policy_doc = 1 if text else 0
    status = "active" if not findings else "failed"
    summary = "privilege_no_sudoers_change_status=%s checks=%d findings=%d target_user=%s sudoers_changes_allowed=%d sudoers_remediation_requested=%d actual_sudoers_change_allowed=%d remediation_complete=%d accepted_risk_continues=%d critical_privilege_risk=%d broad_sudo=%d gate_status=%s policy_doc=%d" % (
        status,
        checks,
        len(findings),
        target_user,
        sudoers_changes_allowed,
        sudoers_remediation_requested,
        actual_sudoers_change_allowed,
        remediation_complete,
        accepted_risk_continues,
        critical_privilege_risk,
        broad_sudo,
        gate_status,
        policy_doc,
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "active" else 1


if __name__ == "__main__":
    raise SystemExit(main())
