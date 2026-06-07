#!/usr/bin/env python3
"""Read-only privilege remediation gate guard for BR-Wissen.

The guard prevents the documented accepted sudo risk and planned least-privilege
follow-up from being mistaken for an actual sudoers remediation. It verifies a
closed remediation gate, checks the risk and plan summaries, never reads or
prints sudoers contents, full command lists, secrets, dumps, logs, answers or
source documents and does not change sudoers or other system configuration.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
GATE_DOC = ROOT / "docs" / "PRIVILEGE-REMEDIATION-GATE.md"
RISK_SCRIPT = ROOT / "scripts" / "check-privilege-risk-review.py"
PLAN_SCRIPT = ROOT / "scripts" / "check-privilege-least-privilege-plan.py"
EXPECTED_TARGET_USER = os.getenv("BR_PRIVILEGE_POLICY_USER", "chris")

REQUIRED_GATE_MARKERS = [
    "# Privilege Remediation Gate",
    "scope=br-wissen",
    "target_user=chris",
    "gate_status=closed",
    "remediation_gate=closed",
    "remediation_allowed=0",
    "actual_sudoers_change_allowed=0",
    "sudoers_auto_change_allowed=0",
    "remediation_complete_required_before_claim=1",
    "accepted_risk_must_remain_visible=1",
    "plan_status_must_remain_planned_until_change=1",
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

FORBIDDEN_GATE_MARKERS = [
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
    parser = argparse.ArgumentParser(description="Check BR-Wissen privilege remediation gate")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    text = ""

    checks += 1
    if not GATE_DOC.exists():
        findings.append("gate_doc_missing")
    elif GATE_DOC.is_symlink():
        findings.append("gate_doc_is_symlink")
    else:
        text = GATE_DOC.read_text(encoding="utf-8", errors="replace")

    for marker in REQUIRED_GATE_MARKERS:
        checks += 1
        if marker not in text:
            findings.append("gate_marker_missing=%s" % safe_label(marker))

    for marker in FORBIDDEN_GATE_MARKERS:
        checks += 1
        if marker in text:
            findings.append("gate_forbidden_marker=%s" % safe_label(marker))

    risk_code, risk = run_summary(RISK_SCRIPT, "--allow-accepted-risk")
    plan_code, plan = run_summary(PLAN_SCRIPT)
    checks += 2
    if risk_code != 0:
        findings.append("risk_summary_unavailable")
    if plan_code != 0:
        findings.append("plan_summary_unavailable")

    target_user = marker_value(text, "target_user") or risk.get("target_user") or plan.get("target_user") or "unknown"
    gate_status_value = marker_value(text, "gate_status") or "unknown"
    remediation_allowed = int(marker_value(text, "remediation_allowed") or -1)
    actual_sudoers_change_allowed = int(marker_value(text, "actual_sudoers_change_allowed") or -1)
    remediation_complete = int(plan.get("remediation_complete") or -1)
    accepted_risk_visible = 1 if risk.get("privilege_risk_review_status") == "accepted_risk" else 0
    critical_privilege_risk = int(risk.get("critical_privilege_risk") or 0)
    broad_sudo = int(risk.get("broad_sudo") or 0)
    plan_status = plan.get("privilege_least_privilege_plan_status", "unknown")
    plan_ready = int(plan.get("plan_ready") or 0)

    checks += 9
    if target_user != EXPECTED_TARGET_USER:
        findings.append("target_user_unexpected")
    if gate_status_value != "closed":
        findings.append("gate_status_not_closed")
    if remediation_allowed != 0:
        findings.append("remediation_allowed_not_zero")
    if actual_sudoers_change_allowed != 0:
        findings.append("actual_sudoers_change_allowed_not_zero")
    if not accepted_risk_visible:
        findings.append("accepted_risk_not_visible")
    if not critical_privilege_risk:
        findings.append("critical_privilege_risk_not_visible")
    if not broad_sudo:
        findings.append("broad_sudo_not_visible")
    if plan_status != "planned" or not plan_ready:
        findings.append("plan_not_planned_ready")
    if remediation_complete != 0:
        findings.append("remediation_complete_not_zero")

    gate_doc = 1 if text else 0
    status = "closed" if not findings else "failed"
    summary = "privilege_remediation_gate_status=%s checks=%d findings=%d target_user=%s remediation_allowed=%d actual_sudoers_change_allowed=%d remediation_complete=%d accepted_risk_visible=%d critical_privilege_risk=%d broad_sudo=%d plan_status=%s gate_doc=%d" % (
        status,
        checks,
        len(findings),
        target_user,
        remediation_allowed,
        actual_sudoers_change_allowed,
        remediation_complete,
        accepted_risk_visible,
        critical_privilege_risk,
        broad_sudo,
        plan_status,
        gate_doc,
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "closed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
