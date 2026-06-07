#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen documentation sources.

The guard validates README, Runbook, systemd documentation and the readiness
dossier for expected operational, guardrail, backup/restore and no-secret
documentation markers. It only reads project documentation files; it does not
run status checks, systemctl, Docker, backups, restores, imports, regressions or
database queries and never reads secrets, dumps, logs, answers or source
documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
README = ROOT / "README.md"
RUNBOOK = ROOT / "docs" / "RUNBOOK.md"
SYSTEMD_README = ROOT / "systemd" / "README.md"
READINESS = ROOT / "docs" / "READINESS.md"


README_MARKERS: list[tuple[str, str]] = [
    ("title", "# BR Wissensdatenbank (`br.m11h.eu`)"),
    ("paths", "/home/chris/web/br.m11h.eu"),
    ("protocol", "/home/chris/web/diverses/betriebsrat.md"),
    ("status", "scripts/status-br-wissen.sh"),
    ("no_regression_default", "Standardmaessig werden keine neuen Testantworten erzeugt"),
    ("doc_source_heading", "Doku-Source-Hardening-Guard pruefen"),
    ("doc_source_command", "scripts/check-doc-source-hardening.py --summary"),
    ("source_coverage_heading", "Source-Hardening-Coverage-Guard pruefen"),
    ("source_coverage_command", "scripts/check-source-hardening-coverage.py --summary"),
    ("summary_contract_heading", "Summary-Contract-Guard pruefen"),
    ("summary_contract_command", "scripts/check-summary-contracts.py --summary"),
    ("surface_registry_heading", "Surface-Registry-Guard pruefen"),
    ("surface_registry_command", "scripts/check-surface-registry.py --summary"),
    ("guard_registry_integrity_heading", "Guard-Registry-Integrity pruefen"),
    ("guard_registry_integrity_command", "scripts/check-guard-registry-integrity.py --summary"),
    ("protocol_integrity_heading", "Protocol-Integrity-Guard pruefen"),
    ("protocol_integrity_command", "scripts/check-protocol-integrity.py --summary"),
    ("git_remote_readiness_heading", "Git-Remote-Readiness pruefen"),
    ("git_remote_readiness_command", "scripts/check-git-remote-readiness.py --summary"),
    ("git_remote_readiness_status", "git_remote_readiness_status=ok"),
    ("github_repo", "scheffe2804/scheffe2804-br.m11h.eu"),
    ("doc_source_read_only", "Der Guard ist read-only"),
    ("doc_source_surfaces", "normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight"),
    ("meta_source", "Meta-Source-Hardening-Guard pruefen"),
    ("backup_source", "Backup-Source-Hardening-Guard pruefen"),
    ("restore_source", "Restore-Source-Hardening-Guard pruefen"),
    ("restore_runtime_policy_heading", "Restore-Runtime-Policy-Guard pruefen"),
    ("restore_runtime_policy_command", "scripts/check-restore-runtime-policy.py --summary"),
    ("restore_resolved_snapshot", "restore_resolved_snapshot=<id>"),
    ("freshness_source", "Freshness-Source-Hardening-Guard pruefen"),
    ("storage_source", "Storage-Source-Hardening-Guard pruefen"),
    ("data_integrity_source", "Data-Integrity-Source-Hardening-Guard pruefen"),
    ("backup_scope_heading", "Backup-Scope-Guard pruefen"),
    ("backup_scope_command", "scripts/check-backup-scope.py --summary"),
    ("backup_freshness_protocol_snapshot", "protocol_snapshot_current=1"),
    ("backup_freshness_helpers", "restic_binary=<pfad>"),
    ("privilege_policy", "Privilege-Policy-Guard"),
    ("privilege_policy_status", "privilege_policy_status=ok"),
    ("privilege_risk_review", "Privilege-Risk-Review-Guard"),
    ("privilege_risk_review_status", "privilege_risk_review_status=accepted_risk"),
    ("privilege_risk_critical", "critical_privilege_risk=1"),
    ("privilege_risk_review_doc", "docs/PRIVILEGE-RISK-REVIEW.md"),
    ("privilege_risk_review_due", "next_review_due"),
    ("privilege_plan", "Privilege-Least-Privilege-Plan-Guard"),
    ("privilege_plan_status", "privilege_least_privilege_plan_status=planned"),
    ("privilege_plan_doc", "docs/PRIVILEGE-LEAST-PRIVILEGE-PLAN.md"),
    ("privilege_plan_due", "target_due"),
    ("privilege_gate", "Privilege-Remediation-Gate-Guard"),
    ("privilege_gate_status", "privilege_remediation_gate_status=closed"),
    ("privilege_gate_doc", "docs/PRIVILEGE-REMEDIATION-GATE.md"),
    ("privilege_gate_closed", "remediation_allowed=0"),
    ("privilege_no_change", "Privilege-No-Sudoers-Change-Guard"),
    ("privilege_no_change_status", "privilege_no_sudoers_change_status=active"),
    ("privilege_no_change_doc", "docs/PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md"),
    ("privilege_no_change_forbidden", "sudoers_changes_allowed=0"),
    ("backup_runtime_policy_heading", "Backup-Runtime-Policy-Guard pruefen"),
    ("backup_runtime_policy_command", "scripts/check-backup-runtime-policy.py --summary"),
    ("restic_repository_check_command", "scripts/check-restic-repository-check.py --summary"),
    ("restic_repository_check_status", "restic_repository_check_status=ok"),
    ("regression_source", "Regression-Source-Hardening-Guard pruefen"),
    ("no_secrets", "liest keine Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte"),
]


RUNBOOK_MARKERS: list[tuple[str, str]] = [
    ("title", "# br.m11h.eu Runbook"),
    ("readiness_link", "docs/READINESS.md"),
    ("secret_warning", "Secretwerte niemals"),
    ("status_section", "## Status und Healthcheck prüfen"),
    ("doc_source_heading", "## Doku-Source-Hardening-Guard pruefen"),
    ("doc_source_command", "scripts/check-doc-source-hardening.py --summary"),
    ("source_coverage_heading", "## Source-Hardening-Coverage-Guard pruefen"),
    ("source_coverage_command", "scripts/check-source-hardening-coverage.py --summary"),
    ("summary_contract_heading", "## Summary-Contract-Guard pruefen"),
    ("summary_contract_command", "scripts/check-summary-contracts.py --summary"),
    ("surface_registry_heading", "## Surface-Registry-Guard pruefen"),
    ("surface_registry_command", "scripts/check-surface-registry.py --summary"),
    ("guard_registry_integrity_heading", "## Guard-Registry-Integrity pruefen"),
    ("guard_registry_integrity_command", "scripts/check-guard-registry-integrity.py --summary"),
    ("protocol_integrity_heading", "## Protocol-Integrity-Guard pruefen"),
    ("protocol_integrity_command", "scripts/check-protocol-integrity.py --summary"),
    ("git_remote_readiness_heading", "## Git-Remote-Readiness pruefen"),
    ("git_remote_readiness_command", "scripts/check-git-remote-readiness.py --summary"),
    ("git_remote_readiness_status", "git_remote_readiness_status=ok"),
    ("github_repo", "scheffe2804/scheffe2804-br.m11h.eu"),
    ("doc_source_read_only", "Der Guard ist read-only"),
    ("doc_source_no_runtime", "ruft keine Statuschecks"),
    ("doc_source_surfaces", "im normalen Statuscheck unter `Doku-Source-Hardening`"),
    ("meta_source", "Meta-Source-Hardening-Guard pruefen"),
    ("systemd_sync", "scripts/check-systemd-units.sh"),
    ("backup", "## Backup"),
    ("backup_scope_heading", "## Backup-Scope-Guard pruefen"),
    ("backup_scope_command", "scripts/check-backup-scope.py --summary"),
    ("backup_freshness_protocol_snapshot", "protocol_snapshot_current=1"),
    ("backup_freshness_helpers", "restic_binary=<pfad>"),
    ("privilege_policy", "Privilege-Policy-Guard"),
    ("privilege_policy_status", "privilege_policy_status=ok"),
    ("privilege_risk_review", "Privilege-Risk-Review-Guard"),
    ("privilege_risk_review_status", "privilege_risk_review_status=accepted_risk"),
    ("privilege_risk_critical", "critical_privilege_risk=1"),
    ("privilege_risk_review_doc", "docs/PRIVILEGE-RISK-REVIEW.md"),
    ("privilege_risk_review_due", "next_review_due"),
    ("privilege_plan", "Privilege-Least-Privilege-Plan-Guard"),
    ("privilege_plan_status", "privilege_least_privilege_plan_status=planned"),
    ("privilege_plan_doc", "docs/PRIVILEGE-LEAST-PRIVILEGE-PLAN.md"),
    ("privilege_plan_due", "target_due"),
    ("privilege_gate", "Privilege-Remediation-Gate-Guard"),
    ("privilege_gate_status", "privilege_remediation_gate_status=closed"),
    ("privilege_gate_doc", "docs/PRIVILEGE-REMEDIATION-GATE.md"),
    ("privilege_gate_closed", "remediation_allowed=0"),
    ("privilege_no_change", "Privilege-No-Sudoers-Change-Guard"),
    ("privilege_no_change_status", "privilege_no_sudoers_change_status=active"),
    ("privilege_no_change_doc", "docs/PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md"),
    ("privilege_no_change_forbidden", "sudoers_changes_allowed=0"),
    ("backup_runtime_policy_heading", "## Backup-Runtime-Policy-Guard pruefen"),
    ("backup_runtime_policy_command", "scripts/check-backup-runtime-policy.py --summary"),
    ("restic_repository_check_command", "scripts/check-restic-repository-check.py --summary"),
    ("restic_repository_check_status", "restic_repository_check_status=ok"),
    ("restore_runtime_policy_heading", "## Restore-Runtime-Policy-Guard pruefen"),
    ("restore_runtime_policy_command", "scripts/check-restore-runtime-policy.py --summary"),
    ("restore_resolved_snapshot", "restore_resolved_snapshot=<id>"),
    ("restore", "## Restore"),
]


SYSTEMD_README_MARKERS: list[tuple[str, str]] = [
    ("title", "# Systemd-Units"),
    ("installed_timers", "## Installierte Timer auf m11h"),
    ("healthcheck_service", "Der Healthcheck-Service fuehrt vor dem read-only App-Healthcheck kompakte Guards"),
    ("doc_source_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-doc-source-hardening.py --summary"),
    ("source_coverage_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-source-hardening-coverage.py --summary"),
    ("summary_contract_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-summary-contracts.py --summary"),
    ("surface_registry_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-surface-registry.py --summary"),
    ("guard_registry_integrity_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-guard-registry-integrity.py --summary"),
    ("protocol_integrity_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-protocol-integrity.py --summary"),
    ("git_remote_readiness_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-git-remote-readiness.py --summary"),
    ("git_remote_readiness_status", "git_remote_readiness_status=ok"),
    ("backup_scope_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-backup-scope.py --summary"),
    ("backup_runtime_policy_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-backup-runtime-policy.py --summary"),
    ("backup_runtime_policy_explanation", "Backup-Runtime-Policy-Guard"),
    ("restic_repository_check_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-restic-repository-check.py --summary"),
    ("restic_repository_check_status", "restic_repository_check_status=ok"),
    ("backup_freshness_protocol_snapshot", "protocol_snapshot_current=1"),
    ("backup_freshness_helpers", "restic_binary=<pfad>"),
    ("privilege_policy", "Privilege-Policy-Guard"),
    ("privilege_policy_status", "privilege_policy_status=ok"),
    ("privilege_risk_review", "Privilege-Risk-Review-Guard"),
    ("privilege_risk_review_status", "privilege_risk_review_status=accepted_risk"),
    ("privilege_risk_critical", "critical_privilege_risk=1"),
    ("privilege_risk_review_due", "next_review_due"),
    ("privilege_plan", "Privilege-Least-Privilege-Plan-Guard"),
    ("privilege_plan_status", "privilege_least_privilege_plan_status=planned"),
    ("privilege_plan_due", "target_due"),
    ("privilege_gate", "Privilege-Remediation-Gate-Guard"),
    ("privilege_gate_status", "privilege_remediation_gate_status=closed"),
    ("privilege_gate_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-privilege-remediation-gate.py --summary"),
    ("privilege_gate_closed", "remediation_allowed=0"),
    ("privilege_no_change", "Privilege-No-Sudoers-Change-Guard"),
    ("privilege_no_change_status", "privilege_no_sudoers_change_status=active"),
    ("privilege_no_change_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-privilege-no-sudoers-change.py --summary"),
    ("privilege_no_change_forbidden", "sudoers_changes_allowed=0"),
    ("restore_runtime_policy_execstartpre", "ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-restore-runtime-policy.py --summary"),
    ("restore_runtime_policy_explanation", "Restore-Runtime-Policy-Guard"),
    ("restore_resolved_snapshot", "restore_resolved_snapshot=<id>"),
    ("backup_scope_explanation", "Backup-Scope-Guard"),
    ("protocol_integrity_explanation", "Protocol-Integrity-Guard"),
    ("guard_registry_integrity_explanation", "Guard-Registry-Integrity"),
    ("surface_registry_explanation", "Surface-Registry-Guard"),
    ("summary_contract_explanation", "Summary-Contract-Guard"),
    ("source_coverage_explanation", "Source-Hardening-Coverage-Guard"),
    ("doc_source_explanation", "Doku-Source-Hardening-Guard"),
    ("meta_source_explanation", "Meta-Source-Hardening-Guard"),
    ("guard_coverage", "Guard-Coverage-Guard"),
    ("readiness_doc", "Readiness-Doku-Guard"),
    ("daemon_reload", "daemon-reload"),
]


READINESS_MARKERS: list[tuple[str, str]] = [
    ("title", "# BR-Wissen Readiness-Dossier"),
    ("stand", "Stand:"),
    ("no_secrets", "keine Secretwerte"),
    ("github_repo", "GitHub-Repo: `scheffe2804/scheffe2804-br.m11h.eu`"),
    ("doc_source_guard", "Doku-Source-Hardening-Guard"),
    ("doc_source_status", "doc_source_hardening_status=ok"),
    ("source_coverage_guard", "Source-Hardening-Coverage-Guard"),
    ("source_coverage_status", "source_hardening_coverage_status=ok"),
    ("summary_contract_guard", "Summary-Contract-Guard"),
    ("summary_contract_status", "summary_contract_status=ok"),
    ("surface_registry_guard", "Surface-Registry-Guard"),
    ("surface_registry_status", "surface_registry_status=ok"),
    ("guard_registry_integrity_guard", "Guard-Registry-Integrity"),
    ("guard_registry_integrity_status", "guard_registry_integrity_status=ok"),
    ("protocol_integrity_guard", "Protocol-Integrity-Guard"),
    ("protocol_integrity_status", "protocol_integrity_status=ok"),
    ("git_remote_readiness_guard", "Git-Remote-Readiness"),
    ("git_remote_readiness_status", "git_remote_readiness_status=ok"),
    ("backup_scope_guard", "Backup-Scope-Guard"),
    ("backup_scope_status", "backup_scope_status=ok"),
    ("backup_runtime_policy_guard", "Backup-Runtime-Policy-Guard"),
    ("backup_runtime_policy_status", "backup_runtime_policy_status=ok"),
    ("restic_repository_check_guard", "Restic-Repository-Check-Freshness"),
    ("restic_repository_check_status", "restic_repository_check_status=ok"),
    ("backup_freshness_protocol_snapshot", "protocol_snapshot_current=1"),
    ("backup_freshness_helpers", "restic_binary=<pfad>"),
    ("privilege_policy", "Privilege-Policy-Guard"),
    ("privilege_policy_status", "privilege_policy_status=ok"),
    ("privilege_risk_review", "Privilege-Risk-Review-Guard"),
    ("privilege_risk_review_status", "privilege_risk_review_status=accepted_risk"),
    ("privilege_risk_critical", "critical_privilege_risk=1"),
    ("privilege_risk_review_doc", "PRIVILEGE-RISK-REVIEW.md"),
    ("privilege_risk_review_due", "next_review_due"),
    ("privilege_plan", "Privilege-Least-Privilege-Plan-Guard"),
    ("privilege_plan_status", "privilege_least_privilege_plan_status=planned"),
    ("privilege_plan_doc", "PRIVILEGE-LEAST-PRIVILEGE-PLAN.md"),
    ("privilege_plan_due", "target_due"),
    ("privilege_gate", "Privilege-Remediation-Gate-Guard"),
    ("privilege_gate_status", "privilege_remediation_gate_status=closed"),
    ("privilege_gate_doc", "PRIVILEGE-REMEDIATION-GATE.md"),
    ("privilege_gate_closed", "remediation_allowed=0"),
    ("privilege_no_change", "Privilege-No-Sudoers-Change-Guard"),
    ("privilege_no_change_status", "privilege_no_sudoers_change_status=active"),
    ("privilege_no_change_doc", "PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md"),
    ("privilege_no_change_forbidden", "sudoers_changes_allowed=0"),
    ("restore_runtime_policy_guard", "Restore-Runtime-Policy-Guard"),
    ("restore_runtime_policy_status", "restore_runtime_policy_status=ok"),
    ("restore_resolved_snapshot", "restore_resolved_snapshot="),
    ("doc_source_description", "read-only Quellenpruefung der Dokumentationsquellen"),
    ("backup_preflight", "Backup-Preflight-Kette"),
    ("guard_stand", "Aktueller Guard-Stand"),
    ("readiness_doc_status", "readiness_doc_status=ok"),
    ("readiness_backup_snapshot", "backup_snapshot="),
    ("readiness_restore_dump", "restore_dump=postgres-"),
    ("meta_source_status", "meta_source_hardening_status=ok"),
    ("backup_freshness_status", "backup_freshness_status=ok"),
    ("restore_freshness_status", "restore_freshness_status=ok"),
]


FORBIDDEN_DOC_MARKERS = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "password=",
    "token=",
    "secret=",
    "MATOMO_AUTH_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS=",
    "DATABASE_URL=postgres",
    "Authorization:",
    "Cookie:",
    "Set-Cookie:",
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
    parser = argparse.ArgumentParser(description="Check BR-Wissen documentation source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    readme_text = read_source(README, findings, "readme")
    runbook_text = read_source(RUNBOOK, findings, "runbook")
    systemd_text = read_source(SYSTEMD_README, findings, "systemd_readme")
    readiness_text = read_source(READINESS, findings, "readiness")
    checks += 4

    checks += check_markers(findings, readme_text, README_MARKERS, "readme")
    checks += check_markers(findings, runbook_text, RUNBOOK_MARKERS, "runbook")
    checks += check_markers(findings, systemd_text, SYSTEMD_README_MARKERS, "systemd_readme")
    checks += check_markers(findings, readiness_text, READINESS_MARKERS, "readiness")

    for prefix, text in [
        ("readme", readme_text),
        ("runbook", runbook_text),
        ("systemd_readme", systemd_text),
        ("readiness", readiness_text),
    ]:
        checks += check_forbidden(findings, text, FORBIDDEN_DOC_MARKERS, prefix)

    checks += 1
    if readme_text.find("Doku-Source-Hardening-Guard pruefen") < readme_text.find("Meta-Source-Hardening-Guard pruefen"):
        findings.append("readme_doc_source_before_meta_source")
    checks += 1
    if runbook_text.find("## Doku-Source-Hardening-Guard pruefen") < runbook_text.find("## Meta-Source-Hardening-Guard pruefen"):
        findings.append("runbook_doc_source_before_meta_source")
    checks += 1
    if systemd_text.find("check-doc-source-hardening.py --summary") > systemd_text.find("check-runtime-log-markers.sh"):
        findings.append("systemd_doc_source_after_runtime_log_marker")
    checks += 1
    if readiness_text.find("Doku-Source-Hardening-Guard") > readiness_text.find("Access-Runtime-Source-Hardening-Guard"):
        findings.append("readiness_doc_source_after_access_runtime")

    status = "ok" if not findings else "failed"
    summary = "doc_source_hardening_status=%s checks=%d findings=%d readme_markers=%d runbook_markers=%d systemd_readme_markers=%d readiness_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(README_MARKERS),
        len(RUNBOOK_MARKERS),
        len(SYSTEMD_README_MARKERS),
        len(READINESS_MARKERS),
        len(FORBIDDEN_DOC_MARKERS) * 4,
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
