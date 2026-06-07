#!/usr/bin/env python3
"""Read-only guard coverage consistency check for BR-Wissen.

The guard verifies that the project-level guard scripts remain consistently wired
into the expected operational surfaces: manual status, backup preflight,
systemd healthcheck and readiness documentation. It only reads project source,
documentation and systemd unit text; it never reads secrets, dumps, logs,
answers or source documents and it never changes runtime state.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STATUS_SCRIPT = ROOT / "scripts" / "status-br-wissen.sh"
BACKUP_SCRIPT = ROOT / "scripts" / "backup-br-wissen.sh"
PROJECT_HEALTHCHECK_UNIT = ROOT / "systemd" / "br-wissen-healthcheck.service"
INSTALLED_HEALTHCHECK_UNIT = Path("/etc/systemd/system/br-wissen-healthcheck.service")
READINESS = ROOT / "docs" / "READINESS.md"


@dataclass(frozen=True)
class GuardSpec:
    label: str
    script: str
    status_key: str
    status_section: str | None = None
    backup_label: str | None = None
    in_status: bool = True
    in_backup: bool = True
    in_healthcheck: bool = True
    in_readiness: bool = True
    healthcheck_args: str = " --summary"
    backup_args: str = " --summary"
    readiness_value: str = "ok"


GUARDS: list[GuardSpec] = [
    GuardSpec("Host-Kontext-Guard", "check-host-context.py", "host_context_status", "Host-Kontext-Guard", "host_context"),
    GuardSpec("Time-Sync-Guard", "check-time-sync.py", "time_sync_status", "Time-Sync-Guard", "time_sync"),
    GuardSpec("Compose-Service-Guard", "check-compose-services.py", "compose_service_status", "Compose-Service-Guard", "compose_service"),
    GuardSpec("Privilege-Policy-Guard", "check-privilege-policy.py", "privilege_policy_status", "Privilege-Policy-Guard", "privilege_policy"),
    GuardSpec("Privilege-Risk-Review-Guard", "check-privilege-risk-review.py", "privilege_risk_review_status", "Privilege-Risk-Review-Guard", "privilege_risk_review", healthcheck_args=" --summary --allow-accepted-risk", backup_args=" --summary --allow-accepted-risk", readiness_value="accepted_risk"),
    GuardSpec("Privilege-Least-Privilege-Plan-Guard", "check-privilege-least-privilege-plan.py", "privilege_least_privilege_plan_status", "Privilege-Least-Privilege-Plan-Guard", "privilege_least_privilege_plan", readiness_value="planned"),
    GuardSpec("Privilege-Remediation-Gate-Guard", "check-privilege-remediation-gate.py", "privilege_remediation_gate_status", "Privilege-Remediation-Gate-Guard", "privilege_remediation_gate", readiness_value="closed"),
    GuardSpec("Privilege-No-Sudoers-Change-Guard", "check-privilege-no-sudoers-change.py", "privilege_no_sudoers_change_status", "Privilege-No-Sudoers-Change-Guard", "privilege_no_sudoers_change", readiness_value="active"),
    GuardSpec("Core-Source-Hardening", "check-core-source-hardening.py", "core_source_hardening_status", "Core-Source-Hardening", "core_source_hardening"),
    GuardSpec("Container-Hardening", "check-container-hardening.py", "container_hardening_status", "Container-Hardening", "container_hardening"),
    GuardSpec("Container-Source-Hardening", "check-container-source-hardening.py", "container_source_hardening_status", "Container-Source-Hardening", "container_source_hardening"),
    GuardSpec("Compose-Source-Hardening", "check-compose-source-hardening.py", "compose_source_hardening_status", "Compose-Source-Hardening", "compose_source_hardening"),
    GuardSpec("Network-Source-Hardening", "check-network-source-hardening.py", "network_source_hardening_status", "Network-Source-Hardening", "network_source_hardening"),
    GuardSpec("Network-Exposure-Guard", "check-network-exposure.py", "network_exposure_status", "Network-Exposure-Guard", "network_exposure"),
    GuardSpec("Public-DNS-Exposure-Guard", "check-public-dns-exposure.py", "public_dns_exposure_status", "Public-DNS-Exposure-Guard", "public_dns_exposure"),
    GuardSpec("Public-DNS-Multiresolver-Guard", "check-public-dns-multiresolver.py", "public_dns_multiresolver_status", "Public-DNS-Multiresolver-Guard", "public_dns_multiresolver"),
    GuardSpec("Public-DNS-Authoritative-Guard", "check-public-dns-authoritative.py", "public_dns_authoritative_status", "Public-DNS-Authoritative-Guard", "public_dns_authoritative"),
    GuardSpec("Public-DNS-CAA-Guard", "check-public-dns-caa.py", "public_dns_caa_status", "Public-DNS-CAA-Guard", "public_dns_caa"),
    GuardSpec("Direct-Origin-Bypass-Guard", "check-direct-origin-bypass.py", "direct_origin_bypass_status", "Direct-Origin-Bypass-Guard", "direct_origin_bypass"),
    GuardSpec("Direct-Origin-Port-Exposure-Guard", "check-direct-origin-port-exposure.py", "direct_origin_port_exposure_status", "Direct-Origin-Port-Exposure-Guard", "direct_origin_port_exposure"),
    GuardSpec("Host-UDP-Exposure-Guard", "check-host-udp-exposure.py", "host_udp_exposure_status", "Host-UDP-Exposure-Guard", "host_udp_exposure"),
    GuardSpec("Host-Firewall-BR-Ports-Guard", "check-host-firewall-br-ports.py", "host_firewall_br_ports_status", "Host-Firewall-BR-Ports-Guard", "host_firewall_br_ports"),
    GuardSpec("Host-NFT-BR-Ports-Guard", "check-host-nft-br-ports.py", "host_nft_br_ports_status", "Host-NFT-BR-Ports-Guard", "host_nft_br_ports"),
    GuardSpec("Network-Policy-Consistency-Guard", "check-network-policy-consistency.py", "network_policy_consistency_status", "Network-Policy-Consistency-Guard", "network_policy_consistency"),
    GuardSpec("Network-Policy-Runtime-Env-Guard", "check-network-policy-runtime-env.py", "network_policy_runtime_env_status", "Network-Policy-Runtime-Env-Guard", "network_policy_runtime_env"),
    GuardSpec("Network-Policy-Runtime-Summary-Guard", "check-network-policy-runtime-summary.py", "network_policy_runtime_summary_status", "Network-Policy-Runtime-Summary-Guard", "network_policy_runtime_summary"),
    GuardSpec("Projektartefakte", "check-project-artifacts.sh", "artifact_status", "Projektartefakte", "artifact"),
    GuardSpec("Image-Pinning-Guard", "check-image-pinning-guard.sh", "image_pinning_guard_status", "Image-Pinning-Guard", "image_pinning"),
    GuardSpec("Systemd-Unit-Guard", "check-systemd-units.sh", "systemd_unit_guard_status", "Systemd Timer", "systemd_unit"),
    GuardSpec("Systemd-Loaded-Unit-Guard", "check-systemd-loaded-units.py", "systemd_loaded_unit_status", "Systemd-Loaded-Unit-Guard", "systemd_loaded_unit"),
    GuardSpec("Systemd-Source-Hardening", "check-systemd-source-hardening.py", "systemd_source_hardening_status", "Systemd-Source-Hardening", "systemd_source_hardening"),
    GuardSpec("Status-Source-Hardening", "check-status-source-hardening.py", "status_source_hardening_status", "Status-Source-Hardening", "status_source_hardening"),
    GuardSpec("Healthcheck-Source-Hardening", "check-healthcheck-source-hardening.py", "healthcheck_source_hardening_status", "Healthcheck-Source-Hardening", "healthcheck_source_hardening"),
    GuardSpec("Operational-Wrapper-Source-Hardening", "check-operational-wrapper-source-hardening.py", "operational_wrapper_source_hardening_status", "Operational-Wrapper-Source-Hardening", "operational_wrapper_source_hardening"),
    GuardSpec("Script-Permission-Policy-Guard", "check-script-permission-policy.py", "script_permission_policy_status", "Script-Permission-Policy-Guard", "script_permission_policy"),
    GuardSpec("Python-Syntax-Guard", "check-python-syntax.sh", "python_syntax_status", "Python-Syntax-Guard", "python_syntax"),
    GuardSpec("Shell-Syntax-Guard", "check-shell-syntax.sh", "shell_syntax_status", "Shell-Syntax-Guard", "shell_syntax"),
    GuardSpec("Guard-Coverage-Guard", "check-guard-coverage.py", "guard_coverage_status", "Guard-Coverage-Guard", "guard_coverage"),
    GuardSpec("Meta-Source-Hardening", "check-meta-source-hardening.py", "meta_source_hardening_status", "Meta-Source-Hardening", "meta_source_hardening"),
    GuardSpec("Doku-Source-Hardening", "check-doc-source-hardening.py", "doc_source_hardening_status", "Doku-Source-Hardening", "doc_source_hardening"),
    GuardSpec("Source-Hardening-Coverage", "check-source-hardening-coverage.py", "source_hardening_coverage_status", "Source-Hardening-Coverage", "source_hardening_coverage"),
    GuardSpec("Summary-Contract-Guard", "check-summary-contracts.py", "summary_contract_status", "Summary-Contract-Guard", "summary_contract"),
    GuardSpec("Surface-Registry-Guard", "check-surface-registry.py", "surface_registry_status", "Surface-Registry-Guard", "surface_registry"),
    GuardSpec("Guard-Registry-Integrity", "check-guard-registry-integrity.py", "guard_registry_integrity_status", "Guard-Registry-Integrity", "guard_registry_integrity"),
    GuardSpec("Protocol-Integrity-Guard", "check-protocol-integrity.py", "protocol_integrity_status", "Protocol-Integrity-Guard", "protocol_integrity"),
    GuardSpec("Git-Remote-Readiness", "check-git-remote-readiness.py", "git_remote_readiness_status", "Git-Remote-Readiness", "git_remote_readiness"),
    GuardSpec("Runtime-Log-Marker", "check-runtime-log-markers.sh", "runtime_log_marker_status", "Runtime-Log-Marker", None, in_backup=False, healthcheck_args=""),
    GuardSpec("Access-Runtime-Source-Hardening", "check-access-runtime-source-hardening.py", "access_runtime_source_hardening_status", "Access-Runtime-Source-Hardening", "access_runtime_source_hardening"),
    GuardSpec("Runtime-HTTP-Security", "check-runtime-http-security.py", "runtime_http_security_status", "Runtime-HTTP-Security", "runtime_http_security"),
    GuardSpec("External-Access-Surface", "check-external-access-surface.py", "external_access_surface_status", "External-Access-Surface", "external_access_surface"),
    GuardSpec("External-Cookie-Security", "check-external-cookie-security.py", "external_cookie_security_status", "External-Cookie-Security", "external_cookie_security"),
    GuardSpec("TLS-Certificate-Guard", "check-tls-certificate.py", "tls_certificate_status", "TLS-Certificate-Guard", "tls_certificate"),
    GuardSpec("App-Auth-Surface", "check-app-auth-surface.py", "app_auth_surface_status", "App-Auth-Surface", "app_auth_surface"),
    GuardSpec("Import-Pipeline-Guard", "check-import-pipeline.py", "import_pipeline_status", "Import-Pipeline-Guard", "import_pipeline"),
    GuardSpec("Import-Source-Hardening", "check-import-source-hardening.py", "import_source_hardening_status", "Import-Source-Hardening", "import_source_hardening"),
    GuardSpec("Antwort-/Export-Safety", "check-answer-export-safety.py", "answer_export_safety_status", "Answer-Export-Safety", "answer_export_safety"),
    GuardSpec("Data-Integrity-Source-Hardening", "check-data-integrity-source-hardening.py", "data_integrity_source_hardening_status", "Data-Integrity-Source-Hardening", "data_integrity_source_hardening"),
    GuardSpec("Audit-Trail", "check-audit-trail.py", "audit_trail_status", "Audit-Trail", "audit_trail"),
    GuardSpec("DB-Schema", "check-db-schema.py", "db_schema_status", "DB-Schema", "db_schema"),
    GuardSpec("Backup-Scope-Guard", "check-backup-scope.py", "backup_scope_status", "Backup-Scope-Guard", "backup_scope"),
    GuardSpec("Backup-Runtime-Policy-Guard", "check-backup-runtime-policy.py", "backup_runtime_policy_status", "Backup-Runtime-Policy-Guard", "backup_runtime_policy"),
    GuardSpec("Restic-Repository-Check-Freshness", "check-restic-repository-check.py", "restic_repository_check_status", "Restic-Repository-Check-Freshness", "restic_repository_check"),
    GuardSpec("Backup-Source-Hardening", "check-backup-source-hardening.py", "backup_source_hardening_status", "Backup-Source-Hardening", "backup_source_hardening"),
    GuardSpec("Restore-Source-Hardening", "check-restore-source-hardening.py", "restore_source_hardening_status", "Restore-Source-Hardening", "restore_source_hardening"),
    GuardSpec("Restore-Runtime-Policy-Guard", "check-restore-runtime-policy.py", "restore_runtime_policy_status", "Restore-Runtime-Policy-Guard", "restore_runtime_policy"),
    GuardSpec("Freshness-Source-Hardening", "check-freshness-source-hardening.py", "freshness_source_hardening_status", "Freshness-Source-Hardening", "freshness_source_hardening"),
    GuardSpec("Storage-Source-Hardening", "check-storage-source-hardening.py", "storage_source_hardening_status", "Storage-Source-Hardening", "storage_source_hardening"),
    GuardSpec("Backup-Freshness", "check-backup-freshness.py", "backup_freshness_status", "Backup-Freshness", None, in_backup=False),
    GuardSpec("Storage-Permissions", "check-storage-permissions.py", "storage_permission_status", "Storage-Permissions", "storage_permission"),
    GuardSpec("Storage-Capacity", "check-storage-capacity.py", "storage_capacity_status", "Storage-Capacity", "storage_capacity"),
    GuardSpec("Restore-Freshness", "check-restore-freshness.py", "restore_freshness_status", "Restore-Freshness", None, in_backup=False),
    GuardSpec("Readiness-Doku", "check-readiness-doc.py", "readiness_doc_status", "Readiness-Doku", "readiness_doc"),
    GuardSpec("Regression-Freshness", "check-regression-freshness.py", "regression_freshness_status", "Regression-Freshness", "regression_freshness"),
    GuardSpec("Regression-Source-Hardening", "check-regression-source-hardening.py", "regression_source_hardening_status", "Regression-Source-Hardening", "regression_source_hardening"),
]


def read_text(path: Path, findings: list[str]) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % path.name)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require_contains(findings: list[str], surface: str, haystack: str, needle: str, label: str) -> None:
    if needle not in haystack:
        findings.append("%s_missing_%s" % (surface, label))


def safe_label(value: str) -> str:
    return value.replace("/", "_").replace("-", "_").replace(" ", "_")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen guard coverage wiring")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    status_text = read_text(STATUS_SCRIPT, findings)
    backup_text = read_text(BACKUP_SCRIPT, findings)
    project_unit_text = read_text(PROJECT_HEALTHCHECK_UNIT, findings)
    installed_unit_text = read_text(INSTALLED_HEALTHCHECK_UNIT, findings)
    readiness_text = read_text(READINESS, findings)
    checks += 5

    status_expected = 0
    backup_expected = 0
    healthcheck_expected = 0
    readiness_expected = 0

    for guard in GUARDS:
        label = safe_label(guard.script)
        script_path = ROOT / "scripts" / guard.script
        checks += 1
        if not script_path.exists():
            findings.append("script_missing=%s" % label)
        checks += 1
        if script_path.exists() and not os.access(script_path, os.X_OK):
            findings.append("script_not_executable=%s" % label)

        if guard.in_status:
            status_expected += 1
            checks += 2
            require_contains(findings, "status", status_text, "scripts/%s" % guard.script, label)
            if guard.status_section:
                require_contains(findings, "status", status_text, "## %s" % guard.status_section, safe_label(guard.status_section))

        if guard.in_backup:
            backup_expected += 1
            checks += 2
            require_contains(findings, "backup", backup_text, "scripts/%s" % guard.script, label)
            if guard.backup_label:
                require_contains(findings, "backup", backup_text, "run_preflight %s" % guard.backup_label, safe_label(guard.backup_label))

        if guard.in_healthcheck:
            healthcheck_expected += 1
            unit_line = "ExecStartPre=%s/scripts/%s%s" % (ROOT, guard.script, guard.healthcheck_args)
            checks += 2
            require_contains(findings, "project_unit", project_unit_text, unit_line, label)
            require_contains(findings, "installed_unit", installed_unit_text, unit_line, label)

        if guard.in_readiness:
            readiness_expected += 1
            checks += 2
            require_contains(findings, "readiness", readiness_text, guard.label, safe_label(guard.label))
            require_contains(findings, "readiness", readiness_text, "%s=%s" % (guard.status_key, guard.readiness_value), safe_label(guard.status_key))

    status = "ok" if not findings else "failed"
    summary = (
        "guard_coverage_status=%s checks=%d findings=%d guards=%d status_expected=%d backup_expected=%d healthcheck_expected=%d readiness_expected=%d"
        % (
            status,
            checks,
            len(findings),
            len(GUARDS),
            status_expected,
            backup_expected,
            healthcheck_expected,
            readiness_expected,
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
