#!/usr/bin/env python3
"""Read-only readiness documentation freshness guard for BR-Wissen.

The guard compares the current readiness dossier against selected metadata-only
guard summaries. It never reads or prints secret values, dump contents, log
contents or credential file contents.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
READINESS = ROOT / "docs" / "READINESS.md"
PROTOCOL = Path(os.getenv("BR_PROTOCOL", "/home/chris/web/diverses/betriebsrat.md"))


def run_summary(script: str) -> tuple[int, str]:
    args = [str(ROOT / "scripts" / script), "--summary"]
    if script == "check-privilege-risk-review.py":
        args.append("--allow-accepted-risk")
    proc = subprocess.run(
        args,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


def parse_key_values(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for part in line.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        values[key] = value
    return values


def parse_stand(text: str) -> datetime | None:
    match = re.search(r"^Stand:\s*([^\s]+)\s*$", text, re.MULTILINE)
    if not match:
        return None
    value = match.group(1).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def age_hours(dt: datetime | None) -> float:
    if dt is None:
        return 999999.0
    return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen readiness documentation freshness")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=float(os.getenv("BR_READINESS_MAX_AGE_HOURS", "336")),
        help="maximum allowed age of the readiness Stand timestamp",
    )
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    text = ""
    if not READINESS.exists():
        findings.append("readiness_missing")
    else:
        text = READINESS.read_text(encoding="utf-8", errors="replace")
    checks += 1

    stand = parse_stand(text) if text else None
    stand_age_h = age_hours(stand)
    checks += 1
    if stand is None:
        findings.append("readiness_stand_missing_or_invalid")
    elif stand_age_h > args.max_age_hours:
        findings.append("readiness_stand_too_old_h=%.1f" % stand_age_h)

    required_literals = [
        "keine Secretwerte",
        "status=ok",
        "Restore-Freshness",
        "Backup-Freshness",
        "Backup-Scope-Guard",
        "Backup-Runtime-Policy-Guard",
        "Restic-Repository-Check-Freshness",
        "Restore-Runtime-Policy-Guard",
        "Backup-Source-Hardening",
        "Restore-Source-Hardening",
        "Freshness-Source-Hardening",
        "Storage-Source-Hardening",
        "Storage-Capacity",
        "Image-Pinning-Guard",
        "Systemd-Unit-Guard",
        "Systemd-Source-Hardening",
        "unit_policy_failures=0",
        "parent_policy_failures=0",
        "attr_policy_failures=0",
        "lsattr_available=1",
        "acl_tool_available=0",
        "xattr_tool_available=0",
        "Status-Source-Hardening",
        "Healthcheck-Source-Hardening",
        "Operational-Wrapper-Source-Hardening",
        "Script-Permission-Policy-Guard",
        "Python-Syntax-Guard",
        "Shell-Syntax-Guard",
        "Guard-Coverage-Guard",
        "Meta-Source-Hardening",
        "Doku-Source-Hardening",
        "Source-Hardening-Coverage",
        "Summary-Contract-Guard",
        "Surface-Registry-Guard",
        "Guard-Registry-Integrity",
        "Protocol-Integrity-Guard",
        "Git-Remote-Readiness",
        "Regression-Source-Hardening",
        "Host-Kontext-Guard",
        "Time-Sync-Guard",
        "Compose-Service-Guard",
        "Privilege-Policy-Guard",
        "Privilege-Risk-Review-Guard",
        "Privilege-Least-Privilege-Plan-Guard",
        "Privilege-Remediation-Gate-Guard",
        "Privilege-No-Sudoers-Change-Guard",
        "Core-Source-Hardening",
        "Container-Hardening",
        "Container-Source-Hardening",
        "Compose-Source-Hardening",
        "Network-Source-Hardening",
        "Network-Exposure-Guard",
        "Public-DNS-Exposure-Guard",
        "Public-DNS-Multiresolver-Guard",
        "Public-DNS-Authoritative-Guard",
        "Public-DNS-CAA-Guard",
        "Direct-Origin-Bypass-Guard",
        "Direct-Origin-Port-Exposure-Guard",
        "Host-UDP-Exposure-Guard",
        "Host-Firewall-BR-Ports-Guard",
        "Host-NFT-BR-Ports-Guard",
        "Network-Policy-Consistency-Guard",
        "Network-Policy-Runtime-Env-Guard",
        "Network-Policy-Runtime-Summary-Guard",
        "Access-Runtime-Source-Hardening",
        "Runtime-HTTP-Security",
        "External-Access-Surface",
        "External-Cookie-Security",
        "TLS-Certificate-Guard",
        "App-Auth-Surface",
        "Import-Source-Hardening",
        "Data-Integrity-Source-Hardening",
        "GitHub-Repo: `scheffe2804/scheffe2804-br.m11h.eu`",
    ]
    for literal in required_literals:
        checks += 1
        if literal not in text:
            findings.append("readiness_missing_literal=%s" % literal.replace(" ", "_"))

    summary_expectations: list[tuple[str, str, str, str | None]] = [
        ("check-host-context.py", "host_context_status", "host_context_status", "ok"),
        ("check-time-sync.py", "time_sync_status", "time_sync_status", "ok"),
        ("check-compose-services.py", "compose_service_status", "compose_service_status", "ok"),
        ("check-privilege-policy.py", "privilege_policy_status", "privilege_policy_status", "ok"),
        ("check-privilege-risk-review.py", "privilege_risk_review_status", "privilege_risk_review_status", "accepted_risk"),
        ("check-privilege-least-privilege-plan.py", "privilege_least_privilege_plan_status", "privilege_least_privilege_plan_status", "planned"),
        ("check-privilege-remediation-gate.py", "privilege_remediation_gate_status", "privilege_remediation_gate_status", "closed"),
        ("check-privilege-no-sudoers-change.py", "privilege_no_sudoers_change_status", "privilege_no_sudoers_change_status", "active"),
        ("check-core-source-hardening.py", "core_source_hardening_status", "core_source_hardening_status", "ok"),
        ("check-container-hardening.py", "container_hardening_status", "container_hardening_status", "ok"),
        ("check-container-source-hardening.py", "container_source_hardening_status", "container_source_hardening_status", "ok"),
        ("check-compose-source-hardening.py", "compose_source_hardening_status", "compose_source_hardening_status", "ok"),
        ("check-network-source-hardening.py", "network_source_hardening_status", "network_source_hardening_status", "ok"),
        ("check-network-exposure.py", "network_exposure_status", "network_exposure_status", "ok"),
        ("check-public-dns-exposure.py", "public_dns_exposure_status", "public_dns_exposure_status", "ok"),
        ("check-public-dns-multiresolver.py", "public_dns_multiresolver_status", "public_dns_multiresolver_status", "ok"),
        ("check-public-dns-authoritative.py", "public_dns_authoritative_status", "public_dns_authoritative_status", "ok"),
        ("check-public-dns-caa.py", "public_dns_caa_status", "public_dns_caa_status", "ok"),
        ("check-direct-origin-bypass.py", "direct_origin_bypass_status", "direct_origin_bypass_status", "ok"),
        ("check-direct-origin-port-exposure.py", "direct_origin_port_exposure_status", "direct_origin_port_exposure_status", "ok"),
        ("check-host-udp-exposure.py", "host_udp_exposure_status", "host_udp_exposure_status", "ok"),
        ("check-host-firewall-br-ports.py", "host_firewall_br_ports_status", "host_firewall_br_ports_status", "ok"),
        ("check-host-nft-br-ports.py", "host_nft_br_ports_status", "host_nft_br_ports_status", "ok"),
        ("check-network-policy-consistency.py", "network_policy_consistency_status", "network_policy_consistency_status", "ok"),
        ("check-network-policy-runtime-env.py", "network_policy_runtime_env_status", "network_policy_runtime_env_status", "ok"),
        ("check-network-policy-runtime-summary.py", "network_policy_runtime_summary_status", "network_policy_runtime_summary_status", "ok"),
        ("check-access-runtime-source-hardening.py", "access_runtime_source_hardening_status", "access_runtime_source_hardening_status", "ok"),
        ("check-runtime-http-security.py", "runtime_http_security_status", "runtime_http_security_status", "ok"),
        ("check-external-access-surface.py", "external_access_surface_status", "external_access_surface_status", "ok"),
        ("check-external-cookie-security.py", "external_cookie_security_status", "external_cookie_security_status", "ok"),
        ("check-tls-certificate.py", "tls_certificate_status", "tls_certificate_status", "ok"),
        ("check-app-auth-surface.py", "app_auth_surface_status", "app_auth_surface_status", "ok"),
        ("check-systemd-units.sh", "systemd_unit_guard_status", "systemd_unit_guard_status", "ok"),
        ("check-systemd-source-hardening.py", "systemd_source_hardening_status", "systemd_source_hardening_status", "ok"),
        ("check-status-source-hardening.py", "status_source_hardening_status", "status_source_hardening_status", "ok"),
        ("check-healthcheck-source-hardening.py", "healthcheck_source_hardening_status", "healthcheck_source_hardening_status", "ok"),
        ("check-operational-wrapper-source-hardening.py", "operational_wrapper_source_hardening_status", "operational_wrapper_source_hardening_status", "ok"),
        ("check-script-permission-policy.py", "script_permission_policy_status", "script_permission_policy_status", "ok"),
        ("check-backup-source-hardening.py", "backup_source_hardening_status", "backup_source_hardening_status", "ok"),
        ("check-restore-source-hardening.py", "restore_source_hardening_status", "restore_source_hardening_status", "ok"),
        ("check-freshness-source-hardening.py", "freshness_source_hardening_status", "freshness_source_hardening_status", "ok"),
        ("check-storage-source-hardening.py", "storage_source_hardening_status", "storage_source_hardening_status", "ok"),
        ("check-python-syntax.sh", "python_syntax_status", "python_syntax_status", "ok"),
        ("check-shell-syntax.sh", "shell_syntax_status", "shell_syntax_status", "ok"),
        ("check-guard-coverage.py", "guard_coverage_status", "guard_coverage_status", "ok"),
        ("check-meta-source-hardening.py", "meta_source_hardening_status", "meta_source_hardening_status", "ok"),
        ("check-doc-source-hardening.py", "doc_source_hardening_status", "doc_source_hardening_status", "ok"),
        ("check-source-hardening-coverage.py", "source_hardening_coverage_status", "source_hardening_coverage_status", "ok"),
        ("check-summary-contracts.py", "summary_contract_status", "summary_contract_status", "ok"),
        ("check-surface-registry.py", "surface_registry_status", "surface_registry_status", "ok"),
        ("check-guard-registry-integrity.py", "guard_registry_integrity_status", "guard_registry_integrity_status", "ok"),
        ("check-protocol-integrity.py", "protocol_integrity_status", "protocol_integrity_status", "ok"),
        ("check-git-remote-readiness.py", "git_remote_readiness_status", "git_remote_readiness_status", "ok"),
        ("check-storage-capacity.py", "storage_capacity_status", "storage_capacity_status", "ok"),
        ("check-import-pipeline.py", "import_pipeline_status", "import_pipeline_status", "ok"),
        ("check-import-source-hardening.py", "import_source_hardening_status", "import_source_hardening_status", "ok"),
        ("check-data-integrity-source-hardening.py", "data_integrity_source_hardening_status", "data_integrity_source_hardening_status", "ok"),
        ("check-backup-scope.py", "backup_scope_status", "backup_scope_status", "ok"),
        ("check-restore-freshness.py", "restore_freshness_status", "restore_freshness_status", "ok"),
        ("check-backup-runtime-policy.py", "backup_runtime_policy_status", "backup_runtime_policy_status", "ok"),
        ("check-restic-repository-check.py", "restic_repository_check_status", "restic_repository_check_status", "ok"),
        ("check-restore-runtime-policy.py", "restore_runtime_policy_status", "restore_runtime_policy_status", "ok"),
        ("check-regression-source-hardening.py", "regression_source_hardening_status", "regression_source_hardening_status", "ok"),
    ]

    summary_cache: dict[str, dict[str, str]] = {}
    for script, key, label, expected_value in summary_expectations:
        if script not in summary_cache:
            code, line = run_summary(script)
            checks += 1
            if code != 0:
                findings.append("summary_unavailable=%s" % script)
                summary_cache[script] = {}
            else:
                summary_cache[script] = parse_key_values(line)
        value = summary_cache.get(script, {}).get(key, "")
        checks += 1
        if not value:
            findings.append("summary_key_missing=%s" % label)
        elif expected_value is not None and value != expected_value:
            findings.append("summary_key_unexpected_%s=%s" % (label, value))

    static_summary_markers = [
        "host_context_status=ok",
        "time_sync_status=ok",
        "compose_service_status=ok",
        "privilege_policy_status=ok",
        "privilege_risk_review_status=accepted_risk",
        "critical_privilege_risk=1",
        "review_overdue=0",
        "privilege_least_privilege_plan_status=planned",
        "due_overdue=0",
        "privilege_remediation_gate_status=closed",
        "remediation_allowed=0",
        "privilege_no_sudoers_change_status=active",
        "sudoers_changes_allowed=0",
        "core_source_hardening_status=ok",
        "container_hardening_status=ok",
        "container_source_hardening_status=ok",
        "compose_source_hardening_status=ok",
        "network_source_hardening_status=ok",
        "network_exposure_status=ok",
        "public_dns_exposure_status=ok",
        "public_dns_multiresolver_status=ok",
        "public_dns_authoritative_status=ok",
        "public_dns_caa_status=ok",
        "direct_origin_bypass_status=ok",
        "direct_origin_port_exposure_status=ok",
        "host_udp_exposure_status=ok",
        "host_firewall_br_ports_status=ok",
        "host_nft_br_ports_status=ok",
        "network_policy_consistency_status=ok",
        "network_policy_runtime_env_status=ok",
        "network_policy_runtime_summary_status=ok",
        "access_runtime_source_hardening_status=ok",
        "runtime_http_security_status=ok",
        "external_access_surface_status=ok",
        "external_cookie_security_status=ok",
        "tls_certificate_status=ok",
        "app_auth_surface_status=ok",
        "systemd_unit_guard_status=ok",
        "unit_policy_failures=0",
        "parent_policy_failures=0",
        "attr_policy_failures=0",
        "lsattr_available=1",
        "acl_tool_available=0",
        "xattr_tool_available=0",
        "systemd_source_hardening_status=ok",
        "status_source_hardening_status=ok",
        "healthcheck_source_hardening_status=ok",
        "operational_wrapper_source_hardening_status=ok",
        "script_permission_policy_status=ok",
        "python_syntax_status=ok",
        "shell_syntax_status=ok",
        "guard_coverage_status=ok",
        "meta_source_hardening_status=ok",
        "doc_source_hardening_status=ok",
        "source_hardening_coverage_status=ok",
        "summary_contract_status=ok",
        "surface_registry_status=ok",
        "guard_registry_integrity_status=ok",
        "protocol_integrity_status=ok",
        "git_remote_readiness_status=ok",
        "backup_freshness_status=ok",
        "helper_binaries=5",
        "restic_binary=/usr/bin/restic",
        "backup_source_hardening_status=ok",
        "restore_source_hardening_status=ok",
        "freshness_source_hardening_status=ok",
        "storage_source_hardening_status=ok",
        "restore_freshness_status=ok",
        "storage_capacity_status=ok",
        "import_pipeline_status=ok",
        "import_source_hardening_status=ok",
        "data_integrity_source_hardening_status=ok",
        "backup_scope_status=ok",
        "backup_runtime_policy_status=ok",
        "restic_repository_check_status=ok",
        "restore_runtime_policy_status=ok",
        "protocol_snapshot_current=1",
        "regression_source_hardening_status=ok",
    ]
    for marker in static_summary_markers:
        checks += 1
        if marker not in text:
            findings.append("readiness_missing_status_marker=%s" % marker)

    checks += 1
    protocol_has_recent_entry = False
    if PROTOCOL.exists():
        protocol_text = PROTOCOL.read_text(encoding="utf-8", errors="replace")
        protocol_has_recent_entry = "BR-Wissen Readiness-/Betriebsdoku auf aktuellen gruenen Stand" in protocol_text
    if not protocol_has_recent_entry:
        findings.append("protocol_missing_readiness_update_entry")

    backup_snapshot = summary_cache.get("check-backup-scope.py", {}).get("latest_snapshot", "not_checked")
    restore_dump = summary_cache.get("check-restore-freshness.py", {}).get("restore_dump", "not_checked")

    checks += 1
    if not backup_snapshot or backup_snapshot in {"not_checked", "none"}:
        findings.append("readiness_backup_snapshot_not_resolved")
    checks += 1
    if not restore_dump or restore_dump in {"not_checked", "none"}:
        findings.append("readiness_restore_dump_not_resolved")

    status = "ok" if not findings else "failed"
    stand_value = stand.isoformat().replace("+00:00", "Z") if stand else "none"

    if args.summary:
        print(
            "readiness_doc_status=%s checks=%d findings=%d stand=%s stand_age_h=%.1f backup_snapshot=%s restore_dump=%s"
            % (status, checks, len(findings), stand_value, stand_age_h, backup_snapshot, restore_dump)
        )
    else:
        print("readiness_doc_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("stand=%s" % stand_value)
        print("stand_age_h=%.1f" % stand_age_h)
        print("backup_snapshot=%s" % backup_snapshot)
        print("restore_dump=%s" % restore_dump)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
