#!/usr/bin/env python3
"""Read-only source hardening guard for the BR-Wissen status wrapper.

The guard validates the central status wrapper source for expected read-only
default behaviour, explicit opt-in for mutating/regression-producing paths,
guard-section coverage and compact summary calls. It only reads the status
wrapper source and never reads secrets, logs, dumps, answers, imports or source
documents. It does not run status checks, docker, systemctl, imports, backups,
restores or regressions.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STATUS_SCRIPT = ROOT / "scripts" / "status-br-wissen.sh"
DUPLICATE_REPORT_WRAPPER = ROOT / "scripts" / "report-duplicate-documents-docker.sh"


REQUIRED_LITERALS = [
    "set -euo pipefail",
    "ROOT=\"/home/chris/web/br.m11h.eu\"",
    "HOST_CONTEXT=\"/etc/opencode-host-context\"",
    "DATE_BIN=\"/usr/bin/date\"",
    "HOSTNAME_BIN=\"/usr/bin/hostname\"",
    "GREP_BIN=\"/usr/bin/grep\"",
    "TAILSCALE_BIN=\"/usr/bin/tailscale\"",
    "DOCKER_BIN=\"/usr/bin/docker\"",
    "SYSTEMCTL_BIN=\"/usr/bin/systemctl\"",
    "PYTHON_BIN=\"/usr/bin/python3.13\"",
    "run_regressions=0",
    "verbose_health=0",
    "show_duplicates=0",
    "show_image_pinning=0",
    "--with-regressions",
    "--verbose-health",
    "--duplicates",
    "--image-pinning",
    "Usage: status-br-wissen.sh [--with-regressions] [--verbose-health] [--duplicates] [--image-pinning]",
    "cd \"$ROOT\"",
    "timestamp_utc=$($DATE_BIN -u +%Y-%m-%dT%H:%M:%SZ)",
    "\"$GREP_BIN\" -E '^(HOST_ROLE|HOST_FQDN|THIS_SERVER|PUBLIC_IPV4|TAILSCALE_IPV4|M00H_IS_DIFFERENT_SERVER)=' \"$HOST_CONTEXT\"",
    "\"$DOCKER_BIN\" compose ps",
    "\"$SYSTEMCTL_BIN\" is-active br-wissen-healthcheck.timer br-wissen-backup.timer br-wissen-import-bag.timer br-wissen-import-m00h.timer br-wissen-restore-smoke.timer",
    "\"$SYSTEMCTL_BIN\" list-timers br-wissen-healthcheck.timer br-wissen-backup.timer br-wissen-import-bag.timer br-wissen-import-m00h.timer br-wissen-restore-smoke.timer --no-pager",
    "scripts/healthcheck-br-wissen-docker.sh --summary",
    "HEALTH_JSON=\"$health_json\" \"$PYTHON_BIN\" - <<'PY'",
    "health_status=%s",
    "scripts/check-project-artifacts.sh",
    "scripts/check-runtime-log-markers.sh",
    "scripts/check-container-images.sh --summary",
    "scripts/check-image-pinning-guard.sh --summary",
    "scripts/check-image-pinning-readiness.sh --summary --no-remote",
    "scripts/check-image-pinning-readiness.sh --summary",
    "scripts/report-duplicate-documents-docker.sh",
    "scripts/run-regressions-docker.sh",
    "skipped=true",
    "hint=Run with --with-regressions to create fresh regression answers and exports.",
    "status=ok",
]


DUPLICATE_WRAPPER_LITERALS = [
    "set -euo pipefail",
    "ROOT=\"/home/chris/web/br.m11h.eu\"",
    "DOCKER_BIN=\"/usr/bin/docker\"",
    "cd \"$ROOT\"",
    "\"$DOCKER_BIN\" compose exec -T app python - < scripts/report-duplicate-documents.py",
]


EXPECTED_SECTIONS = [
    "Host",
    "Host-Kontext-Guard",
    "Time-Sync-Guard",
    "Docker Compose",
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
    "Systemd Timer",
    "Systemd-Source-Hardening",
    "Status-Source-Hardening",
    "Healthcheck-Source-Hardening",
    "Operational-Wrapper-Source-Hardening",
    "Guard-Coverage-Guard",
    "Meta-Source-Hardening",
    "Doku-Source-Hardening",
    "Source-Hardening-Coverage",
    "Summary-Contract-Guard",
    "Surface-Registry-Guard",
    "Guard-Registry-Integrity",
    "Protocol-Integrity-Guard",
    "Git-Remote-Readiness",
    "Python-Syntax-Guard",
    "Shell-Syntax-Guard",
    "App Healthcheck",
    "Projektartefakte",
    "Runtime-Log-Marker",
    "Access-Runtime-Source-Hardening",
    "Runtime-HTTP-Security",
    "External-Access-Surface",
    "External-Cookie-Security",
    "TLS-Certificate-Guard",
    "App-Auth-Surface",
    "Import-Pipeline-Guard",
    "Import-Source-Hardening",
    "Answer-Export-Safety",
    "Data-Integrity-Source-Hardening",
    "Audit-Trail",
    "DB-Schema",
    "Backup-Scope-Guard",
    "Backup-Runtime-Policy-Guard",
    "Backup-Freshness",
    "Backup-Source-Hardening",
    "Restore-Source-Hardening",
    "Restore-Runtime-Policy-Guard",
    "Freshness-Source-Hardening",
    "Storage-Source-Hardening",
    "Storage-Permissions",
    "Storage-Capacity",
    "Restore-Freshness",
    "Readiness-Doku",
    "Regression-Freshness",
    "Regression-Source-Hardening",
    "Container-Images",
    "Image-Pinning-Guard",
    "Image-Pinning-Readiness",
    "Image-Pinning-Readiness-Remote",
    "Regressionen",
]


EXPECTED_SUMMARY_CALLS = [
    "scripts/check-host-context.py --summary",
    "scripts/check-time-sync.py --summary",
    "scripts/check-compose-services.py --summary",
    "scripts/check-privilege-policy.py --summary",
    "scripts/check-privilege-risk-review.py --summary --allow-accepted-risk",
    "scripts/check-privilege-least-privilege-plan.py --summary",
    "scripts/check-privilege-remediation-gate.py --summary",
    "scripts/check-privilege-no-sudoers-change.py --summary",
    "scripts/check-core-source-hardening.py --summary",
    "scripts/check-container-hardening.py --summary",
    "scripts/check-container-source-hardening.py --summary",
    "scripts/check-compose-source-hardening.py --summary",
    "scripts/check-network-source-hardening.py --summary",
    "scripts/check-network-exposure.py --summary",
    "scripts/check-public-dns-exposure.py --summary",
    "scripts/check-public-dns-multiresolver.py --summary",
    "scripts/check-public-dns-authoritative.py --summary",
    "scripts/check-public-dns-caa.py --summary",
    "scripts/check-direct-origin-bypass.py --summary",
    "scripts/check-direct-origin-port-exposure.py --summary",
    "scripts/check-host-udp-exposure.py --summary",
    "scripts/check-host-firewall-br-ports.py --summary",
    "scripts/check-host-nft-br-ports.py --summary",
    "scripts/check-network-policy-consistency.py --summary",
    "scripts/check-network-policy-runtime-env.py --summary",
    "scripts/check-network-policy-runtime-summary.py --summary",
    "scripts/check-systemd-units.sh --summary",
    "scripts/check-systemd-source-hardening.py --summary",
    "scripts/check-status-source-hardening.py --summary",
    "scripts/check-healthcheck-source-hardening.py --summary",
    "scripts/check-operational-wrapper-source-hardening.py --summary",
    "scripts/check-guard-coverage.py --summary",
    "scripts/check-meta-source-hardening.py --summary",
    "scripts/check-doc-source-hardening.py --summary",
    "scripts/check-source-hardening-coverage.py --summary",
    "scripts/check-summary-contracts.py --summary",
    "scripts/check-surface-registry.py --summary",
    "scripts/check-guard-registry-integrity.py --summary",
    "scripts/check-protocol-integrity.py --summary",
    "scripts/check-git-remote-readiness.py --summary",
    "scripts/check-python-syntax.sh --summary",
    "scripts/check-shell-syntax.sh --summary",
    "scripts/healthcheck-br-wissen-docker.sh --summary",
    "scripts/check-access-runtime-source-hardening.py --summary",
    "scripts/check-runtime-http-security.py --summary",
    "scripts/check-external-access-surface.py --summary",
    "scripts/check-external-cookie-security.py --summary",
    "scripts/check-tls-certificate.py --summary",
    "scripts/check-app-auth-surface.py --summary",
    "scripts/check-import-pipeline.py --summary",
    "scripts/check-import-source-hardening.py --summary",
    "scripts/check-answer-export-safety.py --summary",
    "scripts/check-data-integrity-source-hardening.py --summary",
    "scripts/check-audit-trail.py --summary",
    "scripts/check-db-schema.py --summary",
    "scripts/check-backup-scope.py --summary",
    "scripts/check-backup-runtime-policy.py --summary",
    "scripts/check-backup-freshness.py --summary",
    "scripts/check-backup-source-hardening.py --summary",
    "scripts/check-restore-source-hardening.py --summary",
    "scripts/check-restore-runtime-policy.py --summary",
    "scripts/check-freshness-source-hardening.py --summary",
    "scripts/check-storage-source-hardening.py --summary",
    "scripts/check-storage-permissions.py --summary",
    "scripts/check-storage-capacity.py --summary",
    "scripts/check-restore-freshness.py --summary",
    "scripts/check-readiness-doc.py --summary",
    "scripts/check-regression-freshness.py --summary",
    "scripts/check-regression-source-hardening.py --summary",
    "scripts/check-container-images.sh --summary",
    "scripts/check-image-pinning-guard.sh --summary",
    "scripts/check-image-pinning-readiness.sh --summary --no-remote",
    "scripts/check-image-pinning-readiness.sh --summary",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen status wrapper source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    if not STATUS_SCRIPT.exists():
        findings.append("status_script_missing")
        text = ""
    else:
        text = STATUS_SCRIPT.read_text(encoding="utf-8", errors="replace")
    checks += 1

    if not DUPLICATE_REPORT_WRAPPER.exists():
        findings.append("duplicate_wrapper_missing")
        duplicate_wrapper_text = ""
    else:
        duplicate_wrapper_text = DUPLICATE_REPORT_WRAPPER.read_text(encoding="utf-8", errors="replace")
    checks += 1

    for literal in REQUIRED_LITERALS:
        checks += 1
        if literal not in text:
            findings.append("missing_literal=%s" % safe(literal))

    for section in EXPECTED_SECTIONS:
        checks += 1
        if 'echo "## %s"' % section not in text:
            findings.append("missing_section=%s" % safe(section))

    for call in EXPECTED_SUMMARY_CALLS:
        checks += 1
        if call not in text:
            findings.append("missing_summary_call=%s" % safe(call))

    for literal in DUPLICATE_WRAPPER_LITERALS:
        checks += 1
        if literal not in duplicate_wrapper_text:
            findings.append("duplicate_wrapper_missing_literal=%s" % safe(literal))

    checks += 1
    if text.find("run_regressions=0") > text.find("scripts/run-regressions-docker.sh"):
        findings.append("regression_default_after_regression_call")
    checks += 1
    if text.find("scripts/check-backup-freshness.py --summary") > text.find("scripts/check-backup-source-hardening.py --summary"):
        findings.append("backup_freshness_after_backup_source")
    checks += 1
    if text.find("scripts/check-guard-coverage.py --summary") > text.find("scripts/check-python-syntax.sh --summary"):
        findings.append("guard_coverage_after_python_syntax")
    checks += 1
    if "--with-regressions)" not in text or "run_regressions=1" not in text:
        findings.append("regression_opt_in_missing")

    status = "ok" if not findings else "failed"
    summary = "status_source_hardening_status=%s checks=%d findings=%d sections=%d summary_calls=%d required_literals=%d duplicate_wrapper_literals=%d" % (
        status,
        checks,
        len(findings),
        len(EXPECTED_SECTIONS),
        len(EXPECTED_SUMMARY_CALLS),
        len(REQUIRED_LITERALS),
        len(DUPLICATE_WRAPPER_LITERALS),
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
