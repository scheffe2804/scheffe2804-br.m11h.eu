#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen systemd units.

The guard validates expected project systemd service/timer source markers. It
only reads unit source files under the project directory; it does not call
systemctl, does not modify installed units and never reads secrets, dumps, logs,
answers or source documents.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SYSTEMD_DIR = ROOT / "systemd"
WORKING_DIRECTORY = "/home/chris/web/br.m11h.eu"


SERVICE_EXPECTATIONS: dict[str, dict[str, str | list[str]]] = {
    "br-wissen-healthcheck.service": {
        "Description": "BR Wissensdatenbank read-only healthcheck",
        "Wants": "network-online.target docker.service",
        "After": "network-online.target docker.service",
        "Type": "oneshot",
        "User": "chris",
        "WorkingDirectory": WORKING_DIRECTORY,
        "ExecStart": "/home/chris/web/br.m11h.eu/scripts/healthcheck-br-wissen-docker.sh --summary",
        "ExecStartPre": [
            "/home/chris/web/br.m11h.eu/scripts/check-host-context.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-time-sync.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-compose-services.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-privilege-policy.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-privilege-risk-review.py --summary --allow-accepted-risk",
            "/home/chris/web/br.m11h.eu/scripts/check-privilege-least-privilege-plan.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-privilege-remediation-gate.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-privilege-no-sudoers-change.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-core-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-container-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-container-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-compose-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-network-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-network-exposure.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-public-dns-exposure.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-public-dns-multiresolver.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-public-dns-authoritative.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-public-dns-caa.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-direct-origin-bypass.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-direct-origin-port-exposure.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-host-udp-exposure.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-host-firewall-br-ports.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-host-nft-br-ports.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-network-policy-consistency.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-network-policy-runtime-env.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-network-policy-runtime-summary.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-project-artifacts.sh --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-image-pinning-guard.sh --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-systemd-units.sh --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-systemd-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-status-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-healthcheck-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-python-syntax.sh --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-shell-syntax.sh --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-guard-coverage.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-meta-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-doc-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-source-hardening-coverage.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-summary-contracts.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-surface-registry.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-guard-registry-integrity.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-protocol-integrity.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-git-remote-readiness.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-runtime-log-markers.sh",
            "/home/chris/web/br.m11h.eu/scripts/check-access-runtime-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-runtime-http-security.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-external-access-surface.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-external-cookie-security.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-tls-certificate.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-app-auth-surface.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-import-pipeline.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-import-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-answer-export-safety.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-data-integrity-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-audit-trail.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-db-schema.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-backup-scope.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-backup-runtime-policy.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-restic-repository-check.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-backup-freshness.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-backup-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-restore-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-restore-runtime-policy.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-freshness-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-storage-source-hardening.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-storage-permissions.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-storage-capacity.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-restore-freshness.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-readiness-doc.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-regression-freshness.py --summary",
            "/home/chris/web/br.m11h.eu/scripts/check-regression-source-hardening.py --summary",
        ],
    },
    "br-wissen-backup.service": {
        "Description": "BR Wissensdatenbank encrypted backup",
        "Wants": "network-online.target docker.service",
        "After": "network-online.target docker.service",
        "Type": "oneshot",
        "User": "root",
        "WorkingDirectory": WORKING_DIRECTORY,
        "ExecStart": "/home/chris/web/br.m11h.eu/scripts/backup-br-wissen.sh",
    },
    "br-wissen-import-m00h.service": {
        "Description": "BR Wissensdatenbank m00h import check",
        "Wants": "network-online.target",
        "After": "network-online.target docker.service",
        "Type": "oneshot",
        "User": "chris",
        "WorkingDirectory": WORKING_DIRECTORY,
        "ExecStart": "/home/chris/web/br.m11h.eu/scripts/import-m00h-betriebsrat.sh sync",
    },
    "br-wissen-import-bag.service": {
        "Description": "BR Wissensdatenbank BAG official decisions import",
        "Wants": "network-online.target",
        "After": "network-online.target docker.service",
        "Type": "oneshot",
        "User": "chris",
        "WorkingDirectory": WORKING_DIRECTORY,
        "ExecStart": "/home/chris/web/br.m11h.eu/scripts/import-bag-feed-docker.sh 25",
    },
    "br-wissen-restore-smoke.service": {
        "Description": "BR Wissensdatenbank automated restore-smoke drill",
        "Wants": "network-online.target docker.service",
        "After": "network-online.target docker.service",
        "Type": "oneshot",
        "User": "root",
        "WorkingDirectory": WORKING_DIRECTORY,
        "ExecStart": "/home/chris/web/br.m11h.eu/scripts/run-restore-smoke-drill.sh",
    },
}


TIMER_EXPECTATIONS: dict[str, dict[str, str]] = {
    "br-wissen-healthcheck.timer": {
        "Description": "Daily BR Wissensdatenbank read-only healthcheck",
        "OnCalendar": "*-*-* 04:12:00",
        "Persistent": "true",
        "RandomizedDelaySec": "15m",
        "WantedBy": "timers.target",
    },
    "br-wissen-import-m00h.timer": {
        "Description": "Daily BR Wissensdatenbank m00h import check",
        "OnCalendar": "*-*-* 04:17:00",
        "Persistent": "true",
        "RandomizedDelaySec": "20m",
        "WantedBy": "timers.target",
    },
    "br-wissen-import-bag.timer": {
        "Description": "Daily BR Wissensdatenbank BAG official decisions import",
        "OnCalendar": "*-*-* 04:43:00",
        "Persistent": "true",
        "RandomizedDelaySec": "20m",
        "WantedBy": "timers.target",
    },
    "br-wissen-backup.timer": {
        "Description": "Daily BR Wissensdatenbank encrypted backup",
        "OnCalendar": "*-*-* 04:47:00",
        "Persistent": "true",
        "RandomizedDelaySec": "30m",
        "WantedBy": "timers.target",
    },
    "br-wissen-restore-smoke.timer": {
        "Description": "Weekly BR Wissensdatenbank automated restore-smoke drill",
        "OnCalendar": "Sun *-*-* 06:10:00",
        "Persistent": "true",
        "RandomizedDelaySec": "45m",
        "WantedBy": "timers.target",
    },
}


def parse_unit(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key, []).append(value)
    return values


def scalar(values: dict[str, list[str]], key: str) -> str:
    entries = values.get(key) or []
    return entries[0] if entries else ""


def check_expected_values(findings: list[str], unit: str, values: dict[str, list[str]], expected: dict[str, str | list[str]]) -> int:
    checks = 0
    for key, expected_value in expected.items():
        checks += 1
        if isinstance(expected_value, list):
            actual = values.get(key) or []
            if actual != expected_value:
                findings.append("%s_%s_unexpected_count_%d" % (unit, key, len(actual)))
        else:
            actual = scalar(values, key)
            if actual != expected_value:
                findings.append("%s_%s_unexpected" % (unit, key))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen systemd source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    for unit, expected in SERVICE_EXPECTATIONS.items():
        path = SYSTEMD_DIR / unit
        checks += 1
        if not path.exists():
            findings.append("missing_service=%s" % unit)
            continue
        values = parse_unit(path)
        checks += check_expected_values(findings, unit, values, expected)

    for timer, expected in TIMER_EXPECTATIONS.items():
        path = SYSTEMD_DIR / timer
        checks += 1
        if not path.exists():
            findings.append("missing_timer=%s" % timer)
            continue
        values = parse_unit(path)
        checks += check_expected_values(findings, timer, values, expected)

    status = "ok" if not findings else "failed"
    summary = "systemd_source_hardening_status=%s checks=%d findings=%d services=%d timers=%d" % (
        status,
        checks,
        len(findings),
        len(SERVICE_EXPECTATIONS),
        len(TIMER_EXPECTATIONS),
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
