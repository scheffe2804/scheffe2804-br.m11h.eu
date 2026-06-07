#!/usr/bin/env python3
"""Read-only runtime environment override guard for BR-Wissen network policy.

The guard checks that BR network-policy environment variables are not overridden
in the current guard runtime, installed BR systemd units, or project service
sources. It prints only variable names/counts and never prints environment values,
secrets, dump contents, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SYSTEMD_SRC = ROOT / "systemd"
INSTALLED_SYSTEMD = Path("/etc/systemd/system")

NETWORK_POLICY_ENV_NAMES = {
    "BR_DIRECT_ORIGIN_PORT_TARGETS",
    "BR_DIRECT_ORIGIN_PORTS",
    "BR_DIRECT_ORIGIN_ALLOWED_OPEN_PORTS",
    "BR_DIRECT_ORIGIN_PORT_TIMEOUT",
    "BR_DIRECT_ORIGIN_HOST",
    "BR_DIRECT_ORIGIN_TARGETS",
    "BR_DIRECT_ORIGIN_PATHS",
    "BR_DIRECT_ORIGIN_TIMEOUT",
    "BR_DIRECT_ORIGIN_HTTP_PORT",
    "BR_DIRECT_ORIGIN_HTTPS_PORT",
    "BR_HOST_UDP_PORTS",
    "BR_HOST_UDP_ALLOWED_OPEN_PORTS",
    "BR_HOST_UDP_DIRECT_HOSTS",
    "BR_FIREWALL_TCP_PORTS",
    "BR_FIREWALL_UDP_PORTS",
    "BR_FIREWALL_ALLOWED_WEB_TCP_PORTS",
    "BR_FIREWALL_EXPECTED_LOOPBACK_TCP",
    "BR_FIREWALL_DIRECT_HOSTS",
    "BR_NFT_TCP_PORTS",
    "BR_NFT_UDP_PORTS",
    "BR_NFT_ALLOWED_WEB_TCP_PORTS",
    "BR_NFT_EXPECTED_LOOPBACK_TCP",
    "BR_NFT_DIRECT_HOSTS",
    "BR_HOST_CONTEXT",
}

ALLOWED_PROJECT_REFERENCES = {
    "check-direct-origin-port-exposure.py",
    "check-direct-origin-bypass.py",
    "check-host-udp-exposure.py",
    "check-host-firewall-br-ports.py",
    "check-host-nft-br-ports.py",
    "check-network-policy-consistency.py",
    "check-network-policy-runtime-env.py",
    "check-host-context.py",
    "check-core-source-hardening.py",
    "check-network-source-hardening.py",
    "README.md",
    "RUNBOOK.md",
    "READINESS.md",
}

BR_UNITS = [
    "br-wissen-healthcheck.service",
    "br-wissen-backup.service",
    "br-wissen-import-bag.service",
    "br-wissen-import-m00h.service",
    "br-wissen-restore-smoke.service",
]


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def unit_environment(unit: str) -> tuple[int, int, list[str]]:
    proc = run(["systemctl", "show", unit, "--property=Environment,EnvironmentFiles", "--no-pager"])
    if proc.returncode != 0:
        return 1, 0, ["network_policy_runtime_unit_unavailable=%s" % unit]
    hits = 0
    findings: list[str] = []
    for name in NETWORK_POLICY_ENV_NAMES:
        if name in proc.stdout:
            hits += 1
            findings.append("network_policy_runtime_unit_override=%s" % name)
    return 1, hits, findings


def file_hits(paths: list[Path]) -> tuple[int, int, list[str]]:
    checks = 0
    hits = 0
    findings: list[str] = []
    for path in paths:
        if not path.exists() or path.is_symlink() or not path.is_file():
            continue
        checks += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in NETWORK_POLICY_ENV_NAMES:
            if name not in text:
                continue
            hits += 1
            if path.name not in ALLOWED_PROJECT_REFERENCES:
                findings.append("network_policy_runtime_source_reference=%s" % name)
    return checks, hits, findings


def project_paths() -> list[Path]:
    paths: list[Path] = []
    for rel in ["scripts", "systemd", "docs"]:
        base = ROOT / rel
        if base.exists():
            for path in base.rglob("*"):
                if path.is_file() and path.suffix in {".py", ".sh", ".service", ".timer", ".md"}:
                    paths.append(path)
    for name in ["README.md", "docker-compose.yml"]:
        path = ROOT / name
        if path.exists():
            paths.append(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen network-policy runtime env overrides")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    current_env_hits = 0
    checks += len(NETWORK_POLICY_ENV_NAMES)
    for name in sorted(NETWORK_POLICY_ENV_NAMES):
        if name in os.environ:
            current_env_hits += 1
            findings.append("network_policy_runtime_current_env_override=%s" % name)

    unit_hits = 0
    for unit in BR_UNITS:
        c, hits, unit_findings = unit_environment(unit)
        checks += c
        unit_hits += hits
        findings.extend(unit_findings)

    source_checks, source_hits, source_findings = file_hits(project_paths())
    checks += source_checks
    findings.extend(source_findings)

    installed_paths = [INSTALLED_SYSTEMD / unit for unit in BR_UNITS]
    installed_checks, installed_hits, installed_findings = file_hits(installed_paths)
    checks += installed_checks
    findings.extend(installed_findings)

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "network_policy_runtime_env_status=%s checks=%d findings=%d env_names=%d current_env_overrides=%d unit_overrides=%d project_references=%d installed_unit_references=%d"
            % (status, checks, len(findings), len(NETWORK_POLICY_ENV_NAMES), current_env_hits, unit_hits, source_hits, installed_hits)
        )
    else:
        print("network_policy_runtime_env_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("env_names=%d" % len(NETWORK_POLICY_ENV_NAMES))
        print("current_env_overrides=%d" % current_env_hits)
        print("unit_overrides=%d" % unit_hits)
        print("project_references=%d" % source_hits)
        print("installed_unit_references=%d" % installed_hits)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
