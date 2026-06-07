#!/usr/bin/env python3
"""Read-only runtime summary consistency guard for BR-Wissen network policy.

The guard executes existing metadata-only network/exposure guard summaries and
checks that their current runtime counters remain mutually plausible. It does not
alter firewall, DNS, Cloudflare, Caddy or application state, does not read secret
values, dumps, logs, answers or source documents, and prints only compact
counter/finding labels.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SCRIPTS = ROOT / "scripts"

SUMMARY_TIMEOUT_SECONDS = int(os.getenv("BR_NETWORK_POLICY_RUNTIME_SUMMARY_TIMEOUT", "90"))

NETWORK_GUARDS: list[tuple[str, str, str]] = [
    ("network_exposure", "check-network-exposure.py", "network_exposure_status"),
    ("public_dns_exposure", "check-public-dns-exposure.py", "public_dns_exposure_status"),
    ("public_dns_multiresolver", "check-public-dns-multiresolver.py", "public_dns_multiresolver_status"),
    ("public_dns_authoritative", "check-public-dns-authoritative.py", "public_dns_authoritative_status"),
    ("public_dns_caa", "check-public-dns-caa.py", "public_dns_caa_status"),
    ("direct_origin_bypass", "check-direct-origin-bypass.py", "direct_origin_bypass_status"),
    ("direct_origin_port_exposure", "check-direct-origin-port-exposure.py", "direct_origin_port_exposure_status"),
    ("host_udp_exposure", "check-host-udp-exposure.py", "host_udp_exposure_status"),
    ("host_firewall_br_ports", "check-host-firewall-br-ports.py", "host_firewall_br_ports_status"),
    ("host_nft_br_ports", "check-host-nft-br-ports.py", "host_nft_br_ports_status"),
    ("network_policy_consistency", "check-network-policy-consistency.py", "network_policy_consistency_status"),
    ("network_policy_runtime_env", "check-network-policy-runtime-env.py", "network_policy_runtime_env_status"),
]


def run_summary(script: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            [str(SCRIPTS / script), "--summary"],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
            timeout=SUMMARY_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return 124, ""
    return proc.returncode, proc.stdout.strip().splitlines()[-1].strip() if proc.stdout.strip() else ""


def parse_key_values(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for part in line.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        values[key] = value
    return values


def int_value(values: dict[str, str], key: str, default: int = -1) -> int:
    try:
        return int(str(values.get(key, default)))
    except ValueError:
        return default


def require_int(findings: list[str], values: dict[str, str], label: str, key: str, expected: int) -> None:
    actual = int_value(values, key)
    if actual != expected:
        findings.append("%s_%s_unexpected_%s" % (label, key, actual))


def require_min(findings: list[str], values: dict[str, str], label: str, key: str, minimum: int) -> None:
    actual = int_value(values, key)
    if actual < minimum:
        findings.append("%s_%s_below_%d" % (label, key, minimum))


def require_str(findings: list[str], values: dict[str, str], label: str, key: str, expected: str) -> None:
    actual = values.get(key, "")
    if actual != expected:
        findings.append("%s_%s_unexpected" % (label, key))


def check_invariants(summaries: dict[str, dict[str, str]], findings: list[str]) -> dict[str, int]:
    counters = {
        "ok_summaries": 0,
        "failed_summaries": 0,
        "runtime_findings": 0,
        "origin_targets": 0,
        "direct_hosts": 0,
        "tcp_ports": 0,
        "udp_ports": 0,
        "web_tcp": 0,
        "loopback_tcp": 0,
    }

    for label, _script, status_key in NETWORK_GUARDS:
        values = summaries.get(label, {})
        if values.get(status_key) == "ok":
            counters["ok_summaries"] += 1
        else:
            counters["failed_summaries"] += 1
            findings.append("%s_status_not_ok" % label)

    ne = summaries.get("network_exposure", {})
    require_int(findings, ne, "network_exposure", "published_ports", 1)
    require_int(findings, ne, "network_exposure", "public_binds", 0)
    require_int(findings, ne, "network_exposure", "non_loopback_listeners", 0)
    require_str(findings, ne, "network_exposure", "tunnel_host", "br.m11h.eu")

    for label in ["public_dns_exposure", "public_dns_multiresolver", "public_dns_authoritative"]:
        values = summaries.get(label, {})
        require_int(findings, values, label, "forbidden_hits", 0)
        require_int(findings, values, label, "non_public_records", 0)
        require_min(findings, values, label, "global_records", 1)
    require_int(findings, summaries.get("public_dns_caa", {}), "public_dns_caa", "blocked_issue", 0)
    require_int(findings, summaries.get("public_dns_caa", {}), "public_dns_caa", "critical_unknown", 0)

    bypass = summaries.get("direct_origin_bypass", {})
    require_int(findings, bypass, "direct_origin_bypass", "targets", 4)
    require_int(findings, bypass, "direct_origin_bypass", "named_targets", 0)
    require_int(findings, bypass, "direct_origin_bypass", "valid_https", 0)
    require_int(findings, bypass, "direct_origin_bypass", "bypass_findings", 0)
    require_int(findings, bypass, "direct_origin_bypass", "unsafe_http", 0)

    ports = summaries.get("direct_origin_port_exposure", {})
    require_int(findings, ports, "direct_origin_port_exposure", "targets", 4)
    require_int(findings, ports, "direct_origin_port_exposure", "ports", 7)
    require_int(findings, ports, "direct_origin_port_exposure", "unexpected_open", 0)
    require_str(findings, ports, "direct_origin_port_exposure", "allowed_ports", "80:443")

    udp = summaries.get("host_udp_exposure", {})
    require_int(findings, udp, "host_udp_exposure", "ports", 7)
    require_int(findings, udp, "host_udp_exposure", "direct_hosts", 6)
    require_int(findings, udp, "host_udp_exposure", "unexpected_host_udp", 0)
    require_str(findings, udp, "host_udp_exposure", "allowed_udp_ports", "none")

    firewall = summaries.get("host_firewall_br_ports", {})
    require_int(findings, firewall, "host_firewall_br_ports", "direct_hosts", 6)
    require_int(findings, firewall, "host_firewall_br_ports", "unexpected_input_accepts", 0)
    require_int(findings, firewall, "host_firewall_br_ports", "unexpected_nat_rules", 0)
    require_int(findings, firewall, "host_firewall_br_ports", "expected_loopback_nat", 1)

    nft = summaries.get("host_nft_br_ports", {})
    require_int(findings, nft, "host_nft_br_ports", "direct_hosts", 6)
    require_int(findings, nft, "host_nft_br_ports", "unexpected_input_accepts", 0)
    require_int(findings, nft, "host_nft_br_ports", "unexpected_nat_rules", 0)
    require_int(findings, nft, "host_nft_br_ports", "expected_loopback_nat", 1)
    for key in ["unsupported_expr_rules", "unsupported_jump_rules", "unresolved_jump_rules", "chain_traversal_cycles", "unresolved_setref_rules"]:
        require_int(findings, nft, "host_nft_br_ports", key, 0)

    consistency = summaries.get("network_policy_consistency", {})
    require_int(findings, consistency, "network_policy_consistency", "concrete_targets", 4)
    require_int(findings, consistency, "network_policy_consistency", "wildcard_hosts", 2)
    require_int(findings, consistency, "network_policy_consistency", "tcp_ports", 7)
    require_int(findings, consistency, "network_policy_consistency", "udp_ports", 7)
    require_int(findings, consistency, "network_policy_consistency", "web_tcp", 2)
    require_int(findings, consistency, "network_policy_consistency", "loopback_tcp", 1)

    runtime_env = summaries.get("network_policy_runtime_env", {})
    require_int(findings, runtime_env, "network_policy_runtime_env", "current_env_overrides", 0)
    require_int(findings, runtime_env, "network_policy_runtime_env", "unit_overrides", 0)
    require_int(findings, runtime_env, "network_policy_runtime_env", "installed_unit_references", 0)

    counters["runtime_findings"] = len(findings)
    counters["origin_targets"] = int_value(consistency, "concrete_targets", 0)
    counters["direct_hosts"] = int_value(udp, "direct_hosts", 0)
    counters["tcp_ports"] = int_value(consistency, "tcp_ports", 0)
    counters["udp_ports"] = int_value(consistency, "udp_ports", 0)
    counters["web_tcp"] = int_value(consistency, "web_tcp", 0)
    counters["loopback_tcp"] = int_value(consistency, "loopback_tcp", 0)
    return counters


def main() -> int:
    parser = argparse.ArgumentParser(description="Check runtime summary consistency across BR-Wissen network policy guards")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    summaries: dict[str, dict[str, str]] = {}

    for label, script, _status_key in NETWORK_GUARDS:
        checks += 1
        code, line = run_summary(script)
        if code != 0:
            findings.append("summary_unavailable_%s_rc_%d" % (label, code))
            summaries[label] = {}
            continue
        values = parse_key_values(line)
        summaries[label] = values
        if not values:
            findings.append("summary_empty_%s" % label)

    counters = check_invariants(summaries, findings)
    checks += 53

    status = "ok" if not findings else "failed"
    summary = (
        "network_policy_runtime_summary_status=%s checks=%d findings=%d summaries=%d ok_summaries=%d failed_summaries=%d origin_targets=%d direct_hosts=%d tcp_ports=%d udp_ports=%d web_tcp=%d loopback_tcp=%d"
        % (
            status,
            checks,
            len(findings),
            len(NETWORK_GUARDS),
            counters.get("ok_summaries", 0),
            counters.get("failed_summaries", 0),
            counters.get("origin_targets", 0),
            counters.get("direct_hosts", 0),
            counters.get("tcp_ports", 0),
            counters.get("udp_ports", 0),
            counters.get("web_tcp", 0),
            counters.get("loopback_tcp", 0),
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
