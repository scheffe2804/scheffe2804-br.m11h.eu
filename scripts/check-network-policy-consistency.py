#!/usr/bin/env python3
"""Read-only network policy consistency guard for BR-Wissen.

The guard compares the metadata policy defaults used by the direct-origin,
host-UDP, iptables/ip6tables and nftables guards. It reads only local guard source
files and non-secret host-context metadata, does not send packets, does not alter
network/firewall state and never reads application secrets, dumps, logs, answers
or source documents.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
HOST_CONTEXT = Path(os.getenv("BR_HOST_CONTEXT", "/etc/opencode-host-context"))
SCRIPTS = ROOT / "scripts"

DIRECT_ORIGIN_PORT = SCRIPTS / "check-direct-origin-port-exposure.py"
DIRECT_ORIGIN_BYPASS = SCRIPTS / "check-direct-origin-bypass.py"
HOST_UDP = SCRIPTS / "check-host-udp-exposure.py"
HOST_FIREWALL = SCRIPTS / "check-host-firewall-br-ports.py"
HOST_NFT = SCRIPTS / "check-host-nft-br-ports.py"

EXPECTED_CONCRETE_TARGETS = {"31.70.74.139", "2a01:239:4ba:bf00::1", "100.102.205.121", "fd7a:115c:a1e0::f233:cd79"}
EXPECTED_WILDCARDS = {"0.0.0.0", "::"}
EXPECTED_WEB_TCP = {80, 443}
EXPECTED_BR_TCP = {8000, 8080, 18083, 5432, 2019}
EXPECTED_ALL_TCP = EXPECTED_WEB_TCP | EXPECTED_BR_TCP
EXPECTED_BR_UDP = {443, 80, 8000, 8080, 18083, 5432, 2019}
EXPECTED_LOOPBACK_TCP = {"127.0.0.1:18083"}


def literal_assignments(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, str):
            values[node.targets[0].id] = value
    return values


def assignment_default(path: Path, name: str, literal_values: dict[str, str]) -> str:
    if name in literal_values:
        return literal_values[name]
    text = path.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped.startswith("%s =" % name):
            continue
        strings = re.findall(r"['\"]([^'\"]*)['\"]", stripped)
        csv_like = [
            value
            for value in strings
            if value != "," and ("," in value or value.startswith("127.0.0.1:"))
        ]
        if csv_like:
            return csv_like[-1]
        if strings:
            return strings[-1]
    return ""


def split_csv(value: str) -> set[str]:
    return {item.strip().strip("[]") for item in value.split(",") if item.strip()}


def parse_ports(value: str) -> set[int]:
    ports: set[int] = set()
    for item in split_csv(value):
        try:
            ports.add(int(item))
        except ValueError:
            continue
    return ports


def host_context_values() -> dict[str, str]:
    values: dict[str, str] = {}
    if not HOST_CONTEXT.exists() or HOST_CONTEXT.is_symlink():
        return values
    for line in HOST_CONTEXT.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"PUBLIC_IPV4", "TAILSCALE_IPV4", "HOST_ROLE", "THIS_SERVER"}:
            values[key] = value.strip().strip("[]")
    return values


def require_equal(findings: list[str], label: str, actual: set[object], expected: set[object]) -> None:
    if actual != expected:
        missing = len(expected - actual)
        extra = len(actual - expected)
        findings.append("network_policy_%s_mismatch_missing_%d_extra_%d" % (label, missing, extra))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen network policy consistency across guards")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    files = [DIRECT_ORIGIN_PORT, DIRECT_ORIGIN_BYPASS, HOST_UDP, HOST_FIREWALL, HOST_NFT]
    for path in files:
        checks += 1
        if not path.exists() or path.is_symlink():
            findings.append("network_policy_source_unavailable=%s" % path.name)

    direct_port = literal_assignments(DIRECT_ORIGIN_PORT) if DIRECT_ORIGIN_PORT.exists() else {}
    direct_bypass = literal_assignments(DIRECT_ORIGIN_BYPASS) if DIRECT_ORIGIN_BYPASS.exists() else {}
    host_udp = literal_assignments(HOST_UDP) if HOST_UDP.exists() else {}
    host_firewall = literal_assignments(HOST_FIREWALL) if HOST_FIREWALL.exists() else {}
    host_nft = literal_assignments(HOST_NFT) if HOST_NFT.exists() else {}
    context = host_context_values()

    direct_targets = split_csv(direct_port.get("DEFAULT_TARGETS", ""))
    bypass_targets = split_csv(direct_bypass.get("DEFAULT_TARGETS", ""))
    udp_direct_hosts = split_csv(host_udp.get("DEFAULT_DIRECT_HOSTS", ""))
    firewall_direct_hosts = split_csv(host_firewall.get("DEFAULT_DIRECT_HOSTS", ""))
    nft_direct_hosts = split_csv(host_nft.get("DEFAULT_DIRECT_HOSTS", ""))

    direct_ports = parse_ports(direct_port.get("DEFAULT_PORTS", ""))
    direct_allowed = parse_ports(direct_port.get("DEFAULT_ALLOWED_OPEN_PORTS", ""))
    udp_ports = parse_ports(host_udp.get("DEFAULT_PORTS", ""))
    udp_allowed = parse_ports(host_udp.get("DEFAULT_ALLOWED_OPEN_PORTS", ""))
    firewall_tcp = parse_ports(assignment_default(HOST_FIREWALL, "BR_TCP_PORTS_RAW", host_firewall))
    firewall_udp = parse_ports(assignment_default(HOST_FIREWALL, "BR_UDP_PORTS_RAW", host_firewall))
    firewall_web = parse_ports(assignment_default(HOST_FIREWALL, "WEB_TCP_PORTS_RAW", host_firewall))
    nft_tcp_raw = assignment_default(HOST_NFT, "BR_TCP_PORTS_RAW", host_nft) or assignment_default(HOST_FIREWALL, "BR_TCP_PORTS_RAW", host_firewall)
    nft_udp_raw = assignment_default(HOST_NFT, "BR_UDP_PORTS_RAW", host_nft) or assignment_default(HOST_FIREWALL, "BR_UDP_PORTS_RAW", host_firewall)
    nft_web_raw = assignment_default(HOST_NFT, "WEB_TCP_PORTS_RAW", host_nft) or assignment_default(HOST_FIREWALL, "WEB_TCP_PORTS_RAW", host_firewall)
    nft_tcp = parse_ports(nft_tcp_raw)
    nft_udp = parse_ports(nft_udp_raw)
    nft_web = parse_ports(nft_web_raw)
    firewall_loopback = split_csv(assignment_default(HOST_FIREWALL, "EXPECTED_LOOPBACK_TCP", host_firewall) or "127.0.0.1:18083")
    nft_loopback = split_csv(assignment_default(HOST_NFT, "EXPECTED_LOOPBACK_TCP", host_nft) or "127.0.0.1:18083")

    checks += 17
    require_equal(findings, "direct_targets", direct_targets, EXPECTED_CONCRETE_TARGETS)
    require_equal(findings, "bypass_targets", bypass_targets, EXPECTED_CONCRETE_TARGETS)
    for label, hosts in [("udp_direct_hosts", udp_direct_hosts), ("firewall_direct_hosts", firewall_direct_hosts), ("nft_direct_hosts", nft_direct_hosts)]:
        require_equal(findings, label, hosts, EXPECTED_CONCRETE_TARGETS | EXPECTED_WILDCARDS)
    require_equal(findings, "direct_ports", direct_ports, EXPECTED_ALL_TCP)
    require_equal(findings, "direct_allowed", direct_allowed, EXPECTED_WEB_TCP)
    require_equal(findings, "udp_ports", udp_ports, EXPECTED_BR_UDP)
    require_equal(findings, "udp_allowed", udp_allowed, set())
    require_equal(findings, "firewall_tcp", firewall_tcp, EXPECTED_BR_TCP)
    require_equal(findings, "firewall_udp", firewall_udp, EXPECTED_BR_UDP)
    require_equal(findings, "firewall_web", firewall_web, EXPECTED_WEB_TCP)
    require_equal(findings, "nft_tcp", nft_tcp, EXPECTED_BR_TCP)
    require_equal(findings, "nft_udp", nft_udp, EXPECTED_BR_UDP)
    require_equal(findings, "nft_web", nft_web, EXPECTED_WEB_TCP)
    require_equal(findings, "firewall_loopback", firewall_loopback, EXPECTED_LOOPBACK_TCP)
    require_equal(findings, "nft_loopback", nft_loopback, EXPECTED_LOOPBACK_TCP)

    checks += 4
    if context.get("PUBLIC_IPV4") != "31.70.74.139":
        findings.append("network_policy_public_ipv4_unexpected")
    if context.get("TAILSCALE_IPV4") != "100.102.205.121":
        findings.append("network_policy_tailscale_ipv4_unexpected")
    if context.get("PUBLIC_IPV4") and context["PUBLIC_IPV4"] not in EXPECTED_CONCRETE_TARGETS:
        findings.append("network_policy_public_ipv4_missing_from_targets")
    if context.get("TAILSCALE_IPV4") and context["TAILSCALE_IPV4"] not in EXPECTED_CONCRETE_TARGETS:
        findings.append("network_policy_tailscale_ipv4_missing_from_targets")

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "network_policy_consistency_status=%s checks=%d findings=%d concrete_targets=%d wildcard_hosts=%d tcp_ports=%d udp_ports=%d web_tcp=%d loopback_tcp=%d"
            % (status, checks, len(findings), len(EXPECTED_CONCRETE_TARGETS), len(EXPECTED_WILDCARDS), len(EXPECTED_ALL_TCP), len(EXPECTED_BR_UDP), len(EXPECTED_WEB_TCP), len(EXPECTED_LOOPBACK_TCP))
        )
    else:
        print("network_policy_consistency_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("concrete_targets=%d" % len(EXPECTED_CONCRETE_TARGETS))
        print("wildcard_hosts=%d" % len(EXPECTED_WILDCARDS))
        print("tcp_ports=%d" % len(EXPECTED_ALL_TCP))
        print("udp_ports=%d" % len(EXPECTED_BR_UDP))
        print("web_tcp=%d" % len(EXPECTED_WEB_TCP))
        print("loopback_tcp=%d" % len(EXPECTED_LOOPBACK_TCP))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
