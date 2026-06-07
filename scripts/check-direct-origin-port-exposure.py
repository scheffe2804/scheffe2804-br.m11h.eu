#!/usr/bin/env python3
"""Read-only direct-origin TCP port exposure guard for BR-Wissen.

The guard performs metadata-only TCP connect probes against a curated BR-relevant
port set on known origin/Tailscale IPs. It sends no application data, reads no
response bodies, changes no firewall/DNS/proxy configuration and never reads
application secrets, dumps, logs, answers or source documents.

This is deliberately not a full host port scan. It complements the
Direct-Origin-Bypass-Guard: web ports 80/443 may be open, but content/access
semantics for those ports are validated separately by check-direct-origin-bypass.py.
Unexpected exposure of BR app/proxy/database/admin ports is fail-fast.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket


DEFAULT_TARGETS = "31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79"
DEFAULT_PORTS = "80,443,8000,8080,18083,5432,2019"
DEFAULT_ALLOWED_OPEN_PORTS = "80,443"

TARGETS = [item.strip() for item in os.getenv("BR_DIRECT_ORIGIN_PORT_TARGETS", DEFAULT_TARGETS).split(",") if item.strip()]
PORTS_RAW = [item.strip() for item in os.getenv("BR_DIRECT_ORIGIN_PORTS", DEFAULT_PORTS).split(",") if item.strip()]
ALLOWED_OPEN_PORTS_RAW = [
    item.strip() for item in os.getenv("BR_DIRECT_ORIGIN_ALLOWED_OPEN_PORTS", DEFAULT_ALLOWED_OPEN_PORTS).split(",") if item.strip()
]
TIMEOUT_SECONDS = float(os.getenv("BR_DIRECT_ORIGIN_PORT_TIMEOUT", "2"))


def parse_ports(values: list[str]) -> tuple[list[int], list[str]]:
    ports: list[int] = []
    invalid: list[str] = []
    for value in values:
        try:
            port = int(value)
        except ValueError:
            invalid.append(value[:32] or "empty")
            continue
        if not 1 <= port <= 65535:
            invalid.append(value[:32] or "empty")
            continue
        if port not in ports:
            ports.append(port)
    return ports, invalid


PORTS, INVALID_PORTS = parse_ports(PORTS_RAW)
ALLOWED_OPEN_PORTS, INVALID_ALLOWED_PORTS = parse_ports(ALLOWED_OPEN_PORTS_RAW)


def target_family(target: str) -> str:
    try:
        parsed = ipaddress.ip_address(target)
    except ValueError:
        return "name"
    return "ipv6" if parsed.version == 6 else "ipv4"


def target_id(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_") or "target"


def probe_port(target: str, port: int) -> bool:
    try:
        conn = socket.create_connection((target, port), timeout=TIMEOUT_SECONDS)
    except OSError:
        return False
    try:
        conn.close()
    except OSError:
        pass
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen direct origin TCP port exposure metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    open_ports: list[tuple[str, int]] = []
    allowed_open = 0
    unexpected_open = 0
    closed_or_filtered = 0

    ipv4_targets = sum(1 for target in TARGETS if target_family(target) == "ipv4")
    ipv6_targets = sum(1 for target in TARGETS if target_family(target) == "ipv6")
    named_targets = sum(1 for target in TARGETS if target_family(target) == "name")

    checks += 1
    if not TARGETS:
        findings.append("direct_origin_port_no_targets_configured")
    checks += 1
    if named_targets:
        findings.append("direct_origin_port_named_targets_unsupported=%d" % named_targets)
    checks += 1
    if not PORTS:
        findings.append("direct_origin_port_no_ports_configured")
    checks += 1
    if INVALID_PORTS:
        findings.append("direct_origin_port_invalid_ports=%d" % len(INVALID_PORTS))
    checks += 1
    if INVALID_ALLOWED_PORTS:
        findings.append("direct_origin_port_invalid_allowed_ports=%d" % len(INVALID_ALLOWED_PORTS))
    checks += 1
    for port in ALLOWED_OPEN_PORTS:
        if port not in PORTS:
            findings.append("direct_origin_port_allowed_not_probed=%d" % port)

    probes = 0
    if not findings:
        for target in TARGETS:
            for port in PORTS:
                probes += 1
                checks += 1
                is_open = probe_port(target, port)
                if not is_open:
                    closed_or_filtered += 1
                    continue
                open_ports.append((target, port))
                if port in ALLOWED_OPEN_PORTS:
                    allowed_open += 1
                else:
                    unexpected_open += 1
                    findings.append("direct_origin_port_unexpected_open_%s_%d" % (target_id(target), port))

    checks += 1
    if unexpected_open:
        findings.append("direct_origin_port_unexpected_open_count=%d" % unexpected_open)

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "direct_origin_port_exposure_status=%s checks=%d findings=%d targets=%d ipv4_targets=%d ipv6_targets=%d named_targets=%d ports=%d probes=%d open_total=%d allowed_open=%d unexpected_open=%d closed_or_filtered=%d allowed_ports=%s"
            % (
                status,
                checks,
                len(findings),
                len(TARGETS),
                ipv4_targets,
                ipv6_targets,
                named_targets,
                len(PORTS),
                probes,
                len(open_ports),
                allowed_open,
                unexpected_open,
                closed_or_filtered,
                ":".join(str(port) for port in ALLOWED_OPEN_PORTS) or "none",
            )
        )
    else:
        print("direct_origin_port_exposure_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("targets=%d" % len(TARGETS))
        print("ipv4_targets=%d" % ipv4_targets)
        print("ipv6_targets=%d" % ipv6_targets)
        print("named_targets=%d" % named_targets)
        print("ports=%d" % len(PORTS))
        print("probes=%d" % probes)
        print("open_total=%d" % len(open_ports))
        print("allowed_open=%d" % allowed_open)
        print("unexpected_open=%d" % unexpected_open)
        print("closed_or_filtered=%d" % closed_or_filtered)
        print("allowed_ports=%s" % (":".join(str(port) for port in ALLOWED_OPEN_PORTS) or "none"))
        for target, port in open_ports:
            classification = "allowed" if port in ALLOWED_OPEN_PORTS else "unexpected"
            print("open_port=%s:%d classification=%s" % (target_id(target), port, classification))
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
