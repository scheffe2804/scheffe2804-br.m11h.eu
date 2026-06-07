#!/usr/bin/env python3
"""Read-only firewall/NAT metadata guard for BR-Wissen ports.

The guard inspects local iptables/ip6tables-save metadata only. It does not alter
firewall state, does not send packets, does not read application secrets, dumps,
logs, answers or source documents, and prints only counters/findings.

Scope: unexpected direct host INPUT accepts or NAT/redirect/DNAT rules for
BR-relevant ports. Docker-internal bridge rules are counted but not treated as
direct exposure unless they publish an unexpected direct host port.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
from pathlib import Path


HOST_CONTEXT = Path(os.getenv("BR_HOST_CONTEXT", "/etc/opencode-host-context"))
BR_TCP_PORTS_RAW = [item.strip() for item in os.getenv("BR_FIREWALL_TCP_PORTS", "8000,8080,18083,5432,2019").split(",") if item.strip()]
BR_UDP_PORTS_RAW = [item.strip() for item in os.getenv("BR_FIREWALL_UDP_PORTS", "443,80,8000,8080,18083,5432,2019").split(",") if item.strip()]
WEB_TCP_PORTS_RAW = [item.strip() for item in os.getenv("BR_FIREWALL_ALLOWED_WEB_TCP_PORTS", "80,443").split(",") if item.strip()]
EXPECTED_LOOPBACK_TCP = {
    item.strip()
    for item in os.getenv("BR_FIREWALL_EXPECTED_LOOPBACK_TCP", "127.0.0.1:18083").split(",")
    if item.strip()
}
DEFAULT_DIRECT_HOSTS = "0.0.0.0,::,31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79"
DIRECT_HOSTS = {item.strip().strip("[]") for item in os.getenv("BR_FIREWALL_DIRECT_HOSTS", DEFAULT_DIRECT_HOSTS).split(",") if item.strip()}
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
SUDO = Path("/usr/bin/sudo")
XTABLES_NFT_MULTI = Path("/usr/sbin/xtables-nft-multi")


def parse_ports(values: list[str]) -> tuple[set[int], list[str]]:
    ports: set[int] = set()
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
        ports.add(port)
    return ports, invalid


BR_TCP_PORTS, INVALID_TCP_PORTS = parse_ports(BR_TCP_PORTS_RAW)
BR_UDP_PORTS, INVALID_UDP_PORTS = parse_ports(BR_UDP_PORTS_RAW)
WEB_TCP_PORTS, INVALID_WEB_TCP_PORTS = parse_ports(WEB_TCP_PORTS_RAW)


def load_context_direct_hosts() -> set[str]:
    hosts: set[str] = set()
    if not HOST_CONTEXT.exists() or HOST_CONTEXT.is_symlink():
        return hosts
    try:
        text = HOST_CONTEXT.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hosts
    for line in text.splitlines():
        if not (line.startswith("PUBLIC_IPV4=") or line.startswith("TAILSCALE_IPV4=")):
            continue
        value = line.split("=", 1)[1].strip().strip("[]")
        if value:
            hosts.add(value)
    return hosts


DIRECT_HOSTS.update(load_context_direct_hosts())


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


def save_output(label: str, subcommand: str, findings: list[str]) -> tuple[int, str]:
    if not helper_available(SUDO) or not helper_available(XTABLES_NFT_MULTI):
        findings.append("firewall_%s_helper_unavailable" % label)
        return 1, ""
    proc = run([str(SUDO), "-n", str(XTABLES_NFT_MULTI), subcommand])
    if proc.returncode != 0:
        findings.append("firewall_%s_unavailable_rc=%d" % (label, proc.returncode))
        return 1, ""
    return 1, proc.stdout


def token_value(tokens: list[str], option: str) -> str:
    if option not in tokens:
        return ""
    idx = tokens.index(option)
    if idx + 1 >= len(tokens):
        return ""
    return tokens[idx + 1]


def token_port(tokens: list[str]) -> int:
    raw = token_value(tokens, "--dport") or token_value(tokens, "--dports")
    if not raw:
        return 0
    first = raw.split(",", 1)[0].split(":", 1)[0]
    try:
        return int(first)
    except ValueError:
        return 0


def normalize_host(value: str) -> str:
    value = value.strip().strip("[]")
    if "/" in value:
        value = value.split("/", 1)[0]
    return value


def is_loopback_host(value: str) -> bool:
    return normalize_host(value) in LOOPBACK_HOSTS


def is_direct_host(value: str) -> bool:
    host = normalize_host(value)
    if host in LOOPBACK_HOSTS:
        return False
    if host in {"", "0.0.0.0", "::", "*"}:
        return True
    return host in DIRECT_HOSTS


def target_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "target"


def nat_destination_port(tokens: list[str]) -> int:
    raw = ""
    for idx, token in enumerate(tokens):
        if token in {"--to-destination", "--to-ports", "--to-port"} and idx + 1 < len(tokens):
            raw = tokens[idx + 1]
            break
    if not raw:
        return 0
    if ":" in raw:
        raw = raw.rsplit(":", 1)[1]
    if "-" in raw:
        raw = raw.split("-", 1)[0]
    try:
        return int(raw)
    except ValueError:
        return 0


def is_expected_loopback_nat(dest: str, proto: str, dport: int) -> bool:
    if proto != "tcp" or not is_loopback_host(dest):
        return False
    return "%s:%d" % (normalize_host(dest), dport) in EXPECTED_LOOPBACK_TCP


def analyze_save(label: str, text: str, findings: list[str]) -> dict[str, int]:
    counters = {
        "lines": 0,
        "input_accepts": 0,
        "unexpected_input_accepts": 0,
        "nat_rules": 0,
        "expected_loopback_nat": 0,
        "unexpected_nat_rules": 0,
        "web_accepts": 0,
        "docker_bridge_rules": 0,
    }
    table = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("*"):
            table = line[1:]
            continue
        if not line.startswith("-A "):
            continue
        counters["lines"] += 1
        try:
            tokens = shlex.split(line)
        except ValueError:
            findings.append("firewall_%s_unparseable_rule" % label)
            continue
        if len(tokens) < 3:
            continue
        chain = tokens[1]
        proto = token_value(tokens, "-p")
        dport = token_port(tokens)
        jump = token_value(tokens, "-j")
        dest = token_value(tokens, "-d")
        out_iface = token_value(tokens, "-o")

        if chain.startswith("DOCKER") or out_iface.startswith("br-") or out_iface == "docker0":
            counters["docker_bridge_rules"] += 1

        if table == "filter" and jump == "ACCEPT" and chain in {"INPUT", "ufw-user-input", "ufw6-user-input"}:
            if proto in {"tcp", "udp"} and dport:
                counters["input_accepts"] += 1
                if proto == "tcp" and dport in WEB_TCP_PORTS:
                    counters["web_accepts"] += 1
                    continue
                if (proto == "tcp" and dport in BR_TCP_PORTS) or (proto == "udp" and dport in BR_UDP_PORTS):
                    counters["unexpected_input_accepts"] += 1
                    findings.append("firewall_%s_unexpected_input_accept_%s_%d" % (label, proto, dport))

        if table == "nat" and jump in {"DNAT", "REDIRECT"}:
            if proto not in {"tcp", "udp"} or not dport:
                continue
            # Treat the published/listening host-side port as the exposure
            # boundary. Container-internal target ports such as 8080 are common
            # across projects and are not by themselves BR exposure unless the
            # host-side destination port is BR-/web-relevant too.
            relevant_dport = (proto == "tcp" and dport in (BR_TCP_PORTS | WEB_TCP_PORTS)) or (proto == "udp" and dport in BR_UDP_PORTS)
            to_port = nat_destination_port(tokens)
            relevant_to_port = (proto == "tcp" and to_port in BR_TCP_PORTS) or (proto == "udp" and to_port in BR_UDP_PORTS)
            if not relevant_dport:
                continue
            counters["nat_rules"] += 1
            if is_expected_loopback_nat(dest, proto, dport):
                counters["expected_loopback_nat"] += 1
                continue
            if proto == "tcp" and dport in WEB_TCP_PORTS and is_direct_host(dest):
                counters["web_accepts"] += 1
                continue
            if is_direct_host(dest) or relevant_to_port:
                counters["unexpected_nat_rules"] += 1
                findings.append("firewall_%s_unexpected_nat_%s_%s_%d_to_%d" % (label, proto, target_id(dest or "all"), dport, to_port))
    return counters


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen host firewall/NAT metadata for BR ports")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    for invalid_label, values in [("tcp", INVALID_TCP_PORTS), ("udp", INVALID_UDP_PORTS), ("web_tcp", INVALID_WEB_TCP_PORTS)]:
        checks += 1
        if values:
            findings.append("firewall_invalid_%s_ports=%d" % (invalid_label, len(values)))
    checks += 1
    if not DIRECT_HOSTS:
        findings.append("firewall_no_direct_hosts_configured")

    checks4, out4 = save_output("iptables_save", "iptables-save", findings)
    checks6, out6 = save_output("ip6tables_save", "ip6tables-save", findings)
    checks += checks4 + checks6
    counters4 = analyze_save("ipv4", out4, findings) if out4 else {}
    counters6 = analyze_save("ipv6", out6, findings) if out6 else {}
    checks += int(counters4.get("lines", 0)) + int(counters6.get("lines", 0))

    total_input_accepts = int(counters4.get("input_accepts", 0)) + int(counters6.get("input_accepts", 0))
    unexpected_input_accepts = int(counters4.get("unexpected_input_accepts", 0)) + int(counters6.get("unexpected_input_accepts", 0))
    nat_rules = int(counters4.get("nat_rules", 0)) + int(counters6.get("nat_rules", 0))
    expected_loopback_nat = int(counters4.get("expected_loopback_nat", 0)) + int(counters6.get("expected_loopback_nat", 0))
    unexpected_nat_rules = int(counters4.get("unexpected_nat_rules", 0)) + int(counters6.get("unexpected_nat_rules", 0))
    web_accepts = int(counters4.get("web_accepts", 0)) + int(counters6.get("web_accepts", 0))
    docker_bridge_rules = int(counters4.get("docker_bridge_rules", 0)) + int(counters6.get("docker_bridge_rules", 0))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "host_firewall_br_ports_status=%s checks=%d findings=%d direct_hosts=%d input_accepts=%d unexpected_input_accepts=%d nat_rules=%d expected_loopback_nat=%d unexpected_nat_rules=%d web_accepts=%d docker_bridge_rules=%d"
            % (
                status,
                checks,
                len(findings),
                len(DIRECT_HOSTS),
                total_input_accepts,
                unexpected_input_accepts,
                nat_rules,
                expected_loopback_nat,
                unexpected_nat_rules,
                web_accepts,
                docker_bridge_rules,
            )
        )
    else:
        print("host_firewall_br_ports_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("direct_hosts=%d" % len(DIRECT_HOSTS))
        print("input_accepts=%d" % total_input_accepts)
        print("unexpected_input_accepts=%d" % unexpected_input_accepts)
        print("nat_rules=%d" % nat_rules)
        print("expected_loopback_nat=%d" % expected_loopback_nat)
        print("unexpected_nat_rules=%d" % unexpected_nat_rules)
        print("web_accepts=%d" % web_accepts)
        print("docker_bridge_rules=%d" % docker_bridge_rules)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
