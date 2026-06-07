#!/usr/bin/env python3
"""Read-only host UDP/QUIC exposure guard for BR-Wissen.

The guard checks local host and Docker/Compose UDP exposure metadata only. It does
not send UDP packets, does not scan remote systems, does not read response bodies
and never reads application secrets, dumps, logs, answers or source documents.

Scope: curated BR-relevant UDP ports on public/all/tailscale bind addresses,
especially UDP/443 (QUIC). Loopback-only UDP listeners are not considered direct
origin exposure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
HOST_CONTEXT = Path(os.getenv("BR_HOST_CONTEXT", "/etc/opencode-host-context"))
DEFAULT_PORTS = "443,80,8000,8080,18083,5432,2019"
DEFAULT_ALLOWED_OPEN_PORTS = ""
DEFAULT_DIRECT_HOSTS = "0.0.0.0,::,31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
PORTS_RAW = [item.strip() for item in os.getenv("BR_HOST_UDP_PORTS", DEFAULT_PORTS).split(",") if item.strip()]
ALLOWED_RAW = [item.strip() for item in os.getenv("BR_HOST_UDP_ALLOWED_OPEN_PORTS", DEFAULT_ALLOWED_OPEN_PORTS).split(",") if item.strip()]
DIRECT_HOSTS = {item.strip().strip("[]") for item in os.getenv("BR_HOST_UDP_DIRECT_HOSTS", DEFAULT_DIRECT_HOSTS).split(",") if item.strip()}
DOCKER = Path("/usr/bin/docker")
SS = Path("/usr/bin/ss")


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
    return subprocess.run(args, cwd=str(ROOT), text=True, capture_output=True, check=False)


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


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
ALLOWED_OPEN_PORTS, INVALID_ALLOWED_PORTS = parse_ports(ALLOWED_RAW)


def split_listener(local: str) -> tuple[str, int]:
    local = local.strip()
    if local.startswith("[") and "]:" in local:
        host, raw_port = local.rsplit(":", 1)
        host = host.strip("[]")
    elif local.count(":") > 1:
        host, raw_port = local.rsplit(":", 1)
    elif ":" in local:
        host, raw_port = local.rsplit(":", 1)
    else:
        return local, 0
    if "%" in host:
        host = host.split("%", 1)[0]
    try:
        port = int(raw_port)
    except ValueError:
        port = 0
    return host, port


def host_is_direct_exposure(host: str) -> bool:
    cleaned = host.strip().strip("[]")
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    if cleaned in LOOPBACK_HOSTS:
        return False
    if cleaned in {"*", "0.0.0.0", "::", "[::]"}:
        return True
    return cleaned in DIRECT_HOSTS


def collect_udp_listeners(findings: list[str]) -> tuple[int, list[tuple[str, int]], int, int]:
    checks = 1
    relevant: list[tuple[str, int]] = []
    loopback_relevant = 0
    direct_relevant = 0
    if not helper_available(SS):
        findings.append("host_udp_ss_helper_unavailable")
        return checks, relevant, loopback_relevant, direct_relevant
    proc = run([str(SS), "-H", "-lun"])
    if proc.returncode != 0:
        findings.append("host_udp_ss_unavailable_rc=%d" % proc.returncode)
        return checks, relevant, loopback_relevant, direct_relevant
    for raw_line in proc.stdout.splitlines():
        parts = raw_line.split()
        if len(parts) < 4:
            continue
        host, port = split_listener(parts[3])
        if port not in PORTS:
            continue
        checks += 1
        relevant.append((host, port))
        if host.strip().strip("[]") in LOOPBACK_HOSTS:
            loopback_relevant += 1
            continue
        if host_is_direct_exposure(host):
            direct_relevant += 1
            if port not in ALLOWED_OPEN_PORTS:
                findings.append("host_udp_unexpected_direct_listener_%s_%d" % (target_id(host), port))
    return checks, relevant, loopback_relevant, direct_relevant


def compose_ps(findings: list[str]) -> tuple[int, list[dict[str, Any]]]:
    checks = 1
    if not helper_available(DOCKER):
        findings.append("host_udp_docker_helper_unavailable")
        return checks, []
    proc = run([str(DOCKER), "compose", "ps", "--format", "json"])
    if proc.returncode != 0:
        findings.append("host_udp_compose_ps_unavailable_rc=%d" % proc.returncode)
        return checks, []
    rows: list[dict[str, Any]] = []
    stdout = proc.stdout.strip()
    if not stdout:
        return checks, rows
    if stdout.startswith("["):
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            findings.append("host_udp_compose_ps_json_invalid")
            return checks, []
        if isinstance(data, list):
            rows = [item for item in data if isinstance(item, dict)]
        return checks, rows
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            findings.append("host_udp_compose_ps_json_invalid")
            return checks, []
        if isinstance(item, dict):
            rows.append(item)
    return checks, rows


def publisher_int(pub: dict[str, Any], key1: str, key2: str) -> int:
    try:
        return int(pub.get(key1) or pub.get(key2) or 0)
    except (TypeError, ValueError):
        return 0


def collect_compose_udp(rows: list[dict[str, Any]], findings: list[str]) -> tuple[int, int, int, int]:
    checks = 0
    udp_publishers = 0
    host_udp_published = 0
    unexpected_host_udp = 0
    for row in rows:
        service = str(row.get("Service") or row.get("service") or "unknown")
        publishers = row.get("Publishers") or row.get("publishers") or []
        if not isinstance(publishers, list):
            continue
        for pub in publishers:
            if not isinstance(pub, dict):
                continue
            protocol = str(pub.get("Protocol") or pub.get("protocol") or "tcp").lower()
            if protocol != "udp":
                continue
            udp_publishers += 1
            checks += 1
            target_port = publisher_int(pub, "TargetPort", "targetPort")
            published_port = publisher_int(pub, "PublishedPort", "publishedPort")
            url = str(pub.get("URL") or pub.get("url") or "").strip().strip("[]")
            if published_port <= 0:
                continue
            host_udp_published += 1
            direct = (not url) or host_is_direct_exposure(url)
            if direct and published_port in PORTS and published_port not in ALLOWED_OPEN_PORTS:
                unexpected_host_udp += 1
                findings.append("compose_udp_unexpected_publish_%s_%s_%d_to_%d" % (service, target_id(url or "all"), published_port, target_port))
    return checks, udp_publishers, host_udp_published, unexpected_host_udp


def target_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "target"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen host UDP/QUIC exposure metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    checks += 1
    if not PORTS:
        findings.append("host_udp_no_ports_configured")
    checks += 1
    if INVALID_PORTS:
        findings.append("host_udp_invalid_ports=%d" % len(INVALID_PORTS))
    checks += 1
    if INVALID_ALLOWED_PORTS:
        findings.append("host_udp_invalid_allowed_ports=%d" % len(INVALID_ALLOWED_PORTS))
    checks += 1
    for port in ALLOWED_OPEN_PORTS:
        if port not in PORTS:
            findings.append("host_udp_allowed_not_checked=%d" % port)
    checks += 1
    if not DIRECT_HOSTS:
        findings.append("host_udp_no_direct_hosts_configured")

    relevant_listeners: list[tuple[str, int]] = []
    loopback_relevant = 0
    direct_relevant = 0
    udp_publishers = 0
    host_udp_published = 0
    unexpected_host_udp = 0
    if not findings:
        listener_checks, relevant_listeners, loopback_relevant, direct_relevant = collect_udp_listeners(findings)
        checks += listener_checks
        compose_checks, rows = compose_ps(findings)
        checks += compose_checks
        publisher_checks, udp_publishers, host_udp_published, unexpected_host_udp = collect_compose_udp(rows, findings)
        checks += publisher_checks

    status = "ok" if not findings else "failed"
    allowed_ports_value = ":".join(str(port) for port in ALLOWED_OPEN_PORTS) or "none"
    if args.summary:
        print(
            "host_udp_exposure_status=%s checks=%d findings=%d ports=%d direct_hosts=%d relevant_listeners=%d direct_relevant_listeners=%d loopback_relevant_listeners=%d udp_publishers=%d host_udp_published=%d unexpected_host_udp=%d allowed_udp_ports=%s"
            % (
                status,
                checks,
                len(findings),
                len(PORTS),
                len(DIRECT_HOSTS),
                len(relevant_listeners),
                direct_relevant,
                loopback_relevant,
                udp_publishers,
                host_udp_published,
                unexpected_host_udp,
                allowed_ports_value,
            )
        )
    else:
        print("host_udp_exposure_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("ports=%d" % len(PORTS))
        print("direct_hosts=%d" % len(DIRECT_HOSTS))
        print("relevant_listeners=%d" % len(relevant_listeners))
        print("direct_relevant_listeners=%d" % direct_relevant)
        print("loopback_relevant_listeners=%d" % loopback_relevant)
        print("udp_publishers=%d" % udp_publishers)
        print("host_udp_published=%d" % host_udp_published)
        print("unexpected_host_udp=%d" % unexpected_host_udp)
        print("allowed_udp_ports=%s" % allowed_ports_value)
        for host, port in relevant_listeners:
            scope = "loopback" if host.strip().strip("[]") in LOOPBACK_HOSTS else ("direct" if host_is_direct_exposure(host) else "other")
            classification = "allowed" if port in ALLOWED_OPEN_PORTS else ("ignored_loopback" if scope == "loopback" else "unexpected")
            print("udp_listener=%s:%d scope=%s classification=%s" % (target_id(host), port, scope, classification))
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
