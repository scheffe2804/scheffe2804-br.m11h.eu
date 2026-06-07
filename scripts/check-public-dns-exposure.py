#!/usr/bin/env python3
"""Read-only public DNS exposure guard for BR-Wissen.

The guard resolves the public BR-Wissen hostname and validates that it is not
directly exposed via the m11h origin IPs. It only prints counters and metadata,
never changes DNS, and never reads application secrets, dumps, logs, answers or
source documents.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket


HOST = os.getenv("BR_PUBLIC_DNS_HOST", "br.m11h.eu")
PORT = int(os.getenv("BR_PUBLIC_DNS_PORT", "443"))
FORBIDDEN_IPS = {
    ipaddress.ip_address(value.strip())
    for value in os.getenv("BR_PUBLIC_DNS_FORBIDDEN_IPS", "31.70.74.139,100.102.205.121").split(",")
    if value.strip()
}
REQUIRE_A = os.getenv("BR_PUBLIC_DNS_REQUIRE_A", "1") == "1"
ALLOW_AAAA = os.getenv("BR_PUBLIC_DNS_ALLOW_AAAA", "1") == "1"


def resolve_family(family: socket.AddressFamily) -> tuple[set[ipaddress._BaseAddress], str | None]:
    try:
        infos = socket.getaddrinfo(HOST, PORT, family, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return set(), "gaierror_%s" % exc.errno
    addresses: set[ipaddress._BaseAddress] = set()
    for item in infos:
        try:
            addresses.add(ipaddress.ip_address(item[4][0]))
        except ValueError:
            continue
    return addresses, None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen public DNS exposure metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    a_records, a_error = resolve_family(socket.AF_INET)
    aaaa_records, aaaa_error = resolve_family(socket.AF_INET6)

    checks += 1
    if a_error and REQUIRE_A:
        findings.append("a_lookup_failed=%s" % a_error)
    checks += 1
    if REQUIRE_A and not a_records:
        findings.append("missing_a_records")

    checks += 1
    if aaaa_error and not ALLOW_AAAA:
        findings.append("aaaa_lookup_failed=%s" % aaaa_error)

    all_records = a_records | aaaa_records
    checks += 1
    if not all_records:
        findings.append("no_public_dns_records")

    forbidden_hits = sorted(all_records & FORBIDDEN_IPS, key=lambda value: (value.version, str(value)))
    checks += 1
    if forbidden_hits:
        findings.append("forbidden_origin_records=%d" % len(forbidden_hits))

    public_records = [addr for addr in all_records if addr.is_global]
    checks += 1
    if not public_records:
        findings.append("no_global_public_records")

    private_records = [addr for addr in all_records if addr.is_private or addr.is_loopback or addr.is_link_local]
    checks += 1
    if private_records:
        findings.append("non_public_records=%d" % len(private_records))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "public_dns_exposure_status=%s checks=%d findings=%d host=%s a_records=%d aaaa_records=%d forbidden_hits=%d global_records=%d non_public_records=%d"
            % (
                status,
                checks,
                len(findings),
                HOST,
                len(a_records),
                len(aaaa_records),
                len(forbidden_hits),
                len(public_records),
                len(private_records),
            )
        )
    else:
        print("public_dns_exposure_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("host=%s" % HOST)
        print("a_records=%d" % len(a_records))
        print("aaaa_records=%d" % len(aaaa_records))
        print("forbidden_hits=%d" % len(forbidden_hits))
        print("global_records=%d" % len(public_records))
        print("non_public_records=%d" % len(private_records))
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
