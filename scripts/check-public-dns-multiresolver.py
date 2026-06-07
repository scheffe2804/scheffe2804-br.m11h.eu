#!/usr/bin/env python3
"""Read-only multi-resolver public DNS guard for BR-Wissen.

The guard asks a small fixed set of public recursive resolvers for A/AAAA
metadata and validates that br.m11h.eu is not exposed via direct m11h origin
IPs. It prints only counters/metadata, never changes DNS, and never reads
application secrets, dumps, logs, answers or source documents. It intentionally
does not perform DNSSEC validation; resolver choice must remain part of change
management.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import random
import socket
import struct


HOST = os.getenv("BR_PUBLIC_DNS_HOST", "br.m11h.eu").rstrip(".")
RESOLVERS = [
    item.strip()
    for item in os.getenv("BR_PUBLIC_DNS_MULTI_RESOLVERS", "1.1.1.1,8.8.8.8,9.9.9.9").split(",")
    if item.strip()
]
FORBIDDEN_IPS = {
    ipaddress.ip_address(value.strip())
    for value in os.getenv("BR_PUBLIC_DNS_FORBIDDEN_IPS", "31.70.74.139,100.102.205.121").split(",")
    if value.strip()
}
REQUIRE_A = os.getenv("BR_PUBLIC_DNS_REQUIRE_A", "1") == "1"
ALLOW_AAAA = os.getenv("BR_PUBLIC_DNS_ALLOW_AAAA", "1") == "1"
MIN_SUCCESSFUL_RESOLVERS = int(os.getenv("BR_PUBLIC_DNS_MULTI_MIN_SUCCESS", "2"))
TIMEOUT_SECONDS = float(os.getenv("BR_PUBLIC_DNS_MULTI_TIMEOUT", "4"))
DNS_PORT = int(os.getenv("BR_PUBLIC_DNS_MULTI_PORT", "53"))
QTYPE_A = 1
QTYPE_AAAA = 28


def encode_name(name: str) -> bytes:
    parts = []
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("dns_label_too_long")
        parts.append(bytes([len(raw)]) + raw)
    return b"".join(parts) + b"\x00"


def skip_name(data: bytes, offset: int) -> int:
    seen = 0
    while True:
        if offset >= len(data):
            raise ValueError("dns_name_out_of_bounds")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("dns_pointer_out_of_bounds")
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length
        seen += 1
        if seen > 128:
            raise ValueError("dns_name_too_deep")


def dns_query(resolver: str, qtype: int) -> tuple[set[ipaddress._BaseAddress], str | None]:
    query_id = random.randint(0, 65535)  # nosec B311 - DNS transaction ID only
    question = encode_name(HOST) + struct.pack("!HH", qtype, 1)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    try:
        family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            sock.sendto(packet, (resolver, DNS_PORT))
            data, _ = sock.recvfrom(4096)
    except OSError as exc:
        return set(), "network_error_%s" % exc.__class__.__name__

    try:
        return parse_response(data, query_id, qtype)
    except (struct.error, ValueError) as exc:
        return set(), str(exc) or "parse_error"


def parse_response(data: bytes, query_id: int, qtype: int) -> tuple[set[ipaddress._BaseAddress], str | None]:
    if len(data) < 12:
        raise ValueError("dns_response_too_short")
    rid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    if rid != query_id:
        raise ValueError("dns_id_mismatch")
    rcode = flags & 0x000F
    if rcode != 0:
        return set(), "rcode_%d" % rcode
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset)
        offset += 4
        if offset > len(data):
            raise ValueError("dns_question_out_of_bounds")

    addresses: set[ipaddress._BaseAddress] = set()
    for _ in range(ancount):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("dns_rr_out_of_bounds")
        rr_type, rr_class, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rr_class != 1:
            continue
        if qtype == QTYPE_A and rr_type == QTYPE_A and rdlength == 4:
            addresses.add(ipaddress.ip_address(rdata))
        elif qtype == QTYPE_AAAA and rr_type == QTYPE_AAAA and rdlength == 16:
            addresses.add(ipaddress.ip_address(rdata))
    return addresses, None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen public DNS via multiple resolvers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    successful_resolvers = 0
    resolver_errors = 0
    a_total = 0
    aaaa_total = 0
    all_records: set[ipaddress._BaseAddress] = set()

    for resolver in RESOLVERS:
        resolver_records: set[ipaddress._BaseAddress] = set()
        resolver_failed = False
        a_records, a_error = dns_query(resolver, QTYPE_A)
        checks += 1
        if a_error:
            resolver_failed = True
            if REQUIRE_A:
                findings.append("resolver_%s_a_lookup_failed" % resolver.replace(":", "_"))
        checks += 1
        if REQUIRE_A and not a_records:
            findings.append("resolver_%s_missing_a_records" % resolver.replace(":", "_"))
        resolver_records |= a_records
        a_total += len(a_records)

        aaaa_records, aaaa_error = dns_query(resolver, QTYPE_AAAA)
        checks += 1
        if aaaa_error:
            resolver_failed = True
            if not ALLOW_AAAA:
                findings.append("resolver_%s_aaaa_lookup_failed" % resolver.replace(":", "_"))
        resolver_records |= aaaa_records
        aaaa_total += len(aaaa_records)

        if resolver_failed:
            resolver_errors += 1
        else:
            successful_resolvers += 1
        all_records |= resolver_records

    checks += 1
    if successful_resolvers < MIN_SUCCESSFUL_RESOLVERS:
        findings.append("insufficient_successful_resolvers=%d" % successful_resolvers)

    checks += 1
    if not all_records:
        findings.append("no_public_dns_records")

    forbidden_hits = sorted(all_records & FORBIDDEN_IPS, key=lambda value: (value.version, str(value)))
    checks += 1
    if forbidden_hits:
        findings.append("forbidden_origin_records=%d" % len(forbidden_hits))

    global_records = [addr for addr in all_records if addr.is_global]
    checks += 1
    if not global_records:
        findings.append("no_global_public_records")

    non_public_records = [addr for addr in all_records if addr.is_private or addr.is_loopback or addr.is_link_local]
    checks += 1
    if non_public_records:
        findings.append("non_public_records=%d" % len(non_public_records))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "public_dns_multiresolver_status=%s checks=%d findings=%d host=%s resolvers=%d successful_resolvers=%d resolver_errors=%d a_records=%d aaaa_records=%d unique_records=%d forbidden_hits=%d global_records=%d non_public_records=%d"
            % (
                status,
                checks,
                len(findings),
                HOST,
                len(RESOLVERS),
                successful_resolvers,
                resolver_errors,
                a_total,
                aaaa_total,
                len(all_records),
                len(forbidden_hits),
                len(global_records),
                len(non_public_records),
            )
        )
    else:
        print("public_dns_multiresolver_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("host=%s" % HOST)
        print("resolvers=%d" % len(RESOLVERS))
        print("successful_resolvers=%d" % successful_resolvers)
        print("resolver_errors=%d" % resolver_errors)
        print("a_records=%d" % a_total)
        print("aaaa_records=%d" % aaaa_total)
        print("unique_records=%d" % len(all_records))
        print("forbidden_hits=%d" % len(forbidden_hits))
        print("global_records=%d" % len(global_records))
        print("non_public_records=%d" % len(non_public_records))
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
