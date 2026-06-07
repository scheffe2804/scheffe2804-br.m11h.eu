#!/usr/bin/env python3
"""Read-only authoritative public DNS guard for BR-Wissen.

The guard discovers the zone's NS records via a recursive resolver, resolves the
nameserver addresses, then asks authoritative nameservers directly for A/AAAA
metadata of br.m11h.eu. It prints only counters/metadata, never changes DNS, and
never reads application secrets, dumps, logs, answers or source documents. It
intentionally does not perform DNSSEC validation; nameserver/resolver choices must
remain part of change management.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import random
import socket
import struct


HOST = os.getenv("BR_PUBLIC_DNS_HOST", "br.m11h.eu").rstrip(".")
ZONE = os.getenv("BR_PUBLIC_DNS_ZONE", "m11h.eu").rstrip(".")
BOOTSTRAP_RESOLVER = os.getenv("BR_PUBLIC_DNS_AUTH_BOOTSTRAP_RESOLVER", "1.1.1.1")
FORBIDDEN_IPS = {
    ipaddress.ip_address(value.strip())
    for value in os.getenv("BR_PUBLIC_DNS_FORBIDDEN_IPS", "31.70.74.139,100.102.205.121").split(",")
    if value.strip()
}
REQUIRE_A = os.getenv("BR_PUBLIC_DNS_REQUIRE_A", "1") == "1"
ALLOW_AAAA = os.getenv("BR_PUBLIC_DNS_ALLOW_AAAA", "1") == "1"
MIN_SUCCESSFUL_AUTHORITIES = int(os.getenv("BR_PUBLIC_DNS_AUTH_MIN_SUCCESS", "1"))
TIMEOUT_SECONDS = float(os.getenv("BR_PUBLIC_DNS_AUTH_TIMEOUT", "4"))
DNS_PORT = int(os.getenv("BR_PUBLIC_DNS_AUTH_PORT", "53"))
QTYPE_A = 1
QTYPE_NS = 2
QTYPE_AAAA = 28
QCLASS_IN = 1


def encode_name(name: str) -> bytes:
    parts = []
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("dns_label_too_long")
        parts.append(bytes([len(raw)]) + raw)
    return b"".join(parts) + b"\x00"


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    original_offset = offset
    seen_offsets: set[int] = set()
    while True:
        if offset >= len(data):
            raise ValueError("dns_name_out_of_bounds")
        if offset in seen_offsets:
            raise ValueError("dns_pointer_loop")
        seen_offsets.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("dns_pointer_out_of_bounds")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            return ".".join(labels), (original_offset if jumped else offset + 1)
        offset += 1
        if offset + length > len(data):
            raise ValueError("dns_label_out_of_bounds")
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length


def skip_name(data: bytes, offset: int) -> int:
    return decode_name(data, offset)[1]


def send_dns_query(server: str, qname: str, qtype: int, recursion_desired: bool) -> tuple[bytes, int, str | None]:
    query_id = random.randint(0, 65535)  # nosec B311 - DNS transaction ID only
    question = encode_name(qname) + struct.pack("!HH", qtype, QCLASS_IN)
    flags = 0x0100 if recursion_desired else 0x0000
    packet = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0) + question
    try:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            sock.sendto(packet, (server, DNS_PORT))
            data, _ = sock.recvfrom(4096)
    except OSError as exc:
        return b"", query_id, "network_error_%s" % exc.__class__.__name__
    return data, query_id, None


def parse_records(data: bytes, query_id: int, expected_qtype: int) -> tuple[set[ipaddress._BaseAddress], set[str], bool, str | None]:
    if len(data) < 12:
        raise ValueError("dns_response_too_short")
    rid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    if rid != query_id:
        raise ValueError("dns_id_mismatch")
    authoritative = bool(flags & 0x0400)
    rcode = flags & 0x000F
    if rcode != 0:
        return set(), set(), authoritative, "rcode_%d" % rcode
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset) + 4
        if offset > len(data):
            raise ValueError("dns_question_out_of_bounds")

    addresses: set[ipaddress._BaseAddress] = set()
    nameservers: set[str] = set()
    for _ in range(ancount):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("dns_rr_out_of_bounds")
        rr_type, rr_class, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rr_class != QCLASS_IN:
            continue
        if expected_qtype == QTYPE_A and rr_type == QTYPE_A and rdlength == 4:
            addresses.add(ipaddress.ip_address(rdata))
        elif expected_qtype == QTYPE_AAAA and rr_type == QTYPE_AAAA and rdlength == 16:
            addresses.add(ipaddress.ip_address(rdata))
        elif expected_qtype == QTYPE_NS and rr_type == QTYPE_NS:
            ns_name, _ = decode_name(data, rdata_offset)
            if ns_name:
                nameservers.add(ns_name.rstrip(".").lower())
    return addresses, nameservers, authoritative, None


def dns_query(server: str, qname: str, qtype: int, recursion_desired: bool) -> tuple[set[ipaddress._BaseAddress], set[str], bool, str | None]:
    data, query_id, error = send_dns_query(server, qname, qtype, recursion_desired)
    if error:
        return set(), set(), False, error
    try:
        return parse_records(data, query_id, qtype)
    except (struct.error, ValueError) as exc:
        return set(), set(), False, str(exc) or "parse_error"


def resolve_nameserver_addresses(nameservers: set[str]) -> set[str]:
    addresses: set[str] = set()
    for ns_name in nameservers:
        try:
            infos = socket.getaddrinfo(ns_name, DNS_PORT, 0, socket.SOCK_DGRAM)
        except socket.gaierror:
            continue
        for info in infos:
            address = info[4][0]
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            addresses.add(address)
    return addresses


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen public DNS via authoritative nameservers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    all_records: set[ipaddress._BaseAddress] = set()
    a_total = 0
    aaaa_total = 0
    authoritative_responses = 0
    successful_authorities = 0
    authority_errors = 0

    _ns_addresses, nameservers, _authoritative, ns_error = dns_query(BOOTSTRAP_RESOLVER, ZONE, QTYPE_NS, True)
    checks += 1
    if ns_error:
        findings.append("ns_lookup_failed")
    checks += 1
    if not nameservers:
        findings.append("missing_nameservers")

    authority_addresses = resolve_nameserver_addresses(nameservers)
    checks += 1
    if not authority_addresses:
        findings.append("missing_nameserver_addresses")

    for server in sorted(authority_addresses):
        server_failed = False
        a_records, _a_ns, a_authoritative, a_error = dns_query(server, HOST, QTYPE_A, False)
        checks += 1
        if a_authoritative:
            authoritative_responses += 1
        if a_error:
            server_failed = True
            if REQUIRE_A:
                findings.append("authority_a_lookup_failed")
        elif not a_authoritative:
            server_failed = True
            findings.append("authority_a_not_authoritative")
        checks += 1
        if REQUIRE_A and not a_records:
            findings.append("authority_missing_a_records")
        a_total += len(a_records)
        all_records |= a_records

        aaaa_records, _aaaa_ns, aaaa_authoritative, aaaa_error = dns_query(server, HOST, QTYPE_AAAA, False)
        checks += 1
        if aaaa_authoritative:
            authoritative_responses += 1
        if aaaa_error:
            server_failed = True
            if not ALLOW_AAAA:
                findings.append("authority_aaaa_lookup_failed")
        elif not aaaa_authoritative:
            server_failed = True
            findings.append("authority_aaaa_not_authoritative")
        elif not ALLOW_AAAA and aaaa_records:
            findings.append("authority_unexpected_aaaa_records")
        aaaa_total += len(aaaa_records)
        all_records |= aaaa_records

        if server_failed:
            authority_errors += 1
        else:
            successful_authorities += 1

    checks += 1
    if successful_authorities < MIN_SUCCESSFUL_AUTHORITIES:
        findings.append("insufficient_successful_authorities=%d" % successful_authorities)

    checks += 1
    if authoritative_responses < MIN_SUCCESSFUL_AUTHORITIES:
        findings.append("insufficient_authoritative_responses=%d" % authoritative_responses)

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
            "public_dns_authoritative_status=%s checks=%d findings=%d host=%s zone=%s nameservers=%d authority_addresses=%d successful_authorities=%d authority_errors=%d authoritative_responses=%d a_records=%d aaaa_records=%d unique_records=%d forbidden_hits=%d global_records=%d non_public_records=%d"
            % (
                status,
                checks,
                len(findings),
                HOST,
                ZONE,
                len(nameservers),
                len(authority_addresses),
                successful_authorities,
                authority_errors,
                authoritative_responses,
                a_total,
                aaaa_total,
                len(all_records),
                len(forbidden_hits),
                len(global_records),
                len(non_public_records),
            )
        )
    else:
        print("public_dns_authoritative_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("host=%s" % HOST)
        print("zone=%s" % ZONE)
        print("nameservers=%d" % len(nameservers))
        print("authority_addresses=%d" % len(authority_addresses))
        print("successful_authorities=%d" % successful_authorities)
        print("authority_errors=%d" % authority_errors)
        print("authoritative_responses=%d" % authoritative_responses)
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
