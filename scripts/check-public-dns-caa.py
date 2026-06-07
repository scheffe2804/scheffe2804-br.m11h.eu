#!/usr/bin/env python3
"""Read-only public DNS CAA guard for BR-Wissen.

The guard queries CAA metadata for br.m11h.eu and m11h.eu via a public resolver.
It validates that CAA records, if present, do not block the current Let's Encrypt
certificate path and that no unknown critical CAA properties are visible. It
prints only counters/metadata, never changes DNS, and never reads application
secrets, dumps, logs, answers or source documents. It intentionally does not
perform DNSSEC validation; the configured resolver is therefore a trust anchor
and resolver choice must remain part of change management.
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import struct


HOST = os.getenv("BR_PUBLIC_DNS_HOST", "br.m11h.eu").rstrip(".")
ZONE = os.getenv("BR_PUBLIC_DNS_ZONE", "m11h.eu").rstrip(".")
RESOLVER = os.getenv("BR_PUBLIC_DNS_CAA_RESOLVER", "1.1.1.1")
TIMEOUT_SECONDS = float(os.getenv("BR_PUBLIC_DNS_CAA_TIMEOUT", "4"))
DNS_PORT = int(os.getenv("BR_PUBLIC_DNS_CAA_PORT", "53"))
EXPECTED_CA_DOMAINS = tuple(
    item.strip().lower().rstrip(".")
    for item in os.getenv("BR_PUBLIC_DNS_CAA_ALLOWED_CA", "letsencrypt.org").split(",")
    if item.strip()
)
KNOWN_TAGS = {"issue", "issuewild", "iodef", "accounturi", "validationmethods"}
QTYPE_CAA = 257
QCLASS_IN = 1
CRITICAL_FLAG = 0x80


def encode_name(name: str) -> bytes:
    parts = []
    for label in name.split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError("dns_label_too_long")
        parts.append(bytes([len(raw)]) + raw)
    return b"".join(parts) + b"\x00"


def skip_name(data: bytes, offset: int) -> int:
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
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def send_dns_query(qname: str) -> tuple[bytes, int, str | None]:
    query_id = random.randint(0, 65535)  # nosec B311 - DNS transaction ID only
    question = encode_name(qname) + struct.pack("!HH", QTYPE_CAA, QCLASS_IN)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    try:
        family = socket.AF_INET6 if ":" in RESOLVER else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            sock.sendto(packet, (RESOLVER, DNS_PORT))
            data, _ = sock.recvfrom(4096)
    except OSError as exc:
        return b"", query_id, "network_error_%s" % exc.__class__.__name__
    return data, query_id, None


def parse_caa_response(data: bytes, query_id: int) -> tuple[list[dict[str, str | int]], str | None]:
    if len(data) < 12:
        raise ValueError("dns_response_too_short")
    rid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    if rid != query_id:
        raise ValueError("dns_id_mismatch")
    rcode = flags & 0x000F
    if rcode != 0:
        return [], "rcode_%d" % rcode
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset) + 4
        if offset > len(data):
            raise ValueError("dns_question_out_of_bounds")

    records: list[dict[str, str | int]] = []
    for _ in range(ancount):
        offset = skip_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("dns_rr_out_of_bounds")
        rr_type, rr_class, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rr_type != QTYPE_CAA or rr_class != QCLASS_IN:
            continue
        if len(rdata) < 2:
            raise ValueError("caa_rdata_too_short")
        flags_value = rdata[0]
        tag_length = rdata[1]
        if len(rdata) < 2 + tag_length:
            raise ValueError("caa_tag_out_of_bounds")
        try:
            tag = rdata[2 : 2 + tag_length].decode("ascii", errors="strict").lower()
        except UnicodeDecodeError as exc:
            raise ValueError("caa_tag_malformed") from exc
        value = rdata[2 + tag_length :].decode("utf-8", errors="replace").strip()
        records.append({"flags": flags_value, "tag": tag, "value": value})
    return records, None


def query_caa(qname: str) -> tuple[list[dict[str, str | int]], str | None]:
    data, query_id, error = send_dns_query(qname)
    if error:
        return [], error
    try:
        return parse_caa_response(data, query_id)
    except (struct.error, ValueError) as exc:
        return [], str(exc) or "parse_error"


def ca_domain(value: str) -> str:
    return value.split(";", 1)[0].strip().lower().rstrip(".")


def allowed_ca_present(values: list[str]) -> bool:
    domains = {ca_domain(value) for value in values if ca_domain(value)}
    return any(domain in EXPECTED_CA_DOMAINS for domain in domains)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen public DNS CAA metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    qnames = []
    for qname in [HOST, ZONE]:
        if qname not in qnames:
            qnames.append(qname)

    all_records: list[dict[str, str | int]] = []
    successful_lookups = 0
    lookup_errors = 0

    for qname in qnames:
        records, error = query_caa(qname)
        checks += 1
        if error:
            lookup_errors += 1
            findings.append("caa_lookup_failed_%s" % qname.replace(".", "_"))
            continue
        successful_lookups += 1
        all_records.extend(records)

    checks += 1
    if successful_lookups != len(qnames):
        findings.append("caa_lookup_incomplete")

    caa_count = len(all_records)
    issue_values = [str(record["value"]) for record in all_records if record["tag"] == "issue"]
    issuewild_values = [str(record["value"]) for record in all_records if record["tag"] == "issuewild"]
    iodef_count = sum(1 for record in all_records if record["tag"] == "iodef")
    critical_unknown = sum(
        1
        for record in all_records
        if int(record["flags"]) & CRITICAL_FLAG and str(record["tag"]) not in KNOWN_TAGS
    )

    checks += 1
    if critical_unknown:
        findings.append("critical_unknown_caa=%d" % critical_unknown)

    unrestricted = 0
    letsencrypt_allowed = 0
    blocked_issue = 0
    checks += 1
    if not issue_values and not issuewild_values:
        unrestricted = 1
        letsencrypt_allowed = 1
    elif issuewild_values:
        if allowed_ca_present(issuewild_values):
            letsencrypt_allowed = 1
        else:
            blocked_issue = 1
            findings.append("caa_issuewild_blocks_expected_ca")
    elif issue_values:
        if allowed_ca_present(issue_values):
            letsencrypt_allowed = 1
        else:
            blocked_issue = 1
            findings.append("caa_issue_blocks_expected_ca")

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "public_dns_caa_status=%s checks=%d findings=%d host=%s zone=%s qnames=%d successful_lookups=%d lookup_errors=%d caa_records=%d issue=%d issuewild=%d iodef=%d unrestricted=%d letsencrypt_allowed=%d blocked_issue=%d critical_unknown=%d"
            % (
                status,
                checks,
                len(findings),
                HOST,
                ZONE,
                len(qnames),
                successful_lookups,
                lookup_errors,
                caa_count,
                len(issue_values),
                len(issuewild_values),
                iodef_count,
                unrestricted,
                letsencrypt_allowed,
                blocked_issue,
                critical_unknown,
            )
        )
    else:
        print("public_dns_caa_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("host=%s" % HOST)
        print("zone=%s" % ZONE)
        print("qnames=%d" % len(qnames))
        print("successful_lookups=%d" % successful_lookups)
        print("lookup_errors=%d" % lookup_errors)
        print("caa_records=%d" % caa_count)
        print("issue=%d" % len(issue_values))
        print("issuewild=%d" % len(issuewild_values))
        print("iodef=%d" % iodef_count)
        print("unrestricted=%d" % unrestricted)
        print("letsencrypt_allowed=%d" % letsencrypt_allowed)
        print("blocked_issue=%d" % blocked_issue)
        print("critical_unknown=%d" % critical_unknown)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
