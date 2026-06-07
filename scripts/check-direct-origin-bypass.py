#!/usr/bin/env python3
"""Read-only direct-origin bypass guard for BR-Wissen.

The guard probes known origin/Tailscale IPs with Host: br.m11h.eu on HTTP/HTTPS
using HEAD requests and validates that protected content is not reachable without
Cloudflare Access. HTTPS probes require normal certificate validation for
br.m11h.eu; a valid direct-origin HTTPS response is treated as bypass risk. The
guard reads no response bodies, sends no credentials, changes no firewall/DNS/proxy
configuration and never reads application secrets, dumps, logs, answers or source
documents.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import ssl
from urllib.parse import quote


HOST_HEADER = os.getenv("BR_DIRECT_ORIGIN_HOST", "br.m11h.eu")
DEFAULT_TARGETS = "31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79"
DEFAULT_PATHS = "/,/healthz,/login,/queries,/sources,/answers,/search,/validation"
TARGETS = [
    item.strip()
    for item in os.getenv("BR_DIRECT_ORIGIN_TARGETS", DEFAULT_TARGETS).split(",")
    if item.strip()
]
PATHS = [item.strip() or "/" for item in os.getenv("BR_DIRECT_ORIGIN_PATHS", DEFAULT_PATHS).split(",")]
TIMEOUT_SECONDS = float(os.getenv("BR_DIRECT_ORIGIN_TIMEOUT", "5"))
HTTP_PORT = int(os.getenv("BR_DIRECT_ORIGIN_HTTP_PORT", "80"))
HTTPS_PORT = int(os.getenv("BR_DIRECT_ORIGIN_HTTPS_PORT", "443"))
MAX_HEADER_BYTES = 8192


def has_header_injection(value: str) -> bool:
    return "\r" in value or "\n" in value


def request_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return quote(path, safe="/:?&=%-._~")


def read_headers(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < MAX_HEADER_BYTES:
        chunk = sock.recv(min(1024, MAX_HEADER_BYTES - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if b"\r\n\r\n" in b"".join(chunks):
            break
    return b"".join(chunks)


def probe(target: str, port: int, tls: bool, path: str) -> tuple[str, int, dict[str, str]]:
    try:
        raw = socket.create_connection((target, port), timeout=TIMEOUT_SECONDS)
    except OSError:
        return "connection_blocked", 0, {}
    try:
        conn: socket.socket
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            conn = context.wrap_socket(raw, server_hostname=HOST_HEADER)
        else:
            conn = raw
        request = (
            "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: br-wissen-direct-origin-bypass-guard\r\nConnection: close\r\n\r\n"
            % (request_path(path), HOST_HEADER)
        ).encode("ascii", errors="replace")
        conn.settimeout(TIMEOUT_SECONDS)
        conn.sendall(request)
        data = read_headers(conn)
        conn.close()
    except (OSError, ssl.SSLError):
        try:
            raw.close()
        except OSError:
            pass
        return "transport_blocked", 0, {}

    text = data.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return "http_response", status, headers


def target_family(target: str) -> str:
    try:
        parsed = ipaddress.ip_address(target)
    except ValueError:
        return "name"
    return "ipv6" if parsed.version == 6 else "ipv4"


def finding_target_id(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_") or "target"


def allowed_response(status: int, headers: dict[str, str]) -> bool:
    if status == 401 and "basic" in headers.get("www-authenticate", "").lower():
        return True
    if 300 <= status <= 399:
        location = headers.get("location", "").lower()
        return location.startswith("https://%s/" % HOST_HEADER.lower()) or location == "https://%s" % HOST_HEADER.lower()
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen direct origin bypass metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    probes = 0
    blocked = 0
    tls_blocked = 0
    redirects = 0
    basic_auth = 0
    unsafe_http = 0
    valid_https = 0
    ipv4_targets = sum(1 for target in TARGETS if target_family(target) == "ipv4")
    ipv6_targets = sum(1 for target in TARGETS if target_family(target) == "ipv6")
    named_targets = sum(1 for target in TARGETS if target_family(target) == "name")

    checks += 1
    if has_header_injection(HOST_HEADER):
        findings.append("direct_origin_host_header_invalid")

    checks += 1
    if not TARGETS:
        findings.append("direct_origin_no_targets_configured")

    checks += 1
    if named_targets:
        findings.append("direct_origin_named_targets_unsupported=%d" % named_targets)

    checks += 1
    if not PATHS:
        findings.append("direct_origin_no_paths_configured")

    for path in PATHS:
        checks += 1
        if has_header_injection(path):
            findings.append("direct_origin_path_header_invalid")
        elif not path.startswith("/"):
            findings.append("direct_origin_path_not_absolute=%s" % (path[:32] or "empty"))

    if not findings:
        for target in TARGETS:
            for path in PATHS:
                for scheme, port, tls in [("http", HTTP_PORT, False), ("https", HTTPS_PORT, True)]:
                    probes += 1
                    checks += 1
                    kind, status, headers = probe(target, port, tls, path)
                    if kind in {"connection_blocked", "transport_blocked"}:
                        blocked += 1
                        if tls:
                            tls_blocked += 1
                        continue
                    if tls:
                        valid_https += 1
                        unsafe_http += 1
                        findings.append("direct_origin_%s_%s_%s_valid_tls_status=%s" % (finding_target_id(target), scheme, path.strip("/") or "root", status))
                        continue
                    checks += 1
                    if status == 401 and "basic" in headers.get("www-authenticate", "").lower():
                        basic_auth += 1
                        continue
                    if 300 <= status <= 399 and allowed_response(status, headers):
                        redirects += 1
                        continue
                    unsafe_http += 1
                    findings.append("direct_origin_%s_%s_%s_status=%s" % (finding_target_id(target), scheme, path.strip("/") or "root", status))

    checks += 1
    if unsafe_http:
        findings.append("direct_origin_unsafe_responses=%d" % unsafe_http)

    status_text = "ok" if not findings else "failed"
    if args.summary:
        print(
            "direct_origin_bypass_status=%s checks=%d findings=%d targets=%d ipv4_targets=%d ipv6_targets=%d named_targets=%d paths=%d probes=%d blocked=%d tls_blocked=%d redirects=%d basic_auth=%d valid_https=%d bypass_findings=%d unsafe_http=%d"
            % (status_text, checks, len(findings), len(TARGETS), ipv4_targets, ipv6_targets, named_targets, len(PATHS), probes, blocked, tls_blocked, redirects, basic_auth, valid_https, unsafe_http, unsafe_http)
        )
    else:
        print("direct_origin_bypass_status=%s" % status_text)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("targets=%d" % len(TARGETS))
        print("ipv4_targets=%d" % ipv4_targets)
        print("ipv6_targets=%d" % ipv6_targets)
        print("named_targets=%d" % named_targets)
        print("paths=%d" % len(PATHS))
        print("probes=%d" % probes)
        print("blocked=%d" % blocked)
        print("tls_blocked=%d" % tls_blocked)
        print("redirects=%d" % redirects)
        print("basic_auth=%d" % basic_auth)
        print("valid_https=%d" % valid_https)
        print("bypass_findings=%d" % unsafe_http)
        print("unsafe_http=%d" % unsafe_http)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status_text == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
