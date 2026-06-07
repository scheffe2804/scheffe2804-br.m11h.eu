#!/usr/bin/env python3
"""Read-only external TLS certificate metadata guard for BR-Wissen.

The guard opens a normal TLS connection to the public hostname and validates only
certificate/protocol metadata. It never sends credentials and never reads HTTP
response bodies, application secrets, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
from datetime import datetime, timezone
from typing import Any


HOST = os.getenv("BR_TLS_HOST", "br.m11h.eu")
PORT = int(os.getenv("BR_TLS_PORT", "443"))
TIMEOUT_SECONDS = float(os.getenv("BR_TLS_TIMEOUT_SECONDS", "15"))
MIN_VALID_DAYS = float(os.getenv("BR_TLS_MIN_VALID_DAYS", "14"))
EXPECTED_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}
EXPECTED_TLS13_CIPHERS = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
}


def dns_name_matches(pattern: str, hostname: str) -> bool:
    """Return True for exact DNS matches or one-label wildcard matches.

    Example: ``*.m11h.eu`` matches ``br.m11h.eu`` but not ``m11h.eu`` and not
    ``deep.br.m11h.eu``.
    """
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if pattern == hostname:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[1:]
    return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")


def parse_cert_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    except (ValueError, OSError):
        return None


def cert_names(cert: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for item in cert.get("subjectAltName") or []:
        if isinstance(item, tuple) and len(item) == 2 and str(item[0]).upper() == "DNS":
            names.append(str(item[1]))
    if names:
        return names
    for subject_part in cert.get("subject") or []:
        for key, value in subject_part:
            if str(key).lower() == "commonname":
                names.append(str(value))
    return names


def issuer_present(cert: dict[str, Any]) -> bool:
    return bool(cert.get("issuer"))


def collect_tls_metadata() -> tuple[dict[str, Any], str | None]:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((HOST, PORT), timeout=TIMEOUT_SECONDS) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=HOST) as tls_sock:
                cert = tls_sock.getpeercert()
                metadata = {
                    "tls_version": tls_sock.version() or "unknown",
                    "cipher": (tls_sock.cipher() or ("unknown", "", 0))[0],
                    "cert": cert,
                }
                return metadata, None
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return {}, exc.__class__.__name__


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen public TLS certificate metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    metadata, error = collect_tls_metadata()
    checks += 1
    if error:
        findings.append("tls_connection_failed=%s" % error)
        metadata = {"tls_version": "unreachable", "cipher": "none", "cert": {}}

    cert = metadata.get("cert") or {}
    tls_version = str(metadata.get("tls_version") or "unknown")
    cipher = str(metadata.get("cipher") or "unknown")

    checks += 1
    if tls_version not in EXPECTED_TLS_VERSIONS:
        findings.append("unexpected_tls_version=%s" % tls_version)

    checks += 1
    if tls_version == "TLSv1.3" and cipher not in EXPECTED_TLS13_CIPHERS:
        findings.append("unexpected_tls13_cipher=%s" % cipher)

    now = datetime.now(timezone.utc)
    not_before = parse_cert_time(str(cert.get("notBefore") or "")) if cert else None
    not_after = parse_cert_time(str(cert.get("notAfter") or "")) if cert else None

    checks += 1
    if not_before is None:
        findings.append("cert_not_before_missing_or_invalid")
    elif not_before > now:
        findings.append("cert_not_yet_valid")

    days_valid = -1.0
    checks += 1
    if not_after is None:
        findings.append("cert_not_after_missing_or_invalid")
    else:
        days_valid = max(0.0, (not_after - now).total_seconds() / 86400.0)
        if not_after <= now:
            findings.append("cert_expired")
        elif days_valid < MIN_VALID_DAYS:
            findings.append("cert_expires_soon_days=%.1f" % days_valid)

    names = cert_names(cert) if cert else []
    checks += 1
    san_match = any(dns_name_matches(name, HOST) for name in names)
    if not san_match:
        findings.append("cert_name_mismatch_expected=%s_names=%d" % (HOST, len(names)))

    checks += 1
    issuer_ok = issuer_present(cert) if cert else False
    if not issuer_ok:
        findings.append("cert_issuer_missing")

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "tls_certificate_status=%s checks=%d findings=%d host=%s port=%d tls=%s days_valid=%.1f san_match=%d issuer_present=%d cipher_present=%d"
            % (status, checks, len(findings), HOST, PORT, tls_version, days_valid, 1 if san_match else 0, 1 if issuer_ok else 0, 1 if cipher != "unknown" else 0)
        )
    else:
        print("tls_certificate_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("host=%s" % HOST)
        print("port=%d" % PORT)
        print("tls=%s" % tls_version)
        print("days_valid=%.1f" % days_valid)
        print("san_match=%d" % (1 if san_match else 0))
        print("issuer_present=%d" % (1 if issuer_ok else 0))
        print("cipher_present=%d" % (1 if cipher != "unknown" else 0))
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
