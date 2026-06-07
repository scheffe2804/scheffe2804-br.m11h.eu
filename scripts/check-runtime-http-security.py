#!/usr/bin/env python3
"""Read-only runtime HTTP security guard for BR-Wissen.

The guard performs unauthenticated loopback HTTP requests against the local Caddy
proxy and checks status/header metadata only. It never sends credentials and never
reads response bodies, application secrets, dumps, logs, answers or source
documents.
"""

from __future__ import annotations

import argparse
from http.client import HTTPResponse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:18083"
PATHS = ["/", "/healthz"]
TIMEOUT_SECONDS = 10


REQUIRED_HEADERS: dict[str, list[str]] = {
    "www-authenticate": ["basic"],
    "x-robots-tag": ["noindex", "nofollow", "noarchive", "nosnippet", "noimageindex"],
    "referrer-policy": ["no-referrer"],
    "x-content-type-options": ["nosniff"],
    "x-frame-options": ["deny"],
    "permissions-policy": ["camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"],
    "cache-control": ["no-store"],
    "content-security-policy": [
        "default-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    ],
    "cross-origin-opener-policy": ["same-origin"],
    "cross-origin-resource-policy": ["same-origin"],
}


def fetch_headers(path: str) -> tuple[int, dict[str, str]]:
    request = Request(BASE_URL + path, method="GET", headers={"User-Agent": "br-wissen-runtime-http-security-guard"})
    try:
        response: HTTPResponse = urlopen(request, timeout=TIMEOUT_SECONDS)  # nosec B310 - loopback-only operational guard
        status = int(response.status)
        headers = {key.lower(): value for key, value in response.headers.items()}
        response.close()
        return status, headers
    except HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        return int(exc.code), headers
    except URLError:
        return 0, {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen runtime HTTP security headers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    checked_paths = 0
    header_checks = 0
    unauthorized_paths = 0
    server_header_seen = 0

    for path in PATHS:
        status, headers = fetch_headers(path)
        checked_paths += 1
        checks += 1
        if status != 401:
            findings.append("path_%s_status=%s" % (path.strip("/") or "root", status or "unreachable"))
        else:
            unauthorized_paths += 1

        for header, required_values in REQUIRED_HEADERS.items():
            header_checks += 1
            checks += 1
            value = headers.get(header, "")
            lowered = value.lower()
            if not value:
                findings.append("path_%s_missing_header=%s" % (path.strip("/") or "root", header))
                continue
            for required in required_values:
                if required.lower() not in lowered:
                    findings.append("path_%s_header_%s_missing_value=%s" % (path.strip("/") or "root", header, required.replace(" ", "_")))
                    break

        checks += 1
        if headers.get("server"):
            server_header_seen += 1
            findings.append("path_%s_server_header_present" % (path.strip("/") or "root"))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "runtime_http_security_status=%s checks=%d findings=%d paths=%d unauthorized=%d header_checks=%d server_header_seen=%d"
            % (status, checks, len(findings), checked_paths, unauthorized_paths, header_checks, server_header_seen)
        )
    else:
        print("runtime_http_security_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("paths=%d" % checked_paths)
        print("unauthorized=%d" % unauthorized_paths)
        print("header_checks=%d" % header_checks)
        print("server_header_seen=%d" % server_header_seen)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
