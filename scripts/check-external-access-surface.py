#!/usr/bin/env python3
"""Read-only external HTTPS access-surface guard for BR-Wissen.

The guard performs unauthenticated HTTPS GET requests against the public
Cloudflare hostname and checks status/header metadata only. It never sends
credentials and never reads response bodies, application secrets, dumps, logs,
answers or source documents.
"""

from __future__ import annotations

import argparse
from http.client import HTTPResponse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "https://br.m11h.eu"
EXPECTED_ACCESS_DOMAIN = "br.m11h.eu"
PATHS = ["/", "/healthz", "/login", "/queries", "/sources", "/answers", "/search", "/validation"]
TIMEOUT_SECONDS = 15


CADDY_BASIC_AUTH_HEADERS: dict[str, list[str]] = {
    "www-authenticate": ["basic"],
    "x-robots-tag": ["noindex", "nofollow", "noarchive"],
    "cache-control": ["no-store"],
    "content-security-policy": ["frame-ancestors 'none'"],
    "referrer-policy": ["no-referrer"],
    "x-frame-options": ["deny"],
    "x-content-type-options": ["nosniff"],
}


CLOUDFLARE_ACCESS_HEADERS: dict[str, list[str]] = {
    "cf-access-domain": [EXPECTED_ACCESS_DOMAIN],
    "cf-ray": [],
    "cf-version": [],
    "content-security-policy": ["frame-ancestors 'none'"],
    "referrer-policy": ["strict-origin-when-cross-origin"],
    "x-frame-options": ["deny"],
    "x-content-type-options": ["nosniff"],
}


def fetch_headers(path: str) -> tuple[int, dict[str, str]]:
    request = Request(BASE_URL + path, method="GET", headers={"User-Agent": "br-wissen-external-access-surface-guard"})
    try:
        response: HTTPResponse = urlopen(request, timeout=TIMEOUT_SECONDS)  # nosec B310 - fixed operational HTTPS target
        status = int(response.status)
        headers = {key.lower(): value for key, value in response.headers.items()}
        response.close()
        return status, headers
    except HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        return int(exc.code), headers
    except URLError:
        return 0, {}


def has_header_values(headers: dict[str, str], required: dict[str, list[str]]) -> tuple[bool, int]:
    checks = 0
    for header, values in required.items():
        checks += 1
        value = headers.get(header, "")
        if not value:
            return False, checks
        lowered = value.lower()
        for required_value in values:
            if required_value.lower() not in lowered:
                return False, checks
    return True, checks


def path_label(path: str) -> str:
    return path.strip("/") or "root"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen external HTTPS access surface")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    checked_paths = 0
    protected_paths = 0
    cf_access_paths = 0
    basic_auth_paths = 0
    redirect_paths = 0
    cloudflare_server_paths = 0
    set_cookie_paths = 0

    for path in PATHS:
        status, headers = fetch_headers(path)
        label = path_label(path)
        checked_paths += 1
        checks += 1
        if status == 0:
            findings.append("path_%s_unreachable" % label)
            continue

        if 300 <= status <= 399:
            redirect_paths += 1
            findings.append("path_%s_unexpected_redirect_status=%d" % (label, status))

        checks += 1
        server_header = headers.get("server", "").lower()
        if "cloudflare" in server_header:
            cloudflare_server_paths += 1
        else:
            findings.append("path_%s_missing_cloudflare_server_marker" % label)

        checks += 1
        if headers.get("set-cookie"):
            set_cookie_paths += 1

        cf_access, cf_checks = has_header_values(headers, CLOUDFLARE_ACCESS_HEADERS)
        checks += cf_checks
        caddy_basic, caddy_checks = has_header_values(headers, CADDY_BASIC_AUTH_HEADERS)
        checks += caddy_checks

        is_basic_auth_block = status == 401 and caddy_basic
        is_cloudflare_access_block = cf_access and status in {200, 401, 403}

        if is_cloudflare_access_block:
            cf_access_paths += 1
        if is_basic_auth_block:
            basic_auth_paths += 1

        if is_cloudflare_access_block or is_basic_auth_block:
            protected_paths += 1
        else:
            findings.append("path_%s_not_protected_status=%d" % (label, status))

    status_text = "ok" if not findings else "failed"
    if args.summary:
        print(
            "external_access_surface_status=%s checks=%d findings=%d paths=%d protected=%d cf_access=%d basic_auth=%d redirects=%d cloudflare_server=%d set_cookie_paths=%d"
            % (
                status_text,
                checks,
                len(findings),
                checked_paths,
                protected_paths,
                cf_access_paths,
                basic_auth_paths,
                redirect_paths,
                cloudflare_server_paths,
                set_cookie_paths,
            )
        )
    else:
        print("external_access_surface_status=%s" % status_text)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("paths=%d" % checked_paths)
        print("protected=%d" % protected_paths)
        print("cf_access=%d" % cf_access_paths)
        print("basic_auth=%d" % basic_auth_paths)
        print("redirects=%d" % redirect_paths)
        print("cloudflare_server=%d" % cloudflare_server_paths)
        print("set_cookie_paths=%d" % set_cookie_paths)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status_text == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
