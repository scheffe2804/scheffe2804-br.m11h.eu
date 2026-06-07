#!/usr/bin/env python3
"""Read-only external cookie security guard for BR-Wissen.

The guard performs unauthenticated HTTPS GET requests against the public hostname
and validates Set-Cookie attributes only. It never prints cookie values, never
sends credentials and never reads HTTP response bodies, application secrets,
dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
from http.client import HTTPResponse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "https://br.m11h.eu"
EXPECTED_HOST = "br.m11h.eu"
PATHS = ["/", "/healthz", "/login"]
TIMEOUT_SECONDS = 15
EXPECTED_COOKIE_NAME_PREFIXES = ("CF_", "CF_ACCESS_")


def fetch_cookie_headers(path: str) -> tuple[int, list[str]]:
    request = Request(BASE_URL + path, method="GET", headers={"User-Agent": "br-wissen-external-cookie-security-guard"})
    try:
        response: HTTPResponse = urlopen(request, timeout=TIMEOUT_SECONDS)  # nosec B310 - fixed operational HTTPS target
        status = int(response.status)
        cookies = response.headers.get_all("Set-Cookie") or []
        response.close()
        return status, cookies
    except HTTPError as exc:
        cookies = exc.headers.get_all("Set-Cookie") or []
        return int(exc.code), cookies
    except URLError:
        return 0, []


def parse_cookie(cookie: str) -> tuple[str, dict[str, str], set[str]]:
    parts = [part.strip() for part in cookie.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0] if parts else ""
    attrs: dict[str, str] = {}
    flags: set[str] = set()
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            attrs[key.lower()] = value.strip()
        else:
            flags.add(part.lower())
    return name, attrs, flags


def domain_allowed(value: str) -> bool:
    if not value:
        return True
    normalized = value.lower().rstrip(".")
    return normalized in {EXPECTED_HOST, "." + EXPECTED_HOST, ".m11h.eu"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen external cookie security attributes")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    checked_paths = 0
    cookie_count = 0
    secure_count = 0
    httponly_count = 0
    samesite_count = 0
    path_root_count = 0
    expiry_count = 0
    expected_name_count = 0
    allowed_domain_count = 0

    for path in PATHS:
        status, cookies = fetch_cookie_headers(path)
        label = path.strip("/") or "root"
        checked_paths += 1
        checks += 1
        if status == 0:
            findings.append("path_%s_unreachable" % label)
            continue
        checks += 1
        if not cookies:
            findings.append("path_%s_missing_set_cookie" % label)
            continue

        for cookie in cookies:
            cookie_count += 1
            name, attrs, flags = parse_cookie(cookie)
            checks += 1
            if name.startswith(EXPECTED_COOKIE_NAME_PREFIXES):
                expected_name_count += 1
            else:
                findings.append("path_%s_unexpected_cookie_name" % label)

            checks += 1
            if "secure" in flags:
                secure_count += 1
            else:
                findings.append("path_%s_cookie_missing_secure" % label)

            checks += 1
            if "httponly" in flags:
                httponly_count += 1
            else:
                findings.append("path_%s_cookie_missing_httponly" % label)

            checks += 1
            samesite = attrs.get("samesite", "").lower()
            # This validates SameSite syntax/compatibility, not maximum strictness:
            # Cloudflare Access may legitimately use SameSite=None together with Secure.
            if samesite in {"strict", "lax", "none"}:
                samesite_count += 1
            else:
                findings.append("path_%s_cookie_missing_samesite" % label)

            checks += 1
            if attrs.get("path") == "/":
                path_root_count += 1
            else:
                findings.append("path_%s_cookie_path_not_root" % label)

            checks += 1
            if "expires" in attrs or "max-age" in attrs:
                expiry_count += 1
            else:
                findings.append("path_%s_cookie_missing_expiry" % label)

            checks += 1
            if domain_allowed(attrs.get("domain", "")):
                allowed_domain_count += 1
            else:
                findings.append("path_%s_cookie_domain_unexpected" % label)

    status_text = "ok" if not findings else "failed"
    if args.summary:
        print(
            "external_cookie_security_status=%s checks=%d findings=%d paths=%d cookies=%d expected_names=%d secure=%d httponly=%d samesite=%d path_root=%d expiry=%d allowed_domain=%d"
            % (
                status_text,
                checks,
                len(findings),
                checked_paths,
                cookie_count,
                expected_name_count,
                secure_count,
                httponly_count,
                samesite_count,
                path_root_count,
                expiry_count,
                allowed_domain_count,
            )
        )
    else:
        print("external_cookie_security_status=%s" % status_text)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("paths=%d" % checked_paths)
        print("cookies=%d" % cookie_count)
        print("expected_names=%d" % expected_name_count)
        print("secure=%d" % secure_count)
        print("httponly=%d" % httponly_count)
        print("samesite=%d" % samesite_count)
        print("path_root=%d" % path_root_count)
        print("expiry=%d" % expiry_count)
        print("allowed_domain=%d" % allowed_domain_count)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status_text == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
