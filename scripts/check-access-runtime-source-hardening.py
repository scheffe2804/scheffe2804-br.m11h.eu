#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen access/runtime guards.

The guard validates runtime HTTP, external access, external cookie, TLS and app
auth guard sources for expected unauthenticated, metadata-only access checks,
security-header/cookie/TLS markers, CSRF-negative probes and compact summaries.
It only reads project source files; it does not run HTTP probes, TLS probes,
Docker, imports, backups, restores, regressions or database queries and never
reads secrets, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
RUNTIME_HTTP = ROOT / "scripts" / "check-runtime-http-security.py"
EXTERNAL_ACCESS = ROOT / "scripts" / "check-external-access-surface.py"
EXTERNAL_COOKIE = ROOT / "scripts" / "check-external-cookie-security.py"
TLS_CERTIFICATE = ROOT / "scripts" / "check-tls-certificate.py"
APP_AUTH = ROOT / "scripts" / "check-app-auth-surface.py"


RUNTIME_MARKERS: list[tuple[str, str]] = [
    ("docstring_metadata_only", "checks status/header metadata only. It never sends credentials and never\nreads response bodies"),
    ("loopback_base", "BASE_URL = \"http://127.0.0.1:18083\""),
    ("paths", "PATHS = [\"/\", \"/healthz\"]"),
    ("timeout", "TIMEOUT_SECONDS = 10"),
    ("required_headers", "REQUIRED_HEADERS: dict[str, list[str]] = {"),
    ("basic_auth", '"www-authenticate": ["basic"]'),
    ("robots", '"x-robots-tag": ["noindex", "nofollow", "noarchive", "nosnippet", "noimageindex"]'),
    ("referrer", '"referrer-policy": ["no-referrer"]'),
    ("nosniff", '"x-content-type-options": ["nosniff"]'),
    ("frame_options", '"x-frame-options": ["deny"]'),
    ("permissions", '"permissions-policy": ["camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"]'),
    ("cache", '"cache-control": ["no-store"]'),
    ("csp", '"content-security-policy": ['),
    ("user_agent", "br-wissen-runtime-http-security-guard"),
    ("urlopen", "urlopen(request, timeout=TIMEOUT_SECONDS)"),
    ("http_error_headers", "except HTTPError as exc:"),
    ("url_error_empty", "except URLError:"),
    ("status_401", "if status != 401:"),
    ("server_header", 'headers.get("server")'),
    ("summary", "runtime_http_security_status=%s checks=%d findings=%d paths=%d unauthorized=%d header_checks=%d server_header_seen=%d"),
]


EXTERNAL_ACCESS_MARKERS: list[tuple[str, str]] = [
    ("docstring_metadata_only", "checks status/header metadata only. It never sends\ncredentials and never reads response bodies"),
    ("base_url", "BASE_URL = \"https://br.m11h.eu\""),
    ("expected_domain", "EXPECTED_ACCESS_DOMAIN = \"br.m11h.eu\""),
    ("paths", "PATHS = [\"/\", \"/healthz\", \"/login\", \"/queries\", \"/sources\", \"/answers\", \"/search\", \"/validation\"]"),
    ("timeout", "TIMEOUT_SECONDS = 15"),
    ("caddy_headers", "CADDY_BASIC_AUTH_HEADERS: dict[str, list[str]] = {"),
    ("cf_headers", "CLOUDFLARE_ACCESS_HEADERS: dict[str, list[str]] = {"),
    ("cf_access_domain", '"cf-access-domain": [EXPECTED_ACCESS_DOMAIN]'),
    ("cf_ray", '"cf-ray": []'),
    ("cf_version", '"cf-version": []'),
    ("user_agent", "br-wissen-external-access-surface-guard"),
    ("server_cloudflare", 'if "cloudflare" in server_header:'),
    ("set_cookie_count", 'if headers.get("set-cookie"):'),
    ("cf_access_block", "is_cloudflare_access_block = cf_access and status in {200, 401, 403}"),
    ("basic_auth_block", "is_basic_auth_block = status == 401 and caddy_basic"),
    ("redirect_finding", "unexpected_redirect_status"),
    ("protected_finding", "not_protected_status"),
    ("summary", "external_access_surface_status=%s checks=%d findings=%d paths=%d protected=%d cf_access=%d basic_auth=%d redirects=%d cloudflare_server=%d set_cookie_paths=%d"),
]


EXTERNAL_COOKIE_MARKERS: list[tuple[str, str]] = [
    ("docstring_no_values", "validates Set-Cookie attributes only. It never prints cookie values, never\nsends credentials and never reads HTTP response bodies"),
    ("base_url", "BASE_URL = \"https://br.m11h.eu\""),
    ("expected_host", "EXPECTED_HOST = \"br.m11h.eu\""),
    ("paths", "PATHS = [\"/\", \"/healthz\", \"/login\"]"),
    ("timeout", "TIMEOUT_SECONDS = 15"),
    ("cookie_prefixes", "EXPECTED_COOKIE_NAME_PREFIXES = (\"CF_\", \"CF_ACCESS_\")"),
    ("user_agent", "br-wissen-external-cookie-security-guard"),
    ("set_cookie_only", "response.headers.get_all(\"Set-Cookie\") or []"),
    ("parse_cookie", "def parse_cookie(cookie: str)"),
    ("domain_allowed", "def domain_allowed(value: str) -> bool:"),
    ("allowed_domains", "return normalized in {EXPECTED_HOST, \".\" + EXPECTED_HOST, \".m11h.eu\"}"),
    ("missing_cookie", "missing_set_cookie"),
    ("unexpected_name", "unexpected_cookie_name"),
    ("secure", "cookie_missing_secure"),
    ("httponly", "cookie_missing_httponly"),
    ("samesite", "samesite in {\"strict\", \"lax\", \"none\"}"),
    ("path_root", "cookie_path_not_root"),
    ("expiry", "cookie_missing_expiry"),
    ("domain", "cookie_domain_unexpected"),
    ("summary", "external_cookie_security_status=%s checks=%d findings=%d paths=%d cookies=%d expected_names=%d secure=%d httponly=%d samesite=%d path_root=%d expiry=%d allowed_domain=%d"),
]


TLS_MARKERS: list[tuple[str, str]] = [
    ("docstring_metadata_only", "validates only\ncertificate/protocol metadata. It never sends credentials and never reads HTTP\nresponse bodies"),
    ("host", "HOST = os.getenv(\"BR_TLS_HOST\", \"br.m11h.eu\")"),
    ("port", "PORT = int(os.getenv(\"BR_TLS_PORT\", \"443\"))"),
    ("timeout", "BR_TLS_TIMEOUT_SECONDS"),
    ("min_valid", "BR_TLS_MIN_VALID_DAYS"),
    ("tls_versions", "EXPECTED_TLS_VERSIONS = {\"TLSv1.2\", \"TLSv1.3\"}"),
    ("tls13_ciphers", "EXPECTED_TLS13_CIPHERS = {"),
    ("dns_match", "def dns_name_matches(pattern: str, hostname: str) -> bool:"),
    ("wildcard_one_label", "hostname.endswith(suffix) and hostname.count(\".\") == pattern.count(\".\")"),
    ("cert_time", "ssl.cert_time_to_seconds(value)"),
    ("san_names", "subjectAltName"),
    ("issuer", "def issuer_present(cert: dict[str, Any]) -> bool:"),
    ("default_context", "ssl.create_default_context()"),
    ("check_hostname", "context.check_hostname = True"),
    ("cert_required", "context.verify_mode = ssl.CERT_REQUIRED"),
    ("sni", "context.wrap_socket(raw_sock, server_hostname=HOST)"),
    ("getpeercert", "tls_sock.getpeercert()"),
    ("tls_version_check", "unexpected_tls_version"),
    ("cipher_check", "unexpected_tls13_cipher"),
    ("expiry_check", "cert_expires_soon_days"),
    ("san_check", "cert_name_mismatch_expected"),
    ("summary", "tls_certificate_status=%s checks=%d findings=%d host=%s port=%d tls=%s days_valid=%.1f san_match=%d issuer_present=%d cipher_present=%d"),
]


APP_AUTH_MARKERS: list[tuple[str, str]] = [
    ("docstring_metadata_only", "does not send credentials, does not follow redirects, does\nnot read response bodies"),
    ("container_check", "CONTAINER_CHECK = r'''"),
    ("host", "HOST = \"127.0.0.1\""),
    ("port", "PORT = 8000"),
    ("timeout", "TIMEOUT = 5"),
    ("protected_gets", "PROTECTED_GETS = ["),
    ("protected_root", '"/",'),
    ("protected_sources", '"/sources",'),
    ("protected_validation", '"/validation",'),
    ("public_gets", "PUBLIC_GETS = {"),
    ("healthz", '"/healthz": 200'),
    ("login", '"/login": 200'),
    ("csrf_posts", "CSRF_POSTS = ["),
    ("logout", '"/logout",'),
    ("approve_evg", '"/sources/approve-evg-all",'),
    ("export", '"/answers/nonexistent/export",'),
    ("no_redirect_follow", "http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)"),
    ("user_agent", "br-wissen-app-auth-surface-guard"),
    ("post_form", "application/x-www-form-urlencoded"),
    ("location_only", '"location": headers_out.get("location", "")'),
    ("docker_exec", '["docker", "compose", "exec", "-T", "app", "python", "-"]'),
    ("json_parse", "json.loads(proc.stdout)"),
    ("protected_redirect", "status == 303 and location == \"/login\""),
    ("csrf_block", "if status == 403:"),
    ("post_successes", "post_successes += 1"),
    ("post_redirects", "post_redirects += 1"),
    ("protected_count", "if len(protected_gets) != 9:"),
    ("public_count", "if len(public_gets) != 2:"),
    ("csrf_count", "if len(csrf_posts) != 6:"),
    ("summary", "app_auth_surface_status=%s checks=%d findings=%d protected_gets=%d redirected=%d public_gets=%d public_ok=%d csrf_posts=%d csrf_blocked=%d post_successes=%d post_redirects=%d"),
]


FORBIDDEN_COMMON_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
    "COMMIT",
    "conn.commit",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
    ".read_text(",
    "pg_dump",
    "restic ",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def check_markers(findings: list[str], text: str, markers: list[tuple[str, str]], prefix: str) -> int:
    checks = 0
    for label, marker in markers:
        checks += 1
        if marker not in text:
            findings.append("%s_missing=%s" % (prefix, safe(label)))
    return checks


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen access/runtime source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    runtime_text = read_source(RUNTIME_HTTP, findings, "runtime_http_security")
    access_text = read_source(EXTERNAL_ACCESS, findings, "external_access_surface")
    cookie_text = read_source(EXTERNAL_COOKIE, findings, "external_cookie_security")
    tls_text = read_source(TLS_CERTIFICATE, findings, "tls_certificate")
    app_auth_text = read_source(APP_AUTH, findings, "app_auth_surface")
    checks += 5

    checks += check_markers(findings, runtime_text, RUNTIME_MARKERS, "runtime")
    checks += check_markers(findings, access_text, EXTERNAL_ACCESS_MARKERS, "external_access")
    checks += check_markers(findings, cookie_text, EXTERNAL_COOKIE_MARKERS, "external_cookie")
    checks += check_markers(findings, tls_text, TLS_MARKERS, "tls")
    checks += check_markers(findings, app_auth_text, APP_AUTH_MARKERS, "app_auth")

    for prefix, text in [
        ("runtime", runtime_text),
        ("external_access", access_text),
        ("external_cookie", cookie_text),
        ("tls", tls_text),
        ("app_auth", app_auth_text),
    ]:
        checks += check_forbidden(findings, text, FORBIDDEN_COMMON_MARKERS, prefix)

    checks += 1
    if runtime_text.find("REQUIRED_HEADERS") > runtime_text.find("for header, required_values in REQUIRED_HEADERS.items()"):
        findings.append("runtime_required_headers_after_loop")
    checks += 1
    if access_text.find("CLOUDFLARE_ACCESS_HEADERS") > access_text.find("has_header_values(headers, CLOUDFLARE_ACCESS_HEADERS)"):
        findings.append("external_access_cf_headers_after_check")
    checks += 1
    if cookie_text.find("EXPECTED_COOKIE_NAME_PREFIXES") > cookie_text.find("name.startswith(EXPECTED_COOKIE_NAME_PREFIXES)"):
        findings.append("external_cookie_prefixes_after_check")
    checks += 1
    if tls_text.find("EXPECTED_TLS_VERSIONS") > tls_text.find("if tls_version not in EXPECTED_TLS_VERSIONS"):
        findings.append("tls_versions_after_check")
    checks += 1
    if app_auth_text.find("PROTECTED_GETS") > app_auth_text.find("len(protected_gets) != 9"):
        findings.append("app_auth_protected_gets_after_count_check")

    status = "ok" if not findings else "failed"
    summary = "access_runtime_source_hardening_status=%s checks=%d findings=%d runtime_markers=%d external_access_markers=%d external_cookie_markers=%d tls_markers=%d app_auth_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(RUNTIME_MARKERS),
        len(EXTERNAL_ACCESS_MARKERS),
        len(EXTERNAL_COOKIE_MARKERS),
        len(TLS_MARKERS),
        len(APP_AUTH_MARKERS),
        len(FORBIDDEN_COMMON_MARKERS) * 5,
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
