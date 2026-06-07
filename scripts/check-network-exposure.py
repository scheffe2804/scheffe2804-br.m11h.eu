#!/usr/bin/env python3
"""Read-only network exposure guard for BR-Wissen.

The guard checks Docker/Compose, proxy, tunnel, listener and firewall metadata
only. It never reads application secrets, credential files, dumps, logs, answers
or source documents.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "docker-compose.yml"
CADDYFILE = ROOT / "proxy" / "Caddyfile"
CLOUDFLARED_CONFIG = ROOT / "cloudflared" / "config.yml"
EXPECTED_PROXY_PORT = 18083
EXPECTED_PROXY_TARGET = 8080
EXPECTED_HOSTNAME = "br.m11h.eu"
EXPECTED_TUNNEL_SERVICE = "http://proxy:8080"
EXPECTED_CREDENTIAL_PREFIX = "/run/br-secrets/cloudflared/"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
SUDO = Path("/usr/bin/sudo")
NFT = Path("/usr/sbin/nft")
DOCKER = Path("/usr/bin/docker")
SS = Path("/usr/bin/ss")


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(ROOT), text=True, capture_output=True, check=False)


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


def compose_ps() -> tuple[int, list[dict[str, Any]]]:
    if not helper_available(DOCKER):
        return 127, []
    proc = run([str(DOCKER), "compose", "ps", "--format", "json"])
    if proc.returncode != 0:
        return proc.returncode, []
    stdout = proc.stdout.strip()
    if not stdout:
        return 0, []
    if stdout.startswith("["):
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return 1, []
        if not isinstance(data, list):
            return 1, []
        return 0, [item for item in data if isinstance(item, dict)]

    rows: list[dict[str, Any]] = []
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return 1, []
        if isinstance(item, dict):
            rows.append(item)
    return 0, rows


def service_name(row: dict[str, Any]) -> str:
    return str(row.get("Service") or row.get("service") or "")


def publishers(row: dict[str, Any]) -> list[dict[str, Any]]:
    value = row.get("Publishers") or row.get("publishers") or []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def is_published(pub: dict[str, Any]) -> bool:
    try:
        published = int(pub.get("PublishedPort") or pub.get("publishedPort") or 0)
    except (TypeError, ValueError):
        published = 0
    return published > 0


def pub_url(pub: dict[str, Any]) -> str:
    return str(pub.get("URL") or pub.get("url") or "")


def pub_target(pub: dict[str, Any]) -> int:
    try:
        return int(pub.get("TargetPort") or pub.get("targetPort") or 0)
    except (TypeError, ValueError):
        return 0


def pub_port(pub: dict[str, Any]) -> int:
    try:
        return int(pub.get("PublishedPort") or pub.get("publishedPort") or 0)
    except (TypeError, ValueError):
        return 0


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def check_compose(rows: list[dict[str, Any]], findings: list[str]) -> tuple[int, int, int]:
    checks = 0
    published_count = 0
    public_bind_count = 0
    loopback_proxy_found = False

    for row in rows:
        service = service_name(row)
        for pub in publishers(row):
            if not is_published(pub):
                continue
            published_count += 1
            url = pub_url(pub)
            target = pub_target(pub)
            port = pub_port(pub)
            checks += 1
            if service == "proxy" and url in LOOPBACK_HOSTS and port == EXPECTED_PROXY_PORT and target == EXPECTED_PROXY_TARGET:
                loopback_proxy_found = True
                continue
            if url not in LOOPBACK_HOSTS:
                public_bind_count += 1
                findings.append("published_non_loopback_%s_%s_%s" % (service or "unknown", url or "all", port))
            else:
                findings.append("unexpected_loopback_publish_%s_%s_%s" % (service or "unknown", url, port))

    checks += 1
    if not loopback_proxy_found:
        findings.append("missing_proxy_loopback_publish_127.0.0.1:18083")
    return checks, published_count, public_bind_count


def check_compose_file(text: str, findings: list[str]) -> int:
    checks = 0
    checks += 1
    if '127.0.0.1:18083:8080' not in text:
        findings.append("compose_missing_loopback_port_mapping")
    checks += 1
    if re.search(r"(?m)^\s*-\s*\"?(?:0\.0\.0\.0|::|\[::\]|31\.70\.74\.139|100\.102\.205\.121):", text):
        findings.append("compose_contains_non_loopback_port_mapping")
    checks += 1
    if "/srv/br-wissensdatenbank/secrets/cloudflared:/run/br-secrets/cloudflared:ro" not in text:
        findings.append("compose_missing_cloudflared_secret_mount")
    return checks


def check_caddy(text: str, findings: list[str]) -> int:
    checks = 0
    checks += 1
    if ":8080" not in text:
        findings.append("caddy_missing_8080_listener")
    checks += 1
    if "basic_auth" not in text:
        findings.append("caddy_missing_basic_auth")
    checks += 1
    if "reverse_proxy app:8000" not in text:
        findings.append("caddy_missing_app_reverse_proxy")
    checks += 1
    if "X-Robots-Tag" not in text or "noindex" not in text:
        findings.append("caddy_missing_noindex_header")
    checks += 1
    if "Cache-Control" not in text or "no-store" not in text:
        findings.append("caddy_missing_no_store_header")
    return checks


def check_cloudflared(text: str, findings: list[str]) -> int:
    checks = 0
    checks += 1
    if "hostname: %s" % EXPECTED_HOSTNAME not in text:
        findings.append("cloudflared_missing_expected_hostname")
    checks += 1
    if "service: %s" % EXPECTED_TUNNEL_SERVICE not in text:
        findings.append("cloudflared_missing_proxy_service")
    checks += 1
    if "service: http_status:404" not in text:
        findings.append("cloudflared_missing_404_fallback")
    checks += 1
    cred_match = re.search(r"(?m)^credentials-file:\s*(\S+)\s*$", text)
    if not cred_match:
        findings.append("cloudflared_missing_credentials_file_marker")
    else:
        cred_path = cred_match.group(1)
        if not cred_path.startswith(EXPECTED_CREDENTIAL_PREFIX) or not cred_path.endswith(".json"):
            findings.append("cloudflared_credentials_path_unexpected")
        if str(ROOT) in cred_path or cred_path.startswith("./") or cred_path.startswith("/home/"):
            findings.append("cloudflared_credentials_path_in_project_or_home")
    return checks


def split_listener(local: str) -> tuple[str, int]:
    local = local.strip()
    if local.startswith("[") and "]:" in local:
        host, raw_port = local.rsplit(":", 1)
        host = host.strip("[]")
    elif local.count(":") > 1:
        host, raw_port = local.rsplit(":", 1)
    elif ":" in local:
        host, raw_port = local.rsplit(":", 1)
    else:
        return local, 0
    try:
        port = int(raw_port)
    except ValueError:
        port = 0
    return host, port


def check_listener_scope(findings: list[str]) -> tuple[int, int, int]:
    checks = 1
    listener_count = 0
    non_loopback_count = 0
    if not helper_available(SS):
        findings.append("ss_helper_unavailable")
        return checks, listener_count, non_loopback_count
    proc = run([str(SS), "-H", "-ltn"])
    if proc.returncode != 0:
        findings.append("ss_unavailable_scope")
        return checks, listener_count, non_loopback_count
    expected_found = False
    for raw_line in proc.stdout.splitlines():
        parts = raw_line.split()
        if len(parts) < 4:
            continue
        host, port = split_listener(parts[3])
        if port != EXPECTED_PROXY_PORT:
            continue
        listener_count += 1
        checks += 1
        if host in LOOPBACK_HOSTS:
            expected_found = True
        else:
            non_loopback_count += 1

    checks += 1
    if not expected_found:
        findings.append("missing_loopback_listener_18083")
    if non_loopback_count:
        findings.append("non_loopback_listener_18083")
    return checks, listener_count, non_loopback_count


def walk_json(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child)


def check_nft_nat(findings: list[str]) -> tuple[int, int]:
    checks = 1
    redirect_count = 0
    if not helper_available(SUDO) or not helper_available(NFT):
        findings.append("nft_ruleset_helper_unavailable")
        return checks, redirect_count
    proc = run([str(SUDO), "-n", str(NFT), "-j", "list", "ruleset"])
    if proc.returncode != 0:
        findings.append("nft_ruleset_unavailable")
        return checks, redirect_count
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        findings.append("nft_ruleset_json_invalid")
        return checks, redirect_count

    for obj in walk_json(data):
        statements = obj.get("stmt")
        if not isinstance(statements, list):
            continue
        statement_text = json.dumps(statements, sort_keys=True, separators=(",", ":"))
        has_target_port = str(EXPECTED_PROXY_PORT) in statement_text
        has_nat_action = any(keyword in statement_text for keyword in ["redirect", "dnat", "masquerade"])
        if has_target_port and has_nat_action:
            redirect_count += 1
    checks += 1
    if redirect_count:
        findings.append("nft_nat_or_redirect_mentions_18083=%d" % redirect_count)
    return checks, redirect_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen network exposure metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    checks = 0
    code, rows = compose_ps()
    checks += 1
    if code != 0:
        findings.append("compose_ps_unavailable")
        rows = []

    compose_checks, published_count, public_bind_count = check_compose(rows, findings)
    checks += compose_checks
    checks += check_compose_file(read_text(COMPOSE_FILE), findings)
    checks += check_caddy(read_text(CADDYFILE), findings)
    checks += check_cloudflared(read_text(CLOUDFLARED_CONFIG), findings)
    ss_checks, listener_count, non_loopback_listener_count = check_listener_scope(findings)
    checks += ss_checks
    nft_checks, nft_redirect_count = check_nft_nat(findings)
    checks += nft_checks

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "network_exposure_status=%s checks=%d findings=%d published_ports=%d public_binds=%d loopback_listeners=%d non_loopback_listeners=%d nft_nat_redirect_18083=%d tunnel_host=%s"
            % (
                status,
                checks,
                len(findings),
                published_count,
                public_bind_count,
                listener_count,
                non_loopback_listener_count,
                nft_redirect_count,
                EXPECTED_HOSTNAME,
            )
        )
    else:
        print("network_exposure_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("published_ports=%d" % published_count)
        print("public_binds=%d" % public_bind_count)
        print("loopback_listeners=%d" % listener_count)
        print("non_loopback_listeners=%d" % non_loopback_listener_count)
        print("nft_nat_redirect_18083=%d" % nft_redirect_count)
        print("tunnel_host=%s" % EXPECTED_HOSTNAME)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
