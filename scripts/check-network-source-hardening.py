#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen network/exposure guards.

The guard validates network, DNS, direct-origin, UDP, firewall/nft and network
policy guard sources for expected metadata-only probe scope, host/port policy,
origin-protection, firewall/nft parsing and compact summary markers. It only
reads project source files; it does not run Docker, DNS, HTTP/TLS, firewall/nft,
imports, backups, restores, regressions or database queries and never reads
secrets, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SCRIPTS = ROOT / "scripts"


TARGETS: dict[str, Path] = {
    "network": SCRIPTS / "check-network-exposure.py",
    "dns": SCRIPTS / "check-public-dns-exposure.py",
    "multidns": SCRIPTS / "check-public-dns-multiresolver.py",
    "authdns": SCRIPTS / "check-public-dns-authoritative.py",
    "caa": SCRIPTS / "check-public-dns-caa.py",
    "bypass": SCRIPTS / "check-direct-origin-bypass.py",
    "ports": SCRIPTS / "check-direct-origin-port-exposure.py",
    "udp": SCRIPTS / "check-host-udp-exposure.py",
    "firewall": SCRIPTS / "check-host-firewall-br-ports.py",
    "nft": SCRIPTS / "check-host-nft-br-ports.py",
    "consistency": SCRIPTS / "check-network-policy-consistency.py",
    "runtime_env": SCRIPTS / "check-network-policy-runtime-env.py",
    "runtime_summary": SCRIPTS / "check-network-policy-runtime-summary.py",
}


MARKERS: dict[str, list[tuple[str, str]]] = {
    "network": [
        ("docstring_metadata", "Docker/Compose, proxy, tunnel, listener and firewall metadata"),
        ("compose_file", "COMPOSE_FILE = ROOT / \"docker-compose.yml\""),
        ("caddyfile", "CADDYFILE = ROOT / \"proxy\" / \"Caddyfile\""),
        ("cloudflared_config", "CLOUDFLARED_CONFIG = ROOT / \"cloudflared\" / \"config.yml\""),
        ("loopback_port", "EXPECTED_PROXY_PORT = 18083"),
        ("proxy_target", "EXPECTED_PROXY_TARGET = 8080"),
        ("hostname", "EXPECTED_HOSTNAME = \"br.m11h.eu\""),
        ("tunnel_service", "EXPECTED_TUNNEL_SERVICE = \"http://proxy:8080\""),
        ("credential_prefix", "EXPECTED_CREDENTIAL_PREFIX = \"/run/br-secrets/cloudflared/\""),
        ("docker_path", "DOCKER = Path(\"/usr/bin/docker\")"),
        ("ss_path", "SS = Path(\"/usr/bin/ss\")"),
        ("compose_ps", '[str(DOCKER), "compose", "ps", "--format", "json"]'),
        ("loopback_mapping", "127.0.0.1:18083:8080"),
        ("non_loopback_regex", "compose_contains_non_loopback_port_mapping"),
        ("cloudflared_secret_mount", "/srv/br-wissensdatenbank/secrets/cloudflared:/run/br-secrets/cloudflared:ro"),
        ("basic_auth", "caddy_missing_basic_auth"),
        ("reverse_proxy", "reverse_proxy app:8000"),
        ("ss_scope", '[str(SS), "-H", "-ltn"]'),
        ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
        ("nft_path", "NFT = Path(\"/usr/sbin/nft\")"),
        ("helper_available", "def helper_available(path: Path) -> bool:"),
        ("nft_json", '[str(SUDO), "-n", str(NFT), "-j", "list", "ruleset"]'),
        ("summary", "network_exposure_status=%s checks=%d findings=%d published_ports=%d public_binds=%d loopback_listeners=%d non_loopback_listeners=%d nft_nat_redirect_18083=%d tunnel_host=%s"),
    ],
    "dns": [
        ("docstring_no_change", "never changes DNS"),
        ("host_env", "BR_PUBLIC_DNS_HOST"),
        ("forbidden_ips", "31.70.74.139,100.102.205.121"),
        ("require_a", "BR_PUBLIC_DNS_REQUIRE_A"),
        ("allow_aaaa", "BR_PUBLIC_DNS_ALLOW_AAAA"),
        ("getaddrinfo", "socket.getaddrinfo(HOST, PORT, family, socket.SOCK_STREAM)"),
        ("forbidden_hits", "forbidden_origin_records"),
        ("global_records", "no_global_public_records"),
        ("non_public", "non_public_records"),
        ("summary", "public_dns_exposure_status=%s checks=%d findings=%d host=%s a_records=%d aaaa_records=%d forbidden_hits=%d global_records=%d non_public_records=%d"),
    ],
    "multidns": [
        ("docstring_multiresolver", "small fixed set of public recursive resolvers"),
        ("host", "BR_PUBLIC_DNS_HOST"),
        ("resolvers", "1.1.1.1,8.8.8.8,9.9.9.9"),
        ("forbidden_ips", "31.70.74.139,100.102.205.121"),
        ("min_success", "BR_PUBLIC_DNS_MULTI_MIN_SUCCESS"),
        ("timeout", "BR_PUBLIC_DNS_MULTI_TIMEOUT"),
        ("qtype_a", "QTYPE_A = 1"),
        ("qtype_aaaa", "QTYPE_AAAA = 28"),
        ("udp_dns", "socket.SOCK_DGRAM"),
        ("no_dnssec", "does not perform DNSSEC validation"),
        ("forbidden", "forbidden_origin_records"),
        ("summary", "public_dns_multiresolver_status=%s checks=%d findings=%d host=%s resolvers=%d successful_resolvers=%d resolver_errors=%d a_records=%d aaaa_records=%d unique_records=%d forbidden_hits=%d global_records=%d non_public_records=%d"),
    ],
    "authdns": [
        ("docstring_authoritative", "asks authoritative nameservers directly"),
        ("zone", "BR_PUBLIC_DNS_ZONE"),
        ("bootstrap", "BR_PUBLIC_DNS_AUTH_BOOTSTRAP_RESOLVER"),
        ("qtype_ns", "QTYPE_NS = 2"),
        ("decode_name", "def decode_name(data: bytes, offset: int)"),
        ("authoritative_flag", "authoritative = bool(flags & 0x0400)"),
        ("resolve_ns", "def resolve_nameserver_addresses(nameservers: set[str])"),
        ("no_dnssec", "does not perform DNSSEC validation"),
        ("insufficient_authorities", "insufficient_successful_authorities"),
        ("forbidden", "forbidden_origin_records"),
        ("summary", "public_dns_authoritative_status=%s checks=%d findings=%d host=%s zone=%s nameservers=%d authority_addresses=%d successful_authorities=%d authority_errors=%d authoritative_responses=%d a_records=%d aaaa_records=%d unique_records=%d forbidden_hits=%d global_records=%d non_public_records=%d"),
    ],
    "caa": [
        ("docstring_caa", "do not block the current Let's Encrypt"),
        ("resolver", "BR_PUBLIC_DNS_CAA_RESOLVER"),
        ("allowed_ca", "letsencrypt.org"),
        ("known_tags", "KNOWN_TAGS = {\"issue\", \"issuewild\", \"iodef\", \"accounturi\", \"validationmethods\"}"),
        ("qtype_caa", "QTYPE_CAA = 257"),
        ("critical", "CRITICAL_FLAG = 0x80"),
        ("parse_caa", "def parse_caa_response"),
        ("critical_unknown", "critical_unknown_caa"),
        ("issue_blocks", "caa_issue_blocks_expected_ca"),
        ("summary", "public_dns_caa_status=%s checks=%d findings=%d host=%s zone=%s qnames=%d successful_lookups=%d lookup_errors=%d caa_records=%d issue=%d issuewild=%d iodef=%d unrestricted=%d letsencrypt_allowed=%d blocked_issue=%d critical_unknown=%d"),
    ],
    "bypass": [
        ("docstring_no_body", "reads no response bodies, sends no credentials"),
        ("host_header", "BR_DIRECT_ORIGIN_HOST"),
        ("targets", "31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79"),
        ("paths", "DEFAULT_PATHS = \"/,/healthz,/login,/queries,/sources,/answers,/search,/validation\""),
        ("head", "HEAD %s HTTP/1.1"),
        ("header_injection", "has_header_injection"),
        ("tls_cert_required", "context.verify_mode = ssl.CERT_REQUIRED"),
        ("sni", "server_hostname=HOST_HEADER"),
        ("allowed_401", "status == 401"),
        ("allowed_redirect", "location.startswith(\"https://%s/\" % HOST_HEADER.lower())"),
        ("unsafe", "direct_origin_unsafe_responses"),
        ("summary", "direct_origin_bypass_status=%s checks=%d findings=%d targets=%d ipv4_targets=%d ipv6_targets=%d named_targets=%d paths=%d probes=%d blocked=%d tls_blocked=%d redirects=%d basic_auth=%d valid_https=%d bypass_findings=%d unsafe_http=%d"),
    ],
    "ports": [
        ("docstring_metadata", "metadata-only TCP connect probes"),
        ("no_app_data", "It sends no application data"),
        ("targets", "DEFAULT_TARGETS = \"31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79\""),
        ("ports", "DEFAULT_PORTS = \"80,443,8000,8080,18083,5432,2019\""),
        ("allowed", "DEFAULT_ALLOWED_OPEN_PORTS = \"80,443\""),
        ("parse_ports", "def parse_ports(values: list[str])"),
        ("create_connection", "socket.create_connection((target, port), timeout=TIMEOUT_SECONDS)"),
        ("unexpected_open", "direct_origin_port_unexpected_open"),
        ("summary", "direct_origin_port_exposure_status=%s checks=%d findings=%d targets=%d ipv4_targets=%d ipv6_targets=%d named_targets=%d ports=%d probes=%d open_total=%d allowed_open=%d unexpected_open=%d closed_or_filtered=%d allowed_ports=%s"),
    ],
    "udp": [
        ("docstring_metadata", "UDP exposure metadata only"),
        ("no_packets", "does\nnot send UDP packets"),
        ("ports", "DEFAULT_PORTS = \"443,80,8000,8080,18083,5432,2019\""),
        ("direct_hosts", "DEFAULT_DIRECT_HOSTS = \"0.0.0.0,::,31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79\""),
        ("context", "PUBLIC_IPV4="),
        ("docker_path", "DOCKER = Path(\"/usr/bin/docker\")"),
        ("ss_path", "SS = Path(\"/usr/bin/ss\")"),
        ("helper_available", "def helper_available(path: Path) -> bool:"),
        ("ss_udp", '[str(SS), "-H", "-lun"]'),
        ("compose_ps", '[str(DOCKER), "compose", "ps", "--format", "json"]'),
        ("udp_protocol", "protocol != \"udp\""),
        ("unexpected", "host_udp_unexpected_direct_listener"),
        ("summary", "host_udp_exposure_status=%s checks=%d findings=%d ports=%d direct_hosts=%d relevant_listeners=%d direct_relevant_listeners=%d loopback_relevant_listeners=%d udp_publishers=%d host_udp_published=%d unexpected_host_udp=%d allowed_udp_ports=%s"),
    ],
    "firewall": [
        ("docstring_readonly", "iptables/ip6tables-save metadata only"),
        ("tcp_ports", "BR_FIREWALL_TCP_PORTS"),
        ("udp_ports", "BR_FIREWALL_UDP_PORTS"),
        ("web_ports", "BR_FIREWALL_ALLOWED_WEB_TCP_PORTS"),
        ("loopback", "BR_FIREWALL_EXPECTED_LOOPBACK_TCP"),
        ("direct_hosts", "BR_FIREWALL_DIRECT_HOSTS"),
        ("context", "TAILSCALE_IPV4="),
        ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
        ("xtables_nft_multi_path", "XTABLES_NFT_MULTI = Path(\"/usr/sbin/xtables-nft-multi\")"),
        ("helper_available", "def helper_available(path: Path) -> bool:"),
        ("iptables_save", '[str(SUDO), "-n", str(XTABLES_NFT_MULTI), subcommand]'),
        ("shlex", "shlex.split(line)"),
        ("input_accept", "unexpected_input_accepts"),
        ("nat_rules", "unexpected_nat_rules"),
        ("docker_bridge", "docker_bridge_rules"),
        ("summary", "host_firewall_br_ports_status=%s checks=%d findings=%d direct_hosts=%d input_accepts=%d unexpected_input_accepts=%d nat_rules=%d expected_loopback_nat=%d unexpected_nat_rules=%d web_accepts=%d docker_bridge_rules=%d"),
    ],
    "nft": [
        ("docstring_readonly", "nft -j list ruleset"),
        ("tcp_ports", "BR_NFT_TCP_PORTS"),
        ("udp_ports", "BR_NFT_UDP_PORTS"),
        ("web_ports", "BR_NFT_ALLOWED_WEB_TCP_PORTS"),
        ("loopback", "BR_NFT_EXPECTED_LOOPBACK_TCP"),
        ("direct_hosts", "BR_NFT_DIRECT_HOSTS"),
        ("input_chains", "INPUT_CHAINS = {\"INPUT\", \"ufw-user-input\", \"ufw6-user-input\"}"),
        ("unsupported", "UNSUPPORTED_EXPR_KEYS"),
        ("max_depth", "BR_NFT_MAX_CHAIN_TRAVERSAL_DEPTH"),
        ("setref", "expanded_setrefs"),
        ("jump_goto", "jump",),
        ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
        ("nft_path", "NFT = Path(\"/usr/sbin/nft\")"),
        ("helper_available", "def helper_available(path: Path) -> bool:"),
        ("nft_json", '[str(SUDO), "-n", str(NFT), "-j", "list", "ruleset"]'),
        ("summary", "host_nft_br_ports_status=%s checks=%d findings=%d direct_hosts=%d tables=%d chains=%d rules=%d input_accepts=%d unexpected_input_accepts=%d nat_rules=%d expected_loopback_nat=%d unexpected_nat_rules=%d web_exposure_rules=%d docker_bridge_rules=%d xt_nat_rules=%d native_nat_rules=%d unsupported_expr_rules=%d unsupported_jump_rules=%d traversed_jump_rules=%d unresolved_jump_rules=%d chain_traversal_rules=%d chain_traversal_cycles=%d set_objects=%d set_elements=%d expanded_setref_rules=%d expanded_setrefs=%d expanded_anonymous_set_rules=%d expanded_anonymous_sets=%d unresolved_setref_rules=%d"),
    ],
    "consistency": [
        ("docstring_consistency", "compares the metadata policy defaults"),
        ("targets", "EXPECTED_CONCRETE_TARGETS"),
        ("wildcards", "EXPECTED_WILDCARDS"),
        ("web_tcp", "EXPECTED_WEB_TCP = {80, 443}"),
        ("br_tcp", "EXPECTED_BR_TCP = {8000, 8080, 18083, 5432, 2019}"),
        ("br_udp", "EXPECTED_BR_UDP = {443, 80, 8000, 8080, 18083, 5432, 2019}"),
        ("loopback", "EXPECTED_LOOPBACK_TCP = {\"127.0.0.1:18083\"}"),
        ("ast_literal", "ast.literal_eval"),
        ("host_context", "host_context_values"),
        ("summary", "network_policy_consistency_status=%s checks=%d findings=%d concrete_targets=%d wildcard_hosts=%d tcp_ports=%d udp_ports=%d web_tcp=%d loopback_tcp=%d"),
    ],
    "runtime_env": [
        ("docstring_no_values", "never prints environment values"),
        ("env_names", "NETWORK_POLICY_ENV_NAMES = {"),
        ("direct_origin", "BR_DIRECT_ORIGIN_TARGETS"),
        ("firewall", "BR_FIREWALL_DIRECT_HOSTS"),
        ("nft", "BR_NFT_DIRECT_HOSTS"),
        ("allowed_refs", "ALLOWED_PROJECT_REFERENCES = {"),
        ("units", "BR_UNITS = ["),
        ("systemctl_path", "SYSTEMCTL = Path(\"/usr/bin/systemctl\")"),
        ("helper_available", "def helper_available(path: Path) -> bool:"),
        ("systemctl_show", "str(SYSTEMCTL)"),
        ("current_env", "network_policy_runtime_current_env_override"),
        ("unit_override", "network_policy_runtime_unit_override"),
        ("summary", "network_policy_runtime_env_status=%s checks=%d findings=%d env_names=%d current_env_overrides=%d unit_overrides=%d project_references=%d installed_unit_references=%d"),
    ],
    "runtime_summary": [
        ("docstring_existing", "executes existing metadata-only network/exposure guard summaries"),
        ("timeout", "BR_NETWORK_POLICY_RUNTIME_SUMMARY_TIMEOUT"),
        ("network_guards", "NETWORK_GUARDS: list[tuple[str, str, str]] = ["),
        ("network_exposure", "check-network-exposure.py"),
        ("host_nft", "check-host-nft-br-ports.py"),
        ("runtime_env", "check-network-policy-runtime-env.py"),
        ("timeout_expired", "subprocess.TimeoutExpired"),
        ("parse_summary", "def parse_key_values(line: str)"),
        ("invariants", "def check_invariants"),
        ("forbidden_hits", "forbidden_hits"),
        ("unexpected_open", "unexpected_open"),
        ("runtime_overrides", "current_env_overrides"),
        ("summary", "network_policy_runtime_summary_status=%s checks=%d findings=%d summaries=%d ok_summaries=%d failed_summaries=%d origin_targets=%d direct_hosts=%d tcp_ports=%d udp_ports=%d web_tcp=%d loopback_tcp=%d"),
    ],
}


FORBIDDEN_MARKERS = [
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
    "pg_dump",
    "restic ",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    if path.is_symlink():
        findings.append("symlink_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def check_markers(findings: list[str], text: str, markers: list[tuple[str, str]], prefix: str) -> int:
    checks = 0
    for label, marker in markers:
        checks += 1
        if marker not in text:
            findings.append("%s_missing=%s" % (prefix, safe(label)))
    return checks


def check_forbidden(findings: list[str], text: str, prefix: str) -> int:
    checks = 0
    for marker in FORBIDDEN_MARKERS:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen network source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    texts: dict[str, str] = {}
    for label, path in TARGETS.items():
        texts[label] = read_source(path, findings, label)
        checks += 1

    marker_count = 0
    for label, markers in MARKERS.items():
        marker_count += len(markers)
        checks += check_markers(findings, texts.get(label, ""), markers, label)

    for label, text in texts.items():
        checks += check_forbidden(findings, text, label)

    checks += 1
    if texts["network"].find("def compose_ps") > texts["network"].find("def check_compose"):
        findings.append("network_compose_parser_after_check")
    checks += 1
    if texts["multidns"].find("def encode_name") > texts["multidns"].find("def dns_query"):
        findings.append("multidns_encoder_after_query")
    checks += 1
    if texts["authdns"].find("def decode_name") > texts["authdns"].find("def parse_records"):
        findings.append("authdns_decoder_after_parse")
    checks += 1
    if texts["nft"].find("def parse_rule") > texts["nft"].find("def analyze_ruleset") and "def analyze_ruleset" in texts["nft"]:
        findings.append("nft_parse_rule_after_analyze")
    checks += 1
    if texts["runtime_summary"].find("NETWORK_GUARDS") > texts["runtime_summary"].find("for label, script, _status_key in NETWORK_GUARDS"):
        findings.append("runtime_summary_guard_list_after_loop")

    status = "ok" if not findings else "failed"
    summary = "network_source_hardening_status=%s checks=%d findings=%d files=%d markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(TARGETS),
        marker_count,
        len(FORBIDDEN_MARKERS) * len(TARGETS),
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
