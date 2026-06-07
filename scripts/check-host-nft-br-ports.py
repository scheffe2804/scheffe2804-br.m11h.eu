#!/usr/bin/env python3
"""Read-only nftables metadata guard for BR-Wissen ports.

The guard inspects local `nft -j list ruleset` JSON metadata only. It does not
alter firewall state, does not send packets, does not read application secrets,
dumps, logs, answers or source documents, and prints only counters/findings.

Scope: unexpected direct host input accepts or NAT/redirect/DNAT rules for
BR-relevant ports from the native nftables view. Docker-internal bridge rules are
counted but not treated as direct exposure unless they publish an unexpected
direct host port.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


HOST_CONTEXT = Path(os.getenv("BR_HOST_CONTEXT", "/etc/opencode-host-context"))
BR_TCP_PORTS_RAW = [item.strip() for item in os.getenv("BR_NFT_TCP_PORTS", os.getenv("BR_FIREWALL_TCP_PORTS", "8000,8080,18083,5432,2019")).split(",") if item.strip()]
BR_UDP_PORTS_RAW = [item.strip() for item in os.getenv("BR_NFT_UDP_PORTS", os.getenv("BR_FIREWALL_UDP_PORTS", "443,80,8000,8080,18083,5432,2019")).split(",") if item.strip()]
WEB_TCP_PORTS_RAW = [item.strip() for item in os.getenv("BR_NFT_ALLOWED_WEB_TCP_PORTS", os.getenv("BR_FIREWALL_ALLOWED_WEB_TCP_PORTS", "80,443")).split(",") if item.strip()]
EXPECTED_LOOPBACK_TCP = {
    item.strip()
    for item in os.getenv("BR_NFT_EXPECTED_LOOPBACK_TCP", os.getenv("BR_FIREWALL_EXPECTED_LOOPBACK_TCP", "127.0.0.1:18083")).split(",")
    if item.strip()
}
DEFAULT_DIRECT_HOSTS = "0.0.0.0,::,31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79"
DIRECT_HOSTS = {item.strip().strip("[]") for item in os.getenv("BR_NFT_DIRECT_HOSTS", os.getenv("BR_FIREWALL_DIRECT_HOSTS", DEFAULT_DIRECT_HOSTS)).split(",") if item.strip()}
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
INPUT_CHAINS = {"INPUT", "ufw-user-input", "ufw6-user-input"}
UNSUPPORTED_EXPR_KEYS = {"lookup", "map", "vmap", "dynset", "objref", "flow"}
MAX_CHAIN_TRAVERSAL_DEPTH = int(os.getenv("BR_NFT_MAX_CHAIN_TRAVERSAL_DEPTH", "12"))


def parse_ports(values: list[str]) -> tuple[set[int], list[str]]:
    ports: set[int] = set()
    invalid: list[str] = []
    for value in values:
        try:
            port = int(value)
        except ValueError:
            invalid.append(value[:32] or "empty")
            continue
        if not 1 <= port <= 65535:
            invalid.append(value[:32] or "empty")
            continue
        ports.add(port)
    return ports, invalid


BR_TCP_PORTS, INVALID_TCP_PORTS = parse_ports(BR_TCP_PORTS_RAW)
BR_UDP_PORTS, INVALID_UDP_PORTS = parse_ports(BR_UDP_PORTS_RAW)
WEB_TCP_PORTS, INVALID_WEB_TCP_PORTS = parse_ports(WEB_TCP_PORTS_RAW)


def load_context_direct_hosts() -> set[str]:
    hosts: set[str] = set()
    if not HOST_CONTEXT.exists() or HOST_CONTEXT.is_symlink():
        return hosts
    try:
        text = HOST_CONTEXT.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hosts
    for line in text.splitlines():
        if not (line.startswith("PUBLIC_IPV4=") or line.startswith("TAILSCALE_IPV4=")):
            continue
        value = line.split("=", 1)[1].strip().strip("[]")
        if value:
            hosts.add(value)
    return hosts


DIRECT_HOSTS.update(load_context_direct_hosts())


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def normalize_host(value: str) -> str:
    value = str(value).strip().strip("[]")
    if "/" in value:
        value = value.split("/", 1)[0]
    return value


def is_loopback_host(value: str) -> bool:
    return normalize_host(value) in LOOPBACK_HOSTS


def is_direct_host(value: str) -> bool:
    host = normalize_host(value)
    if host in LOOPBACK_HOSTS:
        return False
    if host in {"", "0.0.0.0", "::", "*"}:
        return True
    return host in DIRECT_HOSTS


def target_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "target"


def extract_ports(value: Any) -> set[int]:
    values = value if isinstance(value, list) else [value]
    ports: set[int] = set()
    for item in values:
        try:
            ports.add(int(item))
        except (TypeError, ValueError):
            continue
    return ports


def flatten_simple_values(value: Any) -> list[Any]:
    values: list[Any] = []
    if isinstance(value, list):
        for item in value:
            values.extend(flatten_simple_values(item))
    elif isinstance(value, dict):
        if "elem" in value:
            values.extend(flatten_simple_values(value["elem"]))
        elif "val" in value:
            values.extend(flatten_simple_values(value["val"]))
        elif "set" in value:
            values.extend(flatten_simple_values(value["set"]))
    elif isinstance(value, (str, int)):
        values.append(value)
    return values


def setref_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ["name", "set", "id"]:
            item = value.get(key)
            if item:
                return str(item)
    return ""


def expand_match_values(
    *,
    right: Any,
    family: str,
    table: str,
    set_index: dict[tuple[str, str, str], list[Any]],
    unsupported: set[str],
    meta: dict[str, Any],
) -> list[Any]:
    if isinstance(right, dict) and "setref" in right:
        name = setref_name(right.get("setref"))
        values = set_index.get((family, table, name), []) if name else []
        if values:
            meta["expanded_setrefs"].add(name)
            return values
        if name:
            meta["unresolved_setrefs"].add(name)
        unsupported.add("setref")
        return []
    if isinstance(right, dict) and "set" in right:
        values = flatten_simple_values(right.get("set"))
        if values:
            meta["expanded_sets"] += 1
            return values
        unsupported.add("set")
        return []
    if isinstance(right, dict):
        unsupported.add("complex_value")
        return []
    return right if isinstance(right, list) else [right]


def first_port(ports: set[int]) -> int:
    return min(ports) if ports else 0


def is_expected_loopback_nat(dest: str, proto: str, dport: int) -> bool:
    if proto != "tcp" or not is_loopback_host(dest):
        return False
    return "%s:%d" % (normalize_host(dest), dport) in EXPECTED_LOOPBACK_TCP


def parse_rule(rule: dict[str, Any], set_index: dict[tuple[str, str, str], list[Any]] | None = None) -> dict[str, Any]:
    set_index = set_index or {}
    family = str(rule.get("family") or "")
    table = str(rule.get("table") or "")
    meta: dict[str, Any] = {
        "protos": set(),
        "tcp_dports": set(),
        "udp_dports": set(),
        "dest_hosts": set(),
        "out_ifaces": set(),
        "in_ifaces": set(),
        "actions": set(),
        "verdict_targets": set(),
        "xt_targets": set(),
        "unsupported_exprs": set(),
        "expanded_setrefs": set(),
        "unresolved_setrefs": set(),
        "expanded_sets": 0,
    }
    for expr in rule.get("expr") or []:
        if not isinstance(expr, dict):
            continue
        mark_unsupported_exprs(expr, meta["unsupported_exprs"])
        if "match" in expr and isinstance(expr["match"], dict):
            match = expr["match"]
            left = match.get("left")
            right = match.get("right")
            if isinstance(left, dict) and "payload" in left and isinstance(left["payload"], dict):
                payload = left["payload"]
                protocol = str(payload.get("protocol") or "")
                field = str(payload.get("field") or "")
                values = expand_match_values(right=right, family=family, table=table, set_index=set_index, unsupported=meta["unsupported_exprs"], meta=meta)
                if field == "dport" and protocol in {"tcp", "udp"}:
                    ports = extract_ports(values)
                    meta["%s_dports" % protocol].update(ports)
                    if not ports and meta["unresolved_setrefs"]:
                        meta["unknown_%s_dports" % protocol] = True
                    meta["protos"].add(protocol)
                elif field == "protocol" and protocol in {"ip", "ip6"}:
                    for value in values:
                        if str(value) in {"tcp", "udp"}:
                            meta["protos"].add(str(value))
                elif field == "daddr" and protocol in {"ip", "ip6"}:
                    for value in values:
                        if value:
                            meta["dest_hosts"].add(str(value).strip("[]"))
            elif isinstance(left, dict) and "meta" in left and isinstance(left["meta"], dict):
                key = str(left["meta"].get("key") or "")
                values = expand_match_values(right=right, family=family, table=table, set_index=set_index, unsupported=meta["unsupported_exprs"], meta=meta)
                if key == "l4proto":
                    for value in values:
                        if str(value) in {"tcp", "udp"}:
                            meta["protos"].add(str(value))
                elif key == "oifname":
                    for value in values:
                        if value:
                            meta["out_ifaces"].add(str(value))
                elif key == "iifname":
                    for value in values:
                        if value:
                            meta["in_ifaces"].add(str(value))
        for action in {"accept", "drop", "jump", "goto", "return", "reject", "dnat", "redirect", "masquerade"}:
            if action in expr:
                meta["actions"].add(action)
                if action in {"jump", "goto"}:
                    target = expr.get(action)
                    if isinstance(target, dict):
                        target_value = str(target.get("target") or "")
                    else:
                        target_value = str(target or "")
                    if target_value:
                        meta["verdict_targets"].add("%s:%s" % (action, target_value))
        if "xt" in expr and isinstance(expr["xt"], dict):
            target = str(expr["xt"].get("name") or "")
            if target:
                meta["xt_targets"].add(target.upper())
                meta["actions"].add("xt:%s" % target.upper())
    return meta


def copy_meta(meta: dict[str, Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for key, value in meta.items():
        copied[key] = set(value) if isinstance(value, set) else value
    return copied


def effective_meta(rule_meta: dict[str, Any], inherited: dict[str, Any] | None) -> dict[str, Any]:
    if not inherited:
        return copy_meta(rule_meta)
    meta = copy_meta(rule_meta)
    current_has_ports = bool(rule_meta["tcp_dports"] or rule_meta["udp_dports"])
    for proto_key in ["tcp_dports", "udp_dports"]:
        parent_ports = set(inherited.get(proto_key, set()))
        current_ports = set(rule_meta.get(proto_key, set()))
        if parent_ports and current_ports:
            meta[proto_key] = parent_ports & current_ports
        elif parent_ports and not current_has_ports:
            meta[proto_key] = parent_ports
    for key in ["protos", "dest_hosts", "out_ifaces", "in_ifaces"]:
        if not meta[key] and inherited.get(key):
            meta[key] = set(inherited[key])
    return meta


def relevant_ports(rule_meta: dict[str, Any]) -> bool:
    return bool(rule_meta["tcp_dports"] & (BR_TCP_PORTS | WEB_TCP_PORTS)) or bool(rule_meta["udp_dports"] & BR_UDP_PORTS) or bool(rule_meta.get("unknown_tcp_dports")) or bool(rule_meta.get("unknown_udp_dports"))


def context_kind(table: str, chain: str, rule_meta: dict[str, Any], has_accept: bool, has_nat: bool, inherited_kind: str = "") -> str:
    if inherited_kind:
        return inherited_kind
    has_jump_or_goto = bool({"jump", "goto"} & rule_meta["actions"])
    if table == "filter" and chain in INPUT_CHAINS and (has_accept or has_jump_or_goto) and relevant_ports(rule_meta):
        return "input"
    if table == "nat" and (has_nat or has_jump_or_goto) and relevant_ports(rule_meta):
        return "nat"
    return ""


def split_verdict_target(value: str) -> tuple[str, str]:
    if ":" not in value:
        return "jump", value
    action, target = value.split(":", 1)
    return action, target


def mark_unsupported_exprs(value: Any, unsupported: set[str]) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in UNSUPPORTED_EXPR_KEYS:
                unsupported.add(key)
            mark_unsupported_exprs(nested, unsupported)
    elif isinstance(value, list):
        for item in value:
            mark_unsupported_exprs(item, unsupported)


def relevant_context(table: str, chain: str, rule_meta: dict[str, Any], has_accept: bool, has_nat: bool) -> bool:
    has_relevant_input = False
    if table == "filter" and chain in INPUT_CHAINS and (has_accept or bool({"jump", "goto"} & rule_meta["actions"])):
        has_relevant_input = relevant_ports(rule_meta)
    has_relevant_nat = False
    if table == "nat" and (has_nat or bool({"jump", "goto"} & rule_meta["actions"])):
        has_relevant_nat = relevant_ports(rule_meta)
    return has_relevant_input or has_relevant_nat


def is_docker_bridge_rule(rule_meta: dict[str, Any], chain: str) -> bool:
    if chain.startswith("DOCKER"):
        return True
    for iface in rule_meta["out_ifaces"] | rule_meta["in_ifaces"]:
        if iface == "docker0" or iface.startswith("br-"):
            return True
    return False


def nft_ruleset(findings: list[str]) -> tuple[int, dict[str, Any]]:
    proc = run(["sudo", "-n", "nft", "-j", "list", "ruleset"])
    if proc.returncode != 0:
        findings.append("nft_ruleset_unavailable_rc=%d" % proc.returncode)
        return 1, {}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        findings.append("nft_ruleset_json_invalid")
        return 1, {}
    if not isinstance(data, dict):
        findings.append("nft_ruleset_json_not_object")
        return 1, {}
    return 1, data


def evaluate_rule(
    *,
    family: str,
    table: str,
    chain: str,
    rule_meta: dict[str, Any],
    chain_rules: dict[tuple[str, str, str], list[dict[str, Any]]],
    set_index: dict[tuple[str, str, str], list[Any]],
    counters: dict[str, int],
    findings: list[str],
    inherited_meta: dict[str, Any] | None = None,
    inherited_kind: str = "",
    path: tuple[str, ...] = (),
    depth: int = 0,
) -> None:
    meta = effective_meta(rule_meta, inherited_meta)
    if is_docker_bridge_rule(meta, chain):
        counters["docker_bridge_rules"] += 1
    if meta.get("expanded_setrefs"):
        counters["expanded_setref_rules"] += 1
        counters["expanded_setrefs"] += len(meta["expanded_setrefs"])
    if meta.get("expanded_sets"):
        counters["expanded_anonymous_set_rules"] += 1
        counters["expanded_anonymous_sets"] += int(meta["expanded_sets"])
    if meta.get("unresolved_setrefs") and relevant_ports(meta):
        counters["unresolved_setref_rules"] += 1
        findings.append("nft_%s_unresolved_setref_%s" % (family or "family", target_id("_".join(sorted(meta["unresolved_setrefs"])))))

    has_accept = "accept" in meta["actions"]
    has_nat = bool({"dnat", "redirect"} & meta["actions"]) or bool({"DNAT", "REDIRECT"} & meta["xt_targets"])
    if bool({"DNAT", "REDIRECT"} & meta["xt_targets"]):
        counters["xt_nat_rules"] += 1
    if bool({"dnat", "redirect"} & meta["actions"]):
        counters["native_nat_rules"] += 1

    kind = context_kind(table, chain, meta, has_accept, has_nat, inherited_kind)
    is_relevant = bool(kind and relevant_ports(meta))

    if meta["unsupported_exprs"] and is_relevant:
        counters["unsupported_expr_rules"] += 1
        expr_label = target_id("_".join(sorted(meta["unsupported_exprs"])))
        findings.append("nft_%s_unsupported_expr_%s" % (family or "family", expr_label))

    has_jump_or_goto = bool({"jump", "goto"} & meta["actions"])
    if has_jump_or_goto and is_relevant:
        for verdict_target in sorted(meta["verdict_targets"]):
            action, target = split_verdict_target(verdict_target)
            target_key = (family, table, target)
            path_item = "%s/%s/%s" % (family, table, target)
            if depth >= MAX_CHAIN_TRAVERSAL_DEPTH or path_item in path:
                counters["chain_traversal_cycles"] += 1
                findings.append("nft_%s_chain_traversal_cycle_%s" % (family or "family", target_id(target)))
                continue
            target_rules = chain_rules.get(target_key)
            if target_rules is None:
                counters["unresolved_jump_rules"] += 1
                findings.append("nft_%s_unresolved_%s_%s" % (family or "family", action, target_id(target)))
                continue
            counters["traversed_jump_rules"] += 1
            for target_rule in target_rules:
                counters["chain_traversal_rules"] += 1
                evaluate_rule(
                    family=family,
                    table=table,
                    chain=target,
                    rule_meta=parse_rule(target_rule, set_index),
                    chain_rules=chain_rules,
                    set_index=set_index,
                    counters=counters,
                    findings=findings,
                    inherited_meta=meta,
                    inherited_kind=kind,
                    path=path + (path_item,),
                    depth=depth + 1,
                )

    for proto, ports in [("tcp", meta["tcp_dports"]), ("udp", meta["udp_dports"])]:
        for dport in sorted(ports):
            if has_accept and kind == "input":
                counters["input_accepts"] += 1
                if proto == "tcp" and dport in WEB_TCP_PORTS:
                    counters["web_exposure_rules"] += 1
                    continue
                if (proto == "tcp" and dport in BR_TCP_PORTS) or (proto == "udp" and dport in BR_UDP_PORTS):
                    counters["unexpected_input_accepts"] += 1
                    findings.append("nft_%s_unexpected_input_accept_%s_%d" % (family or "family", proto, dport))

            relevant_dport = (proto == "tcp" and dport in (BR_TCP_PORTS | WEB_TCP_PORTS)) or (proto == "udp" and dport in BR_UDP_PORTS)
            if not has_nat or kind != "nat" or not relevant_dport:
                continue
            counters["nat_rules"] += 1
            dests = meta["dest_hosts"] or {""}
            if any(is_expected_loopback_nat(dest, proto, dport) for dest in dests):
                counters["expected_loopback_nat"] += 1
                continue
            if proto == "tcp" and dport in WEB_TCP_PORTS and any(is_direct_host(dest) for dest in dests):
                counters["web_exposure_rules"] += 1
                continue
            if any(is_direct_host(dest) for dest in dests):
                counters["unexpected_nat_rules"] += 1
                findings.append("nft_%s_unexpected_nat_%s_%s_%d" % (family or "family", proto, target_id(next(iter(dests)) or "all"), dport))


def analyze(data: dict[str, Any], findings: list[str]) -> dict[str, int]:
    counters = {
        "tables": 0,
        "chains": 0,
        "rules": 0,
        "input_accepts": 0,
        "unexpected_input_accepts": 0,
        "nat_rules": 0,
        "expected_loopback_nat": 0,
        "unexpected_nat_rules": 0,
        "web_exposure_rules": 0,
        "docker_bridge_rules": 0,
        "xt_nat_rules": 0,
        "native_nat_rules": 0,
        "unsupported_expr_rules": 0,
        "set_objects": 0,
        "unsupported_jump_rules": 0,
        "traversed_jump_rules": 0,
        "unresolved_jump_rules": 0,
        "chain_traversal_rules": 0,
        "chain_traversal_cycles": 0,
        "expanded_setref_rules": 0,
        "expanded_setrefs": 0,
        "expanded_anonymous_set_rules": 0,
        "expanded_anonymous_sets": 0,
        "unresolved_setref_rules": 0,
        "set_elements": 0,
    }
    rule_items: list[dict[str, Any]] = []
    chain_rules: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    set_index: dict[tuple[str, str, str], list[Any]] = {}
    for item in data.get("nftables") or []:
        if not isinstance(item, dict):
            continue
        if "set" in item:
            counters["set_objects"] += 1
            set_obj = item.get("set")
            if isinstance(set_obj, dict):
                family = str(set_obj.get("family") or "")
                table = str(set_obj.get("table") or "")
                name = str(set_obj.get("name") or "")
                elems = flatten_simple_values(set_obj.get("elem"))
                counters["set_elements"] += len(elems)
                if family and table and name and elems:
                    set_index[(family, table, name)] = elems
            continue
        if "map" in item:
            counters["set_objects"] += 1
            continue
        if "table" in item:
            counters["tables"] += 1
            continue
        if "chain" in item:
            counters["chains"] += 1
            continue
        rule = item.get("rule")
        if not isinstance(rule, dict):
            continue
        counters["rules"] += 1
        rule_items.append(rule)
        chain_key = (str(rule.get("family") or ""), str(rule.get("table") or ""), str(rule.get("chain") or ""))
        chain_rules.setdefault(chain_key, []).append(rule)
    for rule in rule_items:
        family = str(rule.get("family") or "")
        table = str(rule.get("table") or "")
        chain = str(rule.get("chain") or "")
        evaluate_rule(
            family=family,
            table=table,
            chain=chain,
            rule_meta=parse_rule(rule, set_index),
            chain_rules=chain_rules,
            set_index=set_index,
            counters=counters,
            findings=findings,
        )
    return counters


def synthetic_rule(family: str, table: str, chain: str, proto: str, dport: int, action: str, dest: str = "") -> dict[str, Any]:
    expr: list[dict[str, Any]] = []
    if dest:
        expr.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip6" if ":" in dest else "ip", "field": "daddr"}}, "right": dest}})
    expr.append({"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": dport}})
    expr.append({"counter": {"packets": 0, "bytes": 0}})
    if action.startswith("xt:"):
        expr.append({"xt": {"type": "target", "name": action.split(":", 1)[1]}})
    else:
        expr.append({action: None})
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": expr}}


def synthetic_unsupported_rule(family: str, table: str, chain: str, proto: str, dport: int, action: str) -> dict[str, Any]:
    item = synthetic_rule(family, table, chain, proto, dport, action)
    item["rule"]["expr"].insert(0, {"match": {"op": "==", "left": {"lookup": {"source": {"payload": {"protocol": proto, "field": "dport"}}, "set": "br_ports"}}, "right": True}})
    return item


def synthetic_set_object(family: str, table: str, name: str, elems: list[Any]) -> dict[str, Any]:
    return {"set": {"family": family, "table": table, "name": name, "type": "inet_service", "elem": elems}}


def synthetic_setref_rule(family: str, table: str, chain: str, proto: str, set_name: str, action: str) -> dict[str, Any]:
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": {"setref": {"name": set_name}}}},
        {"counter": {"packets": 0, "bytes": 0}},
        {action: None},
    ]}}


def synthetic_anonymous_set_rule(family: str, table: str, chain: str, proto: str, elems: list[Any], action: str) -> dict[str, Any]:
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": {"set": elems}}},
        {"counter": {"packets": 0, "bytes": 0}},
        {action: None},
    ]}}


def synthetic_jump_rule(family: str, table: str, chain: str, proto: str, dport: int, target: str, action: str = "jump") -> dict[str, Any]:
    return synthetic_rule(family, table, chain, proto, dport, "jump", "") | {"rule": {"family": family, "table": table, "chain": chain, "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": dport}},
        {"counter": {"packets": 0, "bytes": 0}},
        {action: {"target": target}},
    ]}}


def synthetic_target_rule(family: str, table: str, chain: str, action: str, dest: str = "") -> dict[str, Any]:
    expr: list[dict[str, Any]] = []
    if dest:
        expr.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip6" if ":" in dest else "ip", "field": "daddr"}}, "right": dest}})
    if action.startswith("xt:"):
        expr.append({"xt": {"type": "target", "name": action.split(":", 1)[1]}})
    else:
        expr.append({action: None})
    return {"rule": {"family": family, "table": table, "chain": chain, "expr": expr}}


def self_test() -> tuple[bool, str]:
    cases: list[tuple[str, dict[str, Any], bool]] = [
        (
            "bad_input_tcp_8000",
            {"nftables": [synthetic_rule("ip", "filter", "ufw-user-input", "tcp", 8000, "accept")]},
            False,
        ),
        (
            "good_input_web_443",
            {"nftables": [synthetic_rule("ip", "filter", "ufw-user-input", "tcp", 443, "accept")]},
            True,
        ),
        (
            "good_loopback_nat_18083",
            {"nftables": [synthetic_rule("ip", "nat", "DOCKER", "tcp", 18083, "xt:DNAT", "127.0.0.1")]},
            True,
        ),
        (
            "bad_direct_nat_18083",
            {"nftables": [synthetic_rule("ip", "nat", "DOCKER", "tcp", 18083, "xt:DNAT", "31.70.74.139")]},
            False,
        ),
        (
            "good_direct_web_nat_80",
            {"nftables": [synthetic_rule("ip", "nat", "DOCKER", "tcp", 80, "xt:DNAT", "31.70.74.139")]},
            True,
        ),
        (
            "bad_direct_udp_443",
            {"nftables": [synthetic_rule("ip", "filter", "ufw-user-input", "udp", 443, "accept")]},
            False,
        ),
        (
            "bad_unsupported_lookup_input_8000",
            {"nftables": [synthetic_unsupported_rule("ip", "filter", "ufw-user-input", "tcp", 8000, "accept")]},
            False,
        ),
        (
            "good_unsupported_lookup_irrelevant_9999",
            {"nftables": [synthetic_unsupported_rule("ip", "filter", "ufw-user-input", "tcp", 9999, "accept")]},
            True,
        ),
        (
            "bad_unresolved_jump_input_8000",
            {"nftables": [synthetic_jump_rule("ip", "filter", "ufw-user-input", "tcp", 8000, "some-chain")]},
            False,
        ),
        (
            "good_jump_input_irrelevant_9999",
            {"nftables": [synthetic_jump_rule("ip", "filter", "ufw-user-input", "tcp", 9999, "some-chain")]},
            True,
        ),
        (
            "bad_resolved_jump_input_8000_accept",
            {"nftables": [synthetic_jump_rule("ip", "filter", "ufw-user-input", "tcp", 8000, "br-chain"), synthetic_target_rule("ip", "filter", "br-chain", "accept")]},
            False,
        ),
        (
            "good_resolved_jump_web_443_accept",
            {"nftables": [synthetic_jump_rule("ip", "filter", "ufw-user-input", "tcp", 443, "br-chain"), synthetic_target_rule("ip", "filter", "br-chain", "accept")]},
            True,
        ),
        (
            "bad_resolved_goto_udp_443_accept",
            {"nftables": [synthetic_jump_rule("ip", "filter", "ufw-user-input", "udp", 443, "br-chain", "goto"), synthetic_target_rule("ip", "filter", "br-chain", "accept")]},
            False,
        ),
        (
            "good_resolved_loopback_nat_jump_18083",
            {"nftables": [synthetic_jump_rule("ip", "nat", "PREROUTING", "tcp", 18083, "br-nat"), synthetic_target_rule("ip", "nat", "br-nat", "xt:DNAT", "127.0.0.1")]},
            True,
        ),
        (
            "bad_resolved_direct_nat_jump_18083",
            {"nftables": [synthetic_jump_rule("ip", "nat", "PREROUTING", "tcp", 18083, "br-nat"), synthetic_target_rule("ip", "nat", "br-nat", "xt:DNAT", "31.70.74.139")]},
            False,
        ),
        (
            "bad_named_set_input_8000",
            {"nftables": [synthetic_set_object("ip", "filter", "br_ports", [8000]), synthetic_setref_rule("ip", "filter", "ufw-user-input", "tcp", "br_ports", "accept")]},
            False,
        ),
        (
            "good_named_set_input_web_443",
            {"nftables": [synthetic_set_object("ip", "filter", "web_ports", [443]), synthetic_setref_rule("ip", "filter", "ufw-user-input", "tcp", "web_ports", "accept")]},
            True,
        ),
        (
            "bad_anonymous_set_udp_443",
            {"nftables": [synthetic_anonymous_set_rule("ip", "filter", "ufw-user-input", "udp", [443], "accept")]},
            False,
        ),
        (
            "bad_unresolved_setref_input",
            {"nftables": [synthetic_setref_rule("ip", "filter", "ufw-user-input", "tcp", "missing_ports", "accept")]},
            False,
        ),
    ]
    failed: list[str] = []
    for name, data, should_pass in cases:
        findings: list[str] = []
        analyze(data, findings)
        passed = not findings
        if passed != should_pass:
            failed.append(name)
    if failed:
        return False, "nft_selftest_status=failed cases=%d failed=%d failed_cases=%s" % (len(cases), len(failed), ":".join(failed))
    return True, "nft_selftest_status=ok cases=%d failed=0" % len(cases)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen host nftables metadata for BR ports")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument("--self-test", action="store_true", help="run synthetic parser/policy self-test")
    args = parser.parse_args()

    if args.self_test:
        ok, line = self_test()
        print(line)
        return 0 if ok else 1

    checks = 0
    findings: list[str] = []
    for invalid_label, values in [("tcp", INVALID_TCP_PORTS), ("udp", INVALID_UDP_PORTS), ("web_tcp", INVALID_WEB_TCP_PORTS)]:
        checks += 1
        if values:
            findings.append("nft_invalid_%s_ports=%d" % (invalid_label, len(values)))
    checks += 1
    if not DIRECT_HOSTS:
        findings.append("nft_no_direct_hosts_configured")

    nft_checks, data = nft_ruleset(findings)
    checks += nft_checks
    counters = analyze(data, findings) if data else {"tables": 0, "chains": 0, "rules": 0}
    checks += int(counters.get("rules", 0))

    status = "ok" if not findings else "failed"
    summary = (
        "host_nft_br_ports_status=%s checks=%d findings=%d direct_hosts=%d tables=%d chains=%d rules=%d input_accepts=%d unexpected_input_accepts=%d nat_rules=%d expected_loopback_nat=%d unexpected_nat_rules=%d web_exposure_rules=%d docker_bridge_rules=%d xt_nat_rules=%d native_nat_rules=%d unsupported_expr_rules=%d unsupported_jump_rules=%d traversed_jump_rules=%d unresolved_jump_rules=%d chain_traversal_rules=%d chain_traversal_cycles=%d set_objects=%d set_elements=%d expanded_setref_rules=%d expanded_setrefs=%d expanded_anonymous_set_rules=%d expanded_anonymous_sets=%d unresolved_setref_rules=%d"
        % (
            status,
            checks,
            len(findings),
            len(DIRECT_HOSTS),
            int(counters.get("tables", 0)),
            int(counters.get("chains", 0)),
            int(counters.get("rules", 0)),
            int(counters.get("input_accepts", 0)),
            int(counters.get("unexpected_input_accepts", 0)),
            int(counters.get("nat_rules", 0)),
            int(counters.get("expected_loopback_nat", 0)),
            int(counters.get("unexpected_nat_rules", 0)),
            int(counters.get("web_exposure_rules", 0)),
            int(counters.get("docker_bridge_rules", 0)),
            int(counters.get("xt_nat_rules", 0)),
            int(counters.get("native_nat_rules", 0)),
            int(counters.get("unsupported_expr_rules", 0)),
            int(counters.get("unsupported_jump_rules", 0)),
            int(counters.get("traversed_jump_rules", 0)),
            int(counters.get("unresolved_jump_rules", 0)),
            int(counters.get("chain_traversal_rules", 0)),
            int(counters.get("chain_traversal_cycles", 0)),
            int(counters.get("set_objects", 0)),
            int(counters.get("set_elements", 0)),
            int(counters.get("expanded_setref_rules", 0)),
            int(counters.get("expanded_setrefs", 0)),
            int(counters.get("expanded_anonymous_set_rules", 0)),
            int(counters.get("expanded_anonymous_sets", 0)),
            int(counters.get("unresolved_setref_rules", 0)),
        )
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
