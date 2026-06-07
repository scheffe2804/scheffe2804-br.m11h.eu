#!/usr/bin/env python3
"""Static compose source hardening guard for BR-Wissen.

This guard reads only the local docker-compose.yml source file and validates
non-secret structural keys. It intentionally does not call ``docker compose
config`` because that would expand env_file values. It never prints environment
values, credential contents, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - operational dependency guard
    yaml = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT / "docker-compose.yml"

EXPECTED_SERVICES = {"db", "app", "worker", "proxy", "cloudflared"}
REQUIRED_NO_NEW_PRIVILEGES = "no-new-privileges:true"

POLICY: dict[str, dict[str, Any]] = {
    "db": {
        "user": "postgres",
        "read_only": True,
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "noexec", "nosuid", "nodev", "size=128m"],
            "/var/run/postgresql": ["rw", "nosuid", "nodev", "size=32m"],
        },
        "pids_limit": 256,
        "mem_limit": "2g",
        "cpus": 1.0,
        "volumes": {
            "br_pgdata:/var/lib/postgresql/data": "rw",
            "./db/init:/docker-entrypoint-initdb.d": "ro",
        },
        "ports": [],
        "expose": [],
    },
    "app": {
        "user": "1000:1000",
        "read_only": True,
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "nosuid", "nodev", "size=512m"],
            "/var/tmp": ["rw", "nosuid", "nodev", "size=256m"],
        },
        "pids_limit": 256,
        "mem_limit": "2g",
        "cpus": 1.0,
        "volumes": {
            "/srv/br-wissensdatenbank:/srv/br-wissensdatenbank": "rw",
            "/srv/br-wissensdatenbank/secrets:/run/br-secrets": "ro",
        },
        "ports": [],
        "expose": ["8000"],
    },
    "worker": {
        "user": "1000:1000",
        "read_only": True,
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "nosuid", "nodev", "size=1g"],
            "/var/tmp": ["rw", "nosuid", "nodev", "size=512m"],
        },
        "pids_limit": 256,
        "mem_limit": "2g",
        "cpus": 1.0,
        "volumes": {
            "/srv/br-wissensdatenbank:/srv/br-wissensdatenbank": "rw",
            "/srv/br-wissensdatenbank/secrets:/run/br-secrets": "ro",
        },
        "ports": [],
        "expose": [],
    },
    "proxy": {
        "user": "1001:127",
        "read_only": True,
        "cap_drop_all": False,
        "tmpfs": {
            "/tmp": ["rw", "noexec", "nosuid", "nodev", "size=64m"],
            "/run": ["rw", "noexec", "nosuid", "nodev", "size=32m"],
            "/data": ["rw", "nosuid", "nodev", "size=64m"],
            "/config": ["rw", "nosuid", "nodev", "size=64m"],
        },
        "pids_limit": 128,
        "mem_limit": "512m",
        "cpus": 0.5,
        "volumes": {
            "./proxy/Caddyfile:/etc/caddy/Caddyfile": "ro",
        },
        "ports": ["127.0.0.1:18083:8080"],
        "expose": [],
    },
    "cloudflared": {
        "user": None,
        "read_only": True,
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "noexec", "nosuid", "nodev", "size=64m"],
            "/run": ["rw", "noexec", "nosuid", "nodev", "size=32m"],
        },
        "pids_limit": 128,
        "mem_limit": "512m",
        "cpus": 0.5,
        "volumes": {
            "./cloudflared/config.yml:/etc/cloudflared/config.yml": "ro",
            "/srv/br-wissensdatenbank/secrets/cloudflared:/run/br-secrets/cloudflared": "ro",
        },
        "ports": [],
        "expose": [],
    },
}


def normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def normalize_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def volume_mode(value: str) -> tuple[str, str]:
    parts = value.split(":")
    if len(parts) >= 3 and parts[-1] in {"ro", "rw"}:
        return ":".join(parts[:-1]), parts[-1]
    return value, "rw"


def tmpfs_entry(value: str) -> tuple[str, set[str]]:
    parts = [part.strip() for part in value.split(":") if part.strip()]
    if not parts:
        return "", set()
    path = parts[0]
    options: set[str] = set()
    if len(parts) > 1:
        options = {part.strip() for part in parts[1].split(",") if part.strip()}
    return path, options


def load_compose() -> tuple[dict[str, Any], list[str]]:
    findings: list[str] = []
    if yaml is None:
        return {}, ["pyyaml_unavailable"]
    if not COMPOSE_FILE.exists():
        return {}, ["compose_file_missing"]
    try:
        data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}, ["compose_yaml_parse_failed"]
    if not isinstance(data, dict):
        findings.append("compose_yaml_not_mapping")
        return {}, findings
    return data, findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Check static BR-Wissen compose hardening source")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    data, load_findings = load_compose()
    findings.extend(load_findings)
    checks += 1

    services = data.get("services") if isinstance(data, dict) else {}
    if not isinstance(services, dict):
        services = {}
        findings.append("services_missing")
    checks += 1

    actual_services = set(str(name) for name in services.keys())
    if actual_services != EXPECTED_SERVICES:
        findings.append("service_set_mismatch")

    read_only_count = 0
    no_new_privileges_count = 0
    cap_drop_all_count = 0
    resource_limited_count = 0
    tmpfs_services = 0
    tmpfs_paths = 0
    expected_port_bindings = 0
    unexpected_port_bindings = 0
    expected_ro_volumes = 0
    writable_required_volumes = 0

    for name, policy in POLICY.items():
        svc = services.get(name)
        checks += 1
        if not isinstance(svc, dict):
            findings.append("service_missing=%s" % name)
            continue

        checks += 1
        if bool(svc.get("read_only")) is True:
            read_only_count += 1
        else:
            findings.append("read_only_missing=%s" % name)

        expected_user = policy["user"]
        checks += 1
        if expected_user is None:
            if "user" in svc:
                findings.append("unexpected_user=%s" % name)
        elif str(svc.get("user") or "") != expected_user:
            findings.append("user_mismatch=%s" % name)

        security_opt = normalize_string_list(svc.get("security_opt"))
        checks += 1
        if REQUIRED_NO_NEW_PRIVILEGES in security_opt:
            no_new_privileges_count += 1
        else:
            findings.append("no_new_privileges_missing=%s" % name)

        cap_drop = normalize_string_list(svc.get("cap_drop"))
        checks += 1
        if policy["cap_drop_all"]:
            if cap_drop == ["ALL"]:
                cap_drop_all_count += 1
            else:
                findings.append("cap_drop_all_missing=%s" % name)
        elif cap_drop:
            findings.append("unexpected_cap_drop=%s" % name)

        tmpfs = normalize_string_list(svc.get("tmpfs"))
        checks += 1
        actual_tmpfs = dict(tmpfs_entry(item) for item in tmpfs)
        expected_tmpfs = policy["tmpfs"]
        if set(actual_tmpfs) == set(expected_tmpfs):
            tmpfs_services += 1
        else:
            findings.append("tmpfs_missing=%s" % name)
        for path, required_options in expected_tmpfs.items():
            checks += 1
            actual_options = actual_tmpfs.get(path, set())
            if not actual_options:
                findings.append("tmpfs_path_missing=%s" % name)
            elif all(item in actual_options for item in required_options):
                tmpfs_paths += 1
            else:
                findings.append("tmpfs_options_mismatch=%s" % name)

        checks += 1
        if int(svc.get("pids_limit") or 0) == int(policy["pids_limit"]):
            pass
        else:
            findings.append("pids_limit_mismatch=%s" % name)

        checks += 1
        if str(svc.get("mem_limit") or "") != str(policy["mem_limit"]):
            findings.append("mem_limit_mismatch=%s" % name)

        checks += 1
        if abs(normalize_number(svc.get("cpus")) - float(policy["cpus"])) > 0.001:
            findings.append("cpus_mismatch=%s" % name)
        else:
            resource_limited_count += 1

        volumes = normalize_string_list(svc.get("volumes"))
        actual_volume_modes = dict(volume_mode(item) for item in volumes)
        checks += 1
        expected_volumes = policy["volumes"]
        if set(actual_volume_modes) != set(expected_volumes):
            findings.append("volume_set_mismatch=%s" % name)
        for volume, mode in expected_volumes.items():
            checks += 1
            actual_mode = actual_volume_modes.get(volume)
            if actual_mode != mode:
                findings.append("volume_mode_mismatch=%s" % name)
            elif mode == "ro":
                expected_ro_volumes += 1
            elif mode == "rw":
                writable_required_volumes += 1

        ports = normalize_string_list(svc.get("ports"))
        checks += 1
        expected_ports = set(policy["ports"])
        if set(ports) != expected_ports:
            unexpected_port_bindings += 1
            findings.append("ports_mismatch=%s" % name)
        else:
            expected_port_bindings += len(expected_ports)

        expose = normalize_string_list(svc.get("expose"))
        checks += 1
        if set(expose) != set(policy["expose"]):
            findings.append("expose_mismatch=%s" % name)

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "compose_source_hardening_status=%s checks=%d findings=%d services=%d read_only=%d no_new_privileges=%d cap_drop_all=%d resource_limited=%d tmpfs_services=%d tmpfs_paths=%d expected_port_bindings=%d unexpected_port_bindings=%d expected_ro_volumes=%d writable_required_volumes=%d"
            % (
                status,
                checks,
                len(findings),
                len(EXPECTED_SERVICES),
                read_only_count,
                no_new_privileges_count,
                cap_drop_all_count,
                resource_limited_count,
                tmpfs_services,
                tmpfs_paths,
                expected_port_bindings,
                unexpected_port_bindings,
                expected_ro_volumes,
                writable_required_volumes,
            )
        )
    else:
        print("compose_source_hardening_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("services=%d" % len(EXPECTED_SERVICES))
        print("read_only=%d" % read_only_count)
        print("no_new_privileges=%d" % no_new_privileges_count)
        print("cap_drop_all=%d" % cap_drop_all_count)
        print("resource_limited=%d" % resource_limited_count)
        print("tmpfs_services=%d" % tmpfs_services)
        print("tmpfs_paths=%d" % tmpfs_paths)
        print("expected_port_bindings=%d" % expected_port_bindings)
        print("unexpected_port_bindings=%d" % unexpected_port_bindings)
        print("expected_ro_volumes=%d" % expected_ro_volumes)
        print("writable_required_volumes=%d" % writable_required_volumes)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
