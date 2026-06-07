#!/usr/bin/env python3
"""Read-only container hardening metadata guard for BR-Wissen.

The guard inspects Docker metadata only. It never reads environment values,
container logs, mounted file contents, dumps, answers, source documents or
credential files.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DOCKER = Path("/usr/bin/docker")
EXPECTED_CONTAINERS = {
    "br-wissen-app": {
        "network": "br-wissen-internal",
        "port_bindings": set(),
        "user": "1000:1000",
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "nosuid", "nodev", "size=512m"],
            "/var/tmp": ["rw", "nosuid", "nodev", "size=256m"],
        },
        "mounts": {
            "/srv/br-wissensdatenbank": "rw",
            "/run/br-secrets": "ro",
        },
    },
    "br-wissen-db": {
        "network": "br-wissen-internal",
        "port_bindings": set(),
        "user": "postgres",
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "noexec", "nosuid", "nodev", "size=128m"],
            "/var/run/postgresql": ["rw", "nosuid", "nodev", "size=32m"],
        },
        "mounts": {
            "/var/lib/postgresql/data": "rw",
            "/docker-entrypoint-initdb.d": "ro",
        },
    },
    "br-wissen-worker": {
        "network": "br-wissen-internal",
        "port_bindings": set(),
        "user": "1000:1000",
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "nosuid", "nodev", "size=1g"],
            "/var/tmp": ["rw", "nosuid", "nodev", "size=512m"],
        },
        "mounts": {
            "/srv/br-wissensdatenbank": "rw",
            "/run/br-secrets": "ro",
        },
    },
    "br-wissen-proxy": {
        "network": "br-wissen-internal",
        "port_bindings": {"8080/tcp"},
        "user": "1001:127",
        "cap_drop_all": False,
        "tmpfs": {
            "/tmp": ["rw", "noexec", "nosuid", "nodev", "size=64m"],
            "/run": ["rw", "noexec", "nosuid", "nodev", "size=32m"],
            "/data": ["rw", "nosuid", "nodev", "size=64m"],
            "/config": ["rw", "nosuid", "nodev", "size=64m"],
        },
        "mounts": {
            "/etc/caddy/Caddyfile": "ro",
        },
    },
    "br-wissen-cloudflared": {
        "network": "br-wissen-internal",
        "port_bindings": set(),
        "user": "65532:65532",
        "cap_drop_all": True,
        "tmpfs": {
            "/tmp": ["rw", "noexec", "nosuid", "nodev", "size=64m"],
            "/run": ["rw", "noexec", "nosuid", "nodev", "size=32m"],
        },
        "mounts": {
            "/etc/cloudflared/config.yml": "ro",
            "/run/br-secrets/cloudflared": "ro",
        },
    },
}


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(ROOT), text=True, capture_output=True, check=False)


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


def inspect_containers() -> tuple[int, list[dict[str, Any]]]:
    if not helper_available(DOCKER):
        return 127, []
    proc = run([str(DOCKER), "inspect", *EXPECTED_CONTAINERS.keys()])
    if proc.returncode != 0:
        return proc.returncode, []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return 1, []
    if not isinstance(data, list):
        return 1, []
    return 0, [item for item in data if isinstance(item, dict)]


def container_name(row: dict[str, Any]) -> str:
    return str(row.get("Name") or "").lstrip("/")


def host_config(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("HostConfig") or {}
    return value if isinstance(value, dict) else {}


def network_names(row: dict[str, Any]) -> set[str]:
    settings = row.get("NetworkSettings") or {}
    networks = settings.get("Networks") if isinstance(settings, dict) else {}
    if not isinstance(networks, dict):
        return set()
    return {str(name) for name in networks.keys()}


def mount_map(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mounts = row.get("Mounts") or []
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(mounts, list):
        return result
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        dest = str(mount.get("Destination") or "")
        if dest:
            result[dest] = mount
    return result


def mount_mode(mount: dict[str, Any]) -> str:
    if bool(mount.get("RW")):
        return "rw"
    return "ro"


def port_binding_keys(hc: dict[str, Any]) -> set[str]:
    bindings = hc.get("PortBindings") or {}
    if not isinstance(bindings, dict):
        return set()
    return {str(key) for key, value in bindings.items() if value}


def tmpfs_map(hc: dict[str, Any]) -> dict[str, str]:
    value = hc.get("Tmpfs") or {}
    if not isinstance(value, dict):
        return {}
    return {str(path): str(options) for path, options in value.items()}


def tmpfs_has_options(options: str, required: list[str]) -> bool:
    parts = {part.strip() for part in options.split(",") if part.strip()}
    return all(item in parts for item in required)


def is_default_namespace(value: Any, default_allowed: set[str]) -> bool:
    text = str(value or "")
    return text in default_allowed


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen container hardening metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    checks = 0
    code, rows = inspect_containers()
    checks += 1
    if code != 0:
        findings.append("docker_inspect_unavailable")
        rows = []

    by_name = {container_name(row): row for row in rows if container_name(row)}
    privileged_count = 0
    cap_add_count = 0
    device_count = 0
    host_namespace_count = 0
    unexpected_port_bindings = 0
    unexpected_networks = 0
    required_ro_mounts = 0
    writable_required_mounts = 0
    readonly_rootfs_count = 0
    writable_rootfs_count = 0
    apparmor_default_count = 0
    no_new_privileges_count = 0
    resource_limited_count = 0
    expected_user_count = 0
    cap_drop_all_count = 0
    cap_drop_exception_count = 0
    tmpfs_service_count = 0
    tmpfs_path_count = 0

    for expected, policy in EXPECTED_CONTAINERS.items():
        checks += 1
        row = by_name.get(expected)
        if not row:
            findings.append("missing_container=%s" % expected)
            continue
        hc = host_config(row)

        checks += 1
        expected_user = str(policy.get("user", ""))
        actual_user = str((row.get("Config") or {}).get("User") or "")
        if actual_user == expected_user:
            expected_user_count += 1
        else:
            findings.append("user_mismatch_container=%s" % expected)

        checks += 1
        if bool(hc.get("Privileged")):
            privileged_count += 1
            findings.append("privileged_container=%s" % expected)

        checks += 1
        cap_add = hc.get("CapAdd") or []
        if cap_add:
            cap_add_count += len(cap_add) if isinstance(cap_add, list) else 1
            findings.append("cap_add_container=%s" % expected)

        checks += 1
        cap_drop = hc.get("CapDrop") or []
        if bool(policy.get("cap_drop_all")):
            if isinstance(cap_drop, list) and cap_drop == ["ALL"]:
                cap_drop_all_count += 1
            else:
                findings.append("cap_drop_all_missing=%s" % expected)
        else:
            if cap_drop:
                findings.append("unexpected_cap_drop_container=%s" % expected)
            else:
                cap_drop_exception_count += 1

        checks += 1
        devices = hc.get("Devices") or []
        if devices:
            device_count += len(devices) if isinstance(devices, list) else 1
            findings.append("device_container=%s" % expected)

        checks += 1
        if not is_default_namespace(hc.get("PidMode"), {""}):
            host_namespace_count += 1
            findings.append("pid_mode_container=%s" % expected)

        checks += 1
        if not is_default_namespace(hc.get("IpcMode"), {"", "private"}):
            host_namespace_count += 1
            findings.append("ipc_mode_container=%s" % expected)

        checks += 1
        if not is_default_namespace(hc.get("NetworkMode"), {policy["network"]}):
            findings.append("network_mode_container=%s" % expected)

        networks = network_names(row)
        checks += 1
        if networks != {policy["network"]}:
            unexpected_networks += 1
            findings.append("network_set_container=%s" % expected)

        actual_ports = port_binding_keys(hc)
        checks += 1
        if actual_ports != policy["port_bindings"]:
            unexpected_port_bindings += 1
            findings.append("port_bindings_container=%s" % expected)

        checks += 1
        actual_tmpfs = tmpfs_map(hc)
        expected_tmpfs = policy.get("tmpfs") or {}
        if set(actual_tmpfs) != set(expected_tmpfs):
            findings.append("tmpfs_set_container=%s" % expected)
        else:
            tmpfs_service_count += 1
        for path, required_options in expected_tmpfs.items():
            checks += 1
            options = actual_tmpfs.get(path, "")
            if not options:
                findings.append("tmpfs_missing_%s_%s" % (expected, path.replace("/", "_")))
            elif tmpfs_has_options(options, list(required_options)):
                tmpfs_path_count += 1
            else:
                findings.append("tmpfs_options_%s_%s" % (expected, path.replace("/", "_")))

        if bool(hc.get("ReadonlyRootfs")):
            readonly_rootfs_count += 1
        else:
            writable_rootfs_count += 1

        mounts = mount_map(row)
        expected_mounts = policy["mounts"]
        checks += 1
        if set(mounts) != set(expected_mounts):
            findings.append("mount_set_container=%s" % expected)
        for dest, expected_mode in expected_mounts.items():
            checks += 1
            mount = mounts.get(dest)
            if not mount:
                findings.append("missing_mount_%s_%s" % (expected, dest.replace("/", "_")))
                continue
            mode = mount_mode(mount)
            if expected_mode == "ro":
                required_ro_mounts += 1
                if mode != "ro":
                    findings.append("mount_not_ro_%s_%s" % (expected, dest.replace("/", "_")))
            elif expected_mode == "rw" and mode == "rw":
                writable_required_mounts += 1

        checks += 1
        restart_policy = hc.get("RestartPolicy") or {}
        if not isinstance(restart_policy, dict) or restart_policy.get("Name") != "unless-stopped":
            findings.append("restart_policy_container=%s" % expected)

        checks += 1
        if row.get("AppArmorProfile") == "docker-default":
            apparmor_default_count += 1
        else:
            findings.append("apparmor_profile_container=%s" % expected)

        security_opt = hc.get("SecurityOpt") or []
        if isinstance(security_opt, list) and any(str(item).lower() == "no-new-privileges:true" for item in security_opt):
            no_new_privileges_count += 1
        else:
            findings.append("no_new_privileges_missing=%s" % expected)

        memory = int(hc.get("Memory") or 0)
        nano_cpus = int(hc.get("NanoCpus") or 0)
        pids_limit = hc.get("PidsLimit")
        try:
            pids_limit_int = int(pids_limit or 0)
        except (TypeError, ValueError):
            pids_limit_int = 0
        if memory > 0 or nano_cpus > 0 or pids_limit_int > 0:
            resource_limited_count += 1
        else:
            findings.append("resource_limit_missing=%s" % expected)

        checks += 1
        if not bool(hc.get("ReadonlyRootfs")):
            findings.append("readonly_rootfs_missing=%s" % expected)

    unexpected_containers = sorted(set(by_name) - set(EXPECTED_CONTAINERS))
    checks += 1
    if unexpected_containers:
        findings.append("unexpected_containers=%d" % len(unexpected_containers))

    checks += 1
    if readonly_rootfs_count != len(EXPECTED_CONTAINERS):
        findings.append("readonly_rootfs_count=%d" % readonly_rootfs_count)

    checks += 1
    if no_new_privileges_count != len(EXPECTED_CONTAINERS):
        findings.append("no_new_privileges_count=%d" % no_new_privileges_count)

    checks += 1
    if resource_limited_count != len(EXPECTED_CONTAINERS):
        findings.append("resource_limited_count=%d" % resource_limited_count)

    checks += 1
    if expected_user_count != len(EXPECTED_CONTAINERS):
        findings.append("expected_user_count=%d" % expected_user_count)

    checks += 1
    expected_cap_drop_all = sum(1 for policy in EXPECTED_CONTAINERS.values() if bool(policy.get("cap_drop_all")))
    if cap_drop_all_count != expected_cap_drop_all:
        findings.append("cap_drop_all_count=%d" % cap_drop_all_count)

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "container_hardening_status=%s checks=%d findings=%d containers=%d privileged=%d cap_add=%d cap_drop_all=%d cap_drop_exceptions=%d expected_users=%d tmpfs_services=%d tmpfs_paths=%d devices=%d host_namespaces=%d unexpected_networks=%d unexpected_port_bindings=%d required_ro_mounts=%d writable_required_mounts=%d readonly_rootfs=%d writable_rootfs=%d apparmor_default=%d no_new_privileges=%d resource_limited=%d"
            % (
                status,
                checks,
                len(findings),
                len(EXPECTED_CONTAINERS),
                privileged_count,
                cap_add_count,
                cap_drop_all_count,
                cap_drop_exception_count,
                expected_user_count,
                tmpfs_service_count,
                tmpfs_path_count,
                device_count,
                host_namespace_count,
                unexpected_networks,
                unexpected_port_bindings,
                required_ro_mounts,
                writable_required_mounts,
                readonly_rootfs_count,
                writable_rootfs_count,
                apparmor_default_count,
                no_new_privileges_count,
                resource_limited_count,
            )
        )
    else:
        print("container_hardening_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("containers=%d" % len(EXPECTED_CONTAINERS))
        print("privileged=%d" % privileged_count)
        print("cap_add=%d" % cap_add_count)
        print("cap_drop_all=%d" % cap_drop_all_count)
        print("cap_drop_exceptions=%d" % cap_drop_exception_count)
        print("expected_users=%d" % expected_user_count)
        print("tmpfs_services=%d" % tmpfs_service_count)
        print("tmpfs_paths=%d" % tmpfs_path_count)
        print("devices=%d" % device_count)
        print("host_namespaces=%d" % host_namespace_count)
        print("unexpected_networks=%d" % unexpected_networks)
        print("unexpected_port_bindings=%d" % unexpected_port_bindings)
        print("required_ro_mounts=%d" % required_ro_mounts)
        print("writable_required_mounts=%d" % writable_required_mounts)
        print("readonly_rootfs=%d" % readonly_rootfs_count)
        print("writable_rootfs=%d" % writable_rootfs_count)
        print("apparmor_default=%d" % apparmor_default_count)
        print("no_new_privileges=%d" % no_new_privileges_count)
        print("resource_limited=%d" % resource_limited_count)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
