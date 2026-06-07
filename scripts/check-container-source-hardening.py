#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen container/image guards.

The guard validates container runtime hardening, container image inventory,
image-pinning and image-pinning-readiness guard sources for expected
metadata-only Docker/Compose/Image reference markers and compact summaries. It
only reads project source files; it does not run Docker, Compose, registry
lookups, backups, restores, imports, regressions or database queries and never
reads secrets, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
CONTAINER_HARDENING = ROOT / "scripts" / "check-container-hardening.py"
CONTAINER_IMAGES = ROOT / "scripts" / "check-container-images.sh"
IMAGE_PINNING_GUARD = ROOT / "scripts" / "check-image-pinning-guard.sh"
IMAGE_PINNING_READINESS = ROOT / "scripts" / "check-image-pinning-readiness.sh"


CONTAINER_HARDENING_MARKERS: list[tuple[str, str]] = [
    ("docstring_metadata_only", "The guard inspects Docker metadata only. It never reads environment values,"),
    ("expected_containers", "EXPECTED_CONTAINERS = {"),
    ("app_container", '"br-wissen-app": {'),
    ("db_container", '"br-wissen-db": {'),
    ("worker_container", '"br-wissen-worker": {'),
    ("proxy_container", '"br-wissen-proxy": {'),
    ("cloudflared_container", '"br-wissen-cloudflared": {'),
    ("internal_network", '"network": "br-wissen-internal"'),
    ("port_bindings", '"port_bindings": set()'),
    ("proxy_port_exception", '"port_bindings": {"8080/tcp"}'),
    ("app_user", '"user": "1000:1000"'),
    ("db_user", '"user": "postgres"'),
    ("proxy_user", '"user": "1001:127"'),
    ("cloudflared_user", '"user": "65532:65532"'),
    ("cap_drop_all", '"cap_drop_all": True'),
    ("proxy_cap_exception", '"cap_drop_all": False'),
    ("tmpfs", '"tmpfs": {'),
    ("storage_mount", '"/srv/br-wissensdatenbank": "rw"'),
    ("secret_mount", '"/run/br-secrets": "ro"'),
    ("cloudflared_secret_mount", '"/run/br-secrets/cloudflared": "ro"'),
    ("docker_helper", "DOCKER = Path(\"/usr/bin/docker\")"),
    ("helper_available", "def helper_available(path: Path) -> bool:"),
    ("docker_inspect", 'run([str(DOCKER), "inspect", *EXPECTED_CONTAINERS.keys()])'),
    ("json_loads", "json.loads(proc.stdout)"),
    ("host_config", "def host_config(row: dict[str, Any])"),
    ("network_names", "def network_names(row: dict[str, Any])"),
    ("mount_map", "def mount_map(row: dict[str, Any])"),
    ("mount_mode", "def mount_mode(mount: dict[str, Any])"),
    ("port_binding_keys", "def port_binding_keys(hc: dict[str, Any])"),
    ("tmpfs_map", "def tmpfs_map(hc: dict[str, Any])"),
    ("tmpfs_options", "def tmpfs_has_options(options: str, required: list[str])"),
    ("default_namespace", "def is_default_namespace(value: Any, default_allowed: set[str])"),
    ("privileged", 'hc.get("Privileged")'),
    ("cap_add", 'hc.get("CapAdd")'),
    ("cap_drop", 'hc.get("CapDrop")'),
    ("devices", 'hc.get("Devices")'),
    ("pid_mode", 'hc.get("PidMode")'),
    ("ipc_mode", 'hc.get("IpcMode")'),
    ("network_mode", 'hc.get("NetworkMode")'),
    ("readonly_rootfs", 'hc.get("ReadonlyRootfs")'),
    ("restart_policy", 'hc.get("RestartPolicy")'),
    ("apparmor", 'row.get("AppArmorProfile") == "docker-default"'),
    ("no_new_privileges", 'no-new-privileges:true'),
    ("memory_limit", 'hc.get("Memory")'),
    ("cpu_limit", 'hc.get("NanoCpus")'),
    ("pids_limit", 'hc.get("PidsLimit")'),
    ("unexpected_containers", "unexpected_containers = sorted(set(by_name) - set(EXPECTED_CONTAINERS))"),
    ("summary", "container_hardening_status=%s checks=%d findings=%d containers=%d privileged=%d cap_add=%d cap_drop_all=%d cap_drop_exceptions=%d expected_users=%d tmpfs_services=%d tmpfs_paths=%d devices=%d host_namespaces=%d unexpected_networks=%d unexpected_port_bindings=%d required_ro_mounts=%d writable_required_mounts=%d readonly_rootfs=%d writable_rootfs=%d apparmor_default=%d no_new_privileges=%d resource_limited=%d"),
]


CONTAINER_IMAGES_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("root", 'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"'),
    ("summary_arg", "--summary"),
    ("docker_bin", "DOCKER_BIN=\"/usr/bin/docker\""),
    ("python_bin", "PYTHON_BIN=\"/usr/bin/python3.13\""),
    ("sort_bin", "SORT_BIN=\"/usr/bin/sort\""),
    ("compose_config_images", "\"$DOCKER_BIN\" compose config --images"),
    ("compose_ps_json", "\"$DOCKER_BIN\" compose ps --format json"),
    ("json_parser", "json.loads(line)"),
    ("image_field", 'obj.get("Image")'),
    ("sort_unique", "\"$SORT_BIN\" -u"),
    ("local_build", 'status="local_build"'),
    ("digest_pinned", 'status="digest_pinned"'),
    ("latest_tag", 'status="latest_tag"'),
    ("unversioned_tag", 'status="unversioned_tag"'),
    ("tag_pinned", 'status="tag_pinned"'),
    ("image_inspect", "\"$DOCKER_BIN\" image inspect"),
    ("status_ok", 'container_image_status="ok"'),
    ("status_warning", 'container_image_status="warning"'),
    ("status_failed", 'container_image_status="failed"'),
    ("summary", "container_image_status=%s images=%d local_build=%d tag_pinned=%d digest_pinned=%d latest=%d unversioned=%d"),
]


IMAGE_PINNING_GUARD_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("docker_bin", "DOCKER_BIN=\"/usr/bin/docker\""),
    ("python_bin", "PYTHON_BIN=\"/usr/bin/python3.13\""),
    ("sort_bin", "SORT_BIN=\"/usr/bin/sort\""),
    ("refs", "declare -A refs"),
    ("origins", "declare -A origins"),
    ("add_ref", "add_ref()"),
    ("compose_config_images", "\"$DOCKER_BIN\" compose config --images"),
    ("compose_ps_json", "\"$DOCKER_BIN\" compose ps --format json"),
    ("json_parser", "json.loads(line)"),
    ("dockerfile_app", '"$ROOT/app/Dockerfile"'),
    ("dockerfile_worker", '"$ROOT/worker/Dockerfile"'),
    ("from_parse", 'parts[0].upper() != "FROM"'),
    ("local_build", 'status="local_build"'),
    ("scratch", 'elif [[ "$ref" == scratch ]]; then'),
    ("digest_pinned", 'status="digest_pinned"'),
    ("violation", 'status="violation"'),
    ("origins_print", "image_pinning_guard_ref=%s origins=%s status=%s"),
    ("ok_summary", "image_pinning_guard_status=ok refs=%d local_build=%d digest_pinned=%d violations=0"),
    ("fail_summary", "image_pinning_guard_status=fail refs=%d local_build=%d digest_pinned=%d violations=%d"),
]


IMAGE_PINNING_READINESS_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("docker_bin", "DOCKER_BIN=\"/usr/bin/docker\""),
    ("python_bin", "PYTHON_BIN=\"/usr/bin/python3.13\""),
    ("sort_bin", "SORT_BIN=\"/usr/bin/sort\""),
    ("timeout_bin", "TIMEOUT_BIN=\"/usr/bin/timeout\""),
    ("summary_arg", "--summary"),
    ("no_remote_arg", "--no-remote"),
    ("remote_default", "remote=1"),
    ("refs", "declare -A refs"),
    ("origins", "declare -A origins"),
    ("add_ref", "add_ref()"),
    ("compose_config_images", "\"$DOCKER_BIN\" compose config --images"),
    ("compose_ps_json", "\"$DOCKER_BIN\" compose ps --format json"),
    ("dockerfile_app", '"$ROOT/app/Dockerfile"'),
    ("dockerfile_worker", '"$ROOT/worker/Dockerfile"'),
    ("remote_lookup_label", "remote_registry_lookup=enabled"),
    ("local_build", 'classification="local_build"'),
    ("digest_pinned", 'classification="digest_pinned"'),
    ("latest_candidate", 'classification="latest_pin_candidate"'),
    ("unversioned_candidate", 'classification="unversioned_pin_candidate"'),
    ("tag_candidate", 'classification="tag_pin_candidate"'),
    ("imagetools", "\"$DOCKER_BIN\" buildx imagetools inspect"),
    ("timeout", "$TIMEOUT_BIN 45"),
    ("remote_status_ok", "remote_status=ok"),
    ("remote_status_unavailable", "remote_status=unavailable"),
    ("display_ref", "display_ref()"),
    ("remote_expected", "remote_expected=$((remote_expected + 1))"),
    ("unavailable_refs", "unavailable_refs+=(\"$(display_ref \"$ref\")\")"),
    ("remote_coverage", "remote_coverage_pct=%d"),
    ("remote_unavailable_refs", "remote_unavailable_refs=%s"),
    ("mode_read_only", "mode=read_only"),
    ("status_ok", 'image_pinning_readiness_status="ok"'),
    ("status_warning", 'image_pinning_readiness_status="warning"'),
    ("status_failed", 'image_pinning_readiness_status="failed"'),
    ("summary", "image_pinning_readiness_status=%s refs=%d local_build=%d digest_pinned=%d tag_pin_candidates=%d latest_pin_candidates=%d unversioned_pin_candidates=%d remote_expected=%d remote_ok=%d remote_unavailable=%d remote_coverage_pct=%d remote_unavailable_refs=%s"),
]


FORBIDDEN_COMMON_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
    "conn.commit",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
    "docker compose up",
    "docker compose down",
    "docker compose restart",
    "docker compose rm",
    "docker rm",
    "docker volume rm",
    "docker rmi",
    "docker system prune",
    "pg_dump",
    "psql ",
    "restic ",
    "/srv/br-wissensdatenbank/logs",
    "/srv/br-wissensdatenbank/backups",
    "/srv/br-wissensdatenbank/sources",
    "/srv/br-wissensdatenbank/exports",
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
    parser = argparse.ArgumentParser(description="Check BR-Wissen container/image source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    container_text = read_source(CONTAINER_HARDENING, findings, "container_hardening")
    images_text = read_source(CONTAINER_IMAGES, findings, "container_images")
    pinning_text = read_source(IMAGE_PINNING_GUARD, findings, "image_pinning_guard")
    readiness_text = read_source(IMAGE_PINNING_READINESS, findings, "image_pinning_readiness")
    checks += 4

    checks += check_markers(findings, container_text, CONTAINER_HARDENING_MARKERS, "container")
    checks += check_markers(findings, images_text, CONTAINER_IMAGES_MARKERS, "images")
    checks += check_markers(findings, pinning_text, IMAGE_PINNING_GUARD_MARKERS, "pinning")
    checks += check_markers(findings, readiness_text, IMAGE_PINNING_READINESS_MARKERS, "readiness")

    for prefix, text in [
        ("container", container_text),
        ("images", images_text),
        ("pinning", pinning_text),
        ("readiness", readiness_text),
    ]:
        checks += check_forbidden(findings, text, FORBIDDEN_COMMON_MARKERS, prefix)

    checks += 1
    if container_text.find("EXPECTED_CONTAINERS") > container_text.find("for expected, policy in EXPECTED_CONTAINERS.items()"):
        findings.append("container_policy_after_loop")
    checks += 1
    if pinning_text.find("add_ref()") > pinning_text.find("add_ref \"$image\" \"compose_config\""):
        findings.append("pinning_add_ref_after_first_use")
    checks += 1
    if readiness_text.find("remote=1") > readiness_text.find("--no-remote"):
        findings.append("readiness_remote_default_after_arg_parse")

    status = "ok" if not findings else "failed"
    summary = "container_source_hardening_status=%s checks=%d findings=%d container_markers=%d image_inventory_markers=%d image_pinning_markers=%d image_readiness_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(CONTAINER_HARDENING_MARKERS),
        len(CONTAINER_IMAGES_MARKERS),
        len(IMAGE_PINNING_GUARD_MARKERS),
        len(IMAGE_PINNING_READINESS_MARKERS),
        len(FORBIDDEN_COMMON_MARKERS) * 4,
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
