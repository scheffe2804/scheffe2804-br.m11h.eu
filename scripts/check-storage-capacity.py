#!/usr/bin/env python3
"""Read-only disk/inode capacity guard for BR-Wissen.

The guard checks only filesystem and Docker capacity metadata. It never reads or
prints file contents, secret values, dump contents or log bodies.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


APP_DIR = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
TMP_DIR = Path(os.getenv("BR_TMP_DIR", "/tmp"))
DOCKER_ROOT = Path(os.getenv("BR_DOCKER_ROOT", "/var/lib/docker"))

GIB = 1024 ** 3
MIN_FREE_DEFAULT_GIB = float(os.getenv("BR_CAPACITY_MIN_FREE_GIB", "10"))
MIN_TMP_FREE_GIB = float(os.getenv("BR_CAPACITY_MIN_TMP_FREE_GIB", "2"))
MIN_DOCKER_FREE_GIB = float(os.getenv("BR_CAPACITY_MIN_DOCKER_FREE_GIB", "10"))
MAX_USED_PERCENT = float(os.getenv("BR_CAPACITY_MAX_USED_PERCENT", "90"))
MAX_INODE_USED_PERCENT = float(os.getenv("BR_CAPACITY_MAX_INODE_USED_PERCENT", "90"))


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def stat_path(label: str, path: Path, min_free_gib: float) -> dict[str, Any]:
    usage = shutil.disk_usage(path)
    statvfs = os.statvfs(path)
    total_inodes = int(statvfs.f_files)
    free_inodes = int(statvfs.f_favail)
    used_inodes = max(0, total_inodes - free_inodes)
    used_percent = 0.0 if usage.total == 0 else (usage.used / usage.total) * 100.0
    inode_used_percent = 0.0 if total_inodes == 0 else (used_inodes / total_inodes) * 100.0
    return {
        "label": label,
        "path": str(path),
        "total_bytes": int(usage.total),
        "used_bytes": int(usage.used),
        "free_bytes": int(usage.free),
        "used_percent": used_percent,
        "total_inodes": total_inodes,
        "free_inodes": free_inodes,
        "inode_used_percent": inode_used_percent,
        "min_free_bytes": int(min_free_gib * GIB),
    }


def docker_summary() -> dict[str, Any]:
    proc = run(["docker", "system", "df", "--format", "json"])
    if proc.returncode != 0:
        return {"available": False, "types": 0, "size_bytes": 0, "reclaimable_bytes": 0}
    types = 0
    size_bytes = 0
    reclaimable_bytes = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        types += 1
        size_bytes += parse_size(str(item.get("Size") or "0B"))
        reclaimable_bytes += parse_size(str(item.get("Reclaimable") or "0B").split()[0])
    return {"available": True, "types": types, "size_bytes": size_bytes, "reclaimable_bytes": reclaimable_bytes}


def parse_size(value: str) -> int:
    value = value.strip().replace(" ", "")
    units = [
        ("GB", 1000 ** 3), ("MB", 1000 ** 2), ("KB", 1000),
        ("GiB", 1024 ** 3), ("MiB", 1024 ** 2), ("KiB", 1024),
        ("B", 1),
    ]
    for suffix, factor in units:
        if value.endswith(suffix):
            try:
                return int(float(value[: -len(suffix)]) * factor)
            except ValueError:
                return 0
    try:
        return int(float(value))
    except ValueError:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen storage capacity")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    path_specs = [
        ("root", Path("/"), MIN_FREE_DEFAULT_GIB),
        ("app", APP_DIR, MIN_FREE_DEFAULT_GIB),
        ("storage", STORAGE_ROOT, MIN_FREE_DEFAULT_GIB),
        ("tmp", TMP_DIR, MIN_TMP_FREE_GIB),
        ("docker", DOCKER_ROOT, MIN_DOCKER_FREE_GIB),
    ]

    findings: list[str] = []
    checks = 0
    seen_devices: set[tuple[int, int]] = set()
    stats: list[dict[str, Any]] = []
    for label, path, min_free_gib in path_specs:
        checks += 1
        if not path.exists():
            findings.append("missing_path_%s" % label)
            continue
        try:
            device = os.stat(path).st_dev
            stat_key = (device, int(min_free_gib * GIB))
            info = stat_path(label, path, min_free_gib)
        except OSError:
            findings.append("stat_failed_%s" % label)
            continue
        stats.append(info)
        if stat_key in seen_devices:
            continue
        seen_devices.add(stat_key)
        if int(info["free_bytes"]) < int(info["min_free_bytes"]):
            findings.append("low_free_%s_gib=%.1f" % (label, int(info["free_bytes"]) / GIB))
        if float(info["used_percent"]) > MAX_USED_PERCENT:
            findings.append("high_used_%s_pct=%.1f" % (label, float(info["used_percent"])))
        if float(info["inode_used_percent"]) > MAX_INODE_USED_PERCENT:
            findings.append("high_inode_%s_pct=%.1f" % (label, float(info["inode_used_percent"])))

    docker = docker_summary()
    checks += 1
    if not bool(docker.get("available")):
        findings.append("docker_system_df_unavailable")

    status = "ok" if not findings else "failed"
    min_free_gib = min((int(item["free_bytes"]) / GIB for item in stats), default=0.0)
    max_used_pct = max((float(item["used_percent"]) for item in stats), default=0.0)
    max_inode_pct = max((float(item["inode_used_percent"]) for item in stats), default=0.0)
    if args.summary:
        print(
            "storage_capacity_status=%s checks=%d findings=%d min_free_gib=%.1f max_used_pct=%.1f max_inode_pct=%.1f docker_size_gib=%.1f docker_reclaimable_gib=%.1f"
            % (
                status,
                checks,
                len(findings),
                min_free_gib,
                max_used_pct,
                max_inode_pct,
                int(docker.get("size_bytes") or 0) / GIB,
                int(docker.get("reclaimable_bytes") or 0) / GIB,
            )
        )
    else:
        print("storage_capacity_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        for item in stats:
            print(
                "capacity_path=%s path=%s free_gib=%.1f used_pct=%.1f inode_used_pct=%.1f min_free_gib=%.1f"
                % (
                    item["label"],
                    item["path"],
                    int(item["free_bytes"]) / GIB,
                    float(item["used_percent"]),
                    float(item["inode_used_percent"]),
                    int(item["min_free_bytes"]) / GIB,
                )
            )
        print("docker_system_df_available=%s" % bool(docker.get("available")))
        print("docker_size_gib=%.1f" % (int(docker.get("size_bytes") or 0) / GIB))
        print("docker_reclaimable_gib=%.1f" % (int(docker.get("reclaimable_bytes") or 0) / GIB))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
