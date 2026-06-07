#!/usr/bin/env python3
"""Read-only Docker Compose service guard for BR-Wissen.

The guard checks expected project containers and health states using Docker
metadata only. It never reads application secrets, backup environment contents,
logs, dumps, answers or source documents.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
EXPECTED_SERVICES = ["app", "db", "worker", "proxy", "cloudflared"]
HEALTH_REQUIRED = {"app", "db"}
DOCKER = Path("/usr/bin/docker")


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
    rows: list[dict[str, Any]] = []
    stdout = proc.stdout.strip()
    if not stdout:
        return 0, rows
    if stdout.startswith("["):
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return 1, []
        if not isinstance(data, list):
            return 1, []
        return 0, [item for item in data if isinstance(item, dict)]
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


def state_value(row: dict[str, Any]) -> str:
    return str(row.get("State") or row.get("state") or "")


def health_value(row: dict[str, Any]) -> str:
    health = str(row.get("Health") or row.get("health") or "")
    if health:
        return health
    status = str(row.get("Status") or row.get("status") or "")
    lowered = status.lower()
    if "healthy" in lowered and "unhealthy" not in lowered:
        return "healthy"
    if "unhealthy" in lowered:
        return "unhealthy"
    if "starting" in lowered:
        return "starting"
    return "none"


def normalize_state(value: str) -> str:
    return value.strip().lower() or "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen Docker Compose services")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    code, rows = compose_ps()
    checks = 1
    if code != 0:
        findings.append("compose_ps_unavailable")
        rows = []

    by_service: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        name = service_name(row)
        if name:
            by_service.setdefault(name, []).append(row)

    running = 0
    healthy = 0
    health_required = len(HEALTH_REQUIRED)
    for expected in EXPECTED_SERVICES:
        checks += 1
        matches = by_service.get(expected) or []
        if len(matches) != 1:
            findings.append("service_count_%s=%d" % (expected, len(matches)))
            continue
        row = matches[0]
        state = normalize_state(state_value(row))
        if state != "running":
            findings.append("service_not_running_%s=%s" % (expected, state))
        else:
            running += 1
        if expected in HEALTH_REQUIRED:
            checks += 1
            health = health_value(row)
            if health != "healthy":
                findings.append("service_not_healthy_%s=%s" % (expected, health))
            else:
                healthy += 1

    unexpected_services = sorted(set(by_service) - set(EXPECTED_SERVICES))
    checks += 1
    if unexpected_services:
        findings.append("unexpected_services=%d" % len(unexpected_services))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "compose_service_status=%s checks=%d findings=%d expected=%d running=%d health_required=%d healthy=%d unexpected=%d"
            % (status, checks, len(findings), len(EXPECTED_SERVICES), running, health_required, healthy, len(unexpected_services))
        )
    else:
        print("compose_service_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("expected=%d" % len(EXPECTED_SERVICES))
        print("running=%d" % running)
        print("health_required=%d" % health_required)
        print("healthy=%d" % healthy)
        print("unexpected=%d" % len(unexpected_services))
        for expected in EXPECTED_SERVICES:
            matches = by_service.get(expected) or []
            if len(matches) == 1:
                row = matches[0]
                print(
                    "compose_service=%s state=%s health=%s"
                    % (expected, normalize_state(state_value(row)), health_value(row))
                )
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
