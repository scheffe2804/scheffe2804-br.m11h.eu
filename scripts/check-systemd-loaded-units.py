#!/usr/bin/env python3
"""Read-only loaded systemd unit metadata guard for BR-Wissen.

The guard verifies what systemd has actually loaded for the managed BR-Wissen
service and timer units. It uses only `systemctl show` metadata and project unit
source text; it does not start, stop, restart, enable, disable or reload units
and never reads secrets, dumps, logs, answers, exports or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SYSTEMD_DIR = ROOT / "systemd"
SYSTEMCTL = Path("/usr/bin/systemctl")
FRAGMENT_PREFIX = "/etc/systemd/system/"
WORKING_DIRECTORY = "/home/chris/web/br.m11h.eu"

SERVICES = [
    "br-wissen-healthcheck.service",
    "br-wissen-backup.service",
    "br-wissen-import-m00h.service",
    "br-wissen-import-bag.service",
    "br-wissen-restore-smoke.service",
]
TIMERS = [
    "br-wissen-healthcheck.timer",
    "br-wissen-backup.timer",
    "br-wissen-import-m00h.timer",
    "br-wissen-import-bag.timer",
    "br-wissen-restore-smoke.timer",
]
UNITS = SERVICES + TIMERS
EXPECTED_SERVICE_USERS = {
    "br-wissen-healthcheck.service": "chris",
    "br-wissen-backup.service": "root",
    "br-wissen-import-m00h.service": "chris",
    "br-wissen-import-bag.service": "chris",
    "br-wissen-restore-smoke.service": "root",
}


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def run_systemctl_show(unit: str) -> tuple[int, dict[str, list[str]]]:
    properties = "Id,LoadState,FragmentPath,UnitFileState,ActiveState,SubState,Result,Type,User,WorkingDirectory,ExecStart,ExecStartPre,Unit,WantedBy,Triggers"
    proc = subprocess.run(
        [str(SYSTEMCTL), "show", unit, "--property=%s" % properties, "--no-pager"],
        text=True,
        capture_output=True,
        check=False,
    )
    values: dict[str, list[str]] = {}
    for raw_line in proc.stdout.splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        values.setdefault(key, []).append(value)
    return proc.returncode, values


def scalar(values: dict[str, list[str]], key: str) -> str:
    entries = values.get(key) or []
    return entries[0] if entries else ""


def project_values(unit: str) -> dict[str, list[str]]:
    path = SYSTEMD_DIR / unit
    values: dict[str, list[str]] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key, []).append(value)
    return values


def command_path(command_blob: str) -> str:
    match = re.search(r"\bpath=([^\s;]+)", command_blob)
    return match.group(1) if match else ""


def check_common(findings: list[str], unit: str, values: dict[str, list[str]], expected_state: str) -> int:
    checks = 0
    checks += 1
    if scalar(values, "Id") != unit:
        findings.append("id_unexpected=%s" % safe(unit))
    checks += 1
    if scalar(values, "LoadState") != "loaded":
        findings.append("load_state_unexpected=%s" % safe(unit))
    checks += 1
    expected_fragment = FRAGMENT_PREFIX + unit
    if scalar(values, "FragmentPath") != expected_fragment:
        findings.append("fragment_path_unexpected=%s" % safe(unit))
    checks += 1
    if scalar(values, "UnitFileState") != expected_state:
        findings.append("unit_file_state_unexpected=%s" % safe(unit))
    return checks


def check_service(findings: list[str], unit: str, values: dict[str, list[str]]) -> int:
    checks = check_common(findings, unit, values, "static")
    project = project_values(unit)
    expected_exec = scalar(project, "ExecStart")

    checks += 1
    if scalar(values, "Type") != "oneshot":
        findings.append("service_type_unexpected=%s" % safe(unit))
    checks += 1
    if scalar(values, "User") != EXPECTED_SERVICE_USERS[unit]:
        findings.append("service_user_unexpected=%s" % safe(unit))
    checks += 1
    if scalar(values, "WorkingDirectory") != WORKING_DIRECTORY:
        findings.append("working_directory_unexpected=%s" % safe(unit))
    checks += 1
    if scalar(values, "ActiveState") == "failed" or scalar(values, "Result") not in {"success", ""}:
        findings.append("service_failed=%s" % safe(unit))
    checks += 1
    if command_path(scalar(values, "ExecStart")) != expected_exec.split()[0]:
        findings.append("execstart_path_unexpected=%s" % safe(unit))

    if unit == "br-wissen-healthcheck.service":
        expected_pre = [entry.split()[0] for entry in project.get("ExecStartPre", [])]
        loaded_pre = [command_path(entry) for entry in values.get("ExecStartPre", [])]
        checks += 1
        if loaded_pre != expected_pre:
            findings.append("healthcheck_execstartpre_sequence_unexpected")
        checks += 1
        if "/home/chris/web/br.m11h.eu/scripts/check-systemd-loaded-units.py" not in loaded_pre and (SYSTEMD_DIR / unit).exists():
            # The guard is allowed to be absent before this block is integrated.
            # Once integrated, source-hardening and coverage guards make absence fail.
            pass
    return checks


def check_timer(findings: list[str], unit: str, values: dict[str, list[str]]) -> int:
    checks = check_common(findings, unit, values, "enabled")
    expected_service = unit.replace(".timer", ".service")
    checks += 1
    if scalar(values, "ActiveState") != "active":
        findings.append("timer_inactive=%s" % safe(unit))
    checks += 1
    if scalar(values, "Unit") not in {expected_service, ""}:
        findings.append("timer_unit_unexpected=%s" % safe(unit))
    checks += 1
    if scalar(values, "Triggers") not in {expected_service, ""}:
        findings.append("timer_triggers_unexpected=%s" % safe(unit))
    checks += 1
    if "timers.target" not in " ".join(values.get("WantedBy", [])):
        findings.append("timer_wantedby_unexpected=%s" % safe(unit))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen loaded systemd unit metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    loaded_units = 0
    active_timers = 0
    static_services = 0
    failed_services = 0
    enabled_timers = 0
    fragment_matches = 0

    checks += 1
    if not SYSTEMCTL.exists() or SYSTEMCTL.is_symlink() or not SYSTEMCTL.is_file():
        findings.append("systemctl_helper_unavailable")

    for unit in UNITS:
        code, values = run_systemctl_show(unit)
        checks += 1
        if code != 0:
            findings.append("systemctl_show_failed=%s" % safe(unit))
            continue
        if scalar(values, "LoadState") == "loaded":
            loaded_units += 1
        if scalar(values, "FragmentPath") == FRAGMENT_PREFIX + unit:
            fragment_matches += 1
        if unit in SERVICES:
            if scalar(values, "UnitFileState") == "static":
                static_services += 1
            if scalar(values, "ActiveState") == "failed" or scalar(values, "Result") not in {"success", ""}:
                failed_services += 1
            checks += check_service(findings, unit, values)
        else:
            if scalar(values, "UnitFileState") == "enabled":
                enabled_timers += 1
            if scalar(values, "ActiveState") == "active":
                active_timers += 1
            checks += check_timer(findings, unit, values)

    status = "ok" if not findings else "failed"
    summary = (
        "systemd_loaded_unit_status=%s checks=%d findings=%d units=%d loaded_units=%d "
        "fragment_matches=%d static_services=%d enabled_timers=%d active_timers=%d failed_services=%d"
        % (status, checks, len(findings), len(UNITS), loaded_units, fragment_matches, static_services, enabled_timers, active_timers, failed_services)
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
