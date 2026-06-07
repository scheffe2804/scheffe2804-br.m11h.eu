#!/usr/bin/env python3
"""Read-only host time synchronisation guard for BR-Wissen.

The guard validates time/NTP metadata that other guards depend on, especially TLS
certificate validity checks and backup/restore freshness calculations. It never
changes time settings and never reads application secrets, dumps, logs, answers
or source documents.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


MAX_SYSTEM_OFFSET_SECONDS = 1.0
MAX_RMS_OFFSET_SECONDS = 1.0
MAX_STRATUM = 8
TIMEDATECTL = Path("/usr/bin/timedatectl")
CHRONYC = Path("/usr/bin/chronyc")


def number_value(value: float | int | str | None, default: float) -> float:
    return default if value is None else float(value)


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


def timedatectl_values() -> dict[str, str] | None:
    if not helper_available(TIMEDATECTL):
        return None
    proc = run([str(TIMEDATECTL), "show", "-p", "NTPSynchronized", "-p", "SystemClockSynchronized", "-p", "Timezone"])
    if proc.returncode != 0:
        return None
    values: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def parse_seconds(line: str) -> float | None:
    match = re.search(r":\s*([+-]?\d+(?:\.\d+)?)\s+seconds\b", line)
    if not match:
        return None
    return float(match.group(1))


def chrony_tracking() -> dict[str, float | int | str] | None:
    if not helper_available(CHRONYC):
        return None
    proc = run([str(CHRONYC), "tracking"])
    if proc.returncode != 0:
        return None
    values: dict[str, float | int | str] = {
        "stratum": -1,
        "system_offset": 999999.0,
        "rms_offset": 999999.0,
        "leap_status": "unknown",
    }
    for line in proc.stdout.splitlines():
        if line.startswith("Stratum"):
            match = re.search(r":\s*(\d+)", line)
            if match:
                values["stratum"] = int(match.group(1))
        elif line.startswith("System time"):
            parsed = parse_seconds(line)
            if parsed is not None:
                values["system_offset"] = abs(parsed)
        elif line.startswith("RMS offset"):
            parsed = parse_seconds(line)
            if parsed is not None:
                values["rms_offset"] = abs(parsed)
        elif line.startswith("Leap status"):
            values["leap_status"] = line.split(":", 1)[1].strip() if ":" in line else "unknown"
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen host time synchronisation metadata")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    timedate = timedatectl_values()
    checks += 1
    if timedate is None:
        findings.append("timedatectl_unavailable")
        timedate = {}

    ntp_synchronized = timedate.get("NTPSynchronized", "") == "yes"
    system_clock_value = timedate.get("SystemClockSynchronized")
    system_clock_synchronized = system_clock_value == "yes"
    system_clock_available = system_clock_value in {"yes", "no"}
    timezone = timedate.get("Timezone", "unknown") or "unknown"

    checks += 1
    if not ntp_synchronized:
        findings.append("ntp_not_synchronized")
    checks += 1
    if system_clock_available and not system_clock_synchronized:
        findings.append("system_clock_not_synchronized")

    chrony = chrony_tracking()
    checks += 1
    if chrony is None:
        findings.append("chrony_tracking_unavailable")
        chrony = {"stratum": -1, "system_offset": 999999.0, "rms_offset": 999999.0, "leap_status": "unknown"}

    stratum = int(number_value(chrony.get("stratum"), -1))
    system_offset = number_value(chrony.get("system_offset"), 999999.0)
    rms_offset = number_value(chrony.get("rms_offset"), 999999.0)
    leap_status = str(chrony.get("leap_status") or "unknown")

    checks += 1
    if stratum < 1 or stratum > MAX_STRATUM:
        findings.append("chrony_unexpected_stratum=%d" % stratum)
    checks += 1
    if system_offset > MAX_SYSTEM_OFFSET_SECONDS:
        findings.append("chrony_system_offset_too_high=%.6f" % system_offset)
    checks += 1
    if rms_offset > MAX_RMS_OFFSET_SECONDS:
        findings.append("chrony_rms_offset_too_high=%.6f" % rms_offset)
    checks += 1
    if leap_status.lower() != "normal":
        findings.append("chrony_leap_status=%s" % leap_status.replace(" ", "_"))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "time_sync_status=%s checks=%d findings=%d ntp=%d system_clock=%d timezone=%s chrony_stratum=%d system_offset_s=%.6f rms_offset_s=%.6f leap_normal=%d"
            % (
                status,
                checks,
                len(findings),
                1 if ntp_synchronized else 0,
                1 if system_clock_synchronized else (-1 if not system_clock_available else 0),
                timezone,
                stratum,
                system_offset,
                rms_offset,
                1 if leap_status.lower() == "normal" else 0,
            )
        )
    else:
        print("time_sync_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("ntp=%d" % (1 if ntp_synchronized else 0))
        print("system_clock=%d" % (1 if system_clock_synchronized else (-1 if not system_clock_available else 0)))
        print("timezone=%s" % timezone)
        print("chrony_stratum=%d" % stratum)
        print("system_offset_s=%.6f" % system_offset)
        print("rms_offset_s=%.6f" % rms_offset)
        print("leap_normal=%d" % (1 if leap_status.lower() == "normal" else 0))
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
