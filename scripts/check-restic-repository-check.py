#!/usr/bin/env python3
"""Read-only Restic repository check freshness guard for BR-Wissen.

This guard verifies that the latest documented explicit `restic check` result is
fresh enough and successful. It intentionally does not run `restic check`, does
not take a repository lock, does not read backup secrets, dumps, logs, answers or
source documents, and does not print credential values.
"""

from __future__ import annotations

import argparse
import os
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
READINESS = ROOT / "docs" / "READINESS.md"
MAX_AGE_HOURS = float(os.getenv("BR_RESTIC_CHECK_MAX_AGE_HOURS", "720"))


def parse_timestamp(text: str) -> datetime | None:
    matches = re.findall(
        r"Letzter (?:expliziter Restic-Repository-Integritaetscheck|dokumentierter Lauf):\s*`(20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)`",
        text,
    )
    if not matches:
        return None
    value = matches[-1].replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        return None


def age_hours(stamp: datetime | None) -> float:
    if stamp is None:
        return 999999.0
    return max(0.0, (datetime.now(timezone.utc) - stamp).total_seconds() / 3600.0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check documented Restic repository-check freshness")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument("--max-age-hours", type=float, default=MAX_AGE_HOURS)
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    text = ""
    if not READINESS.exists():
        findings.append("readiness_missing")
    elif READINESS.is_symlink():
        findings.append("readiness_is_symlink")
    else:
        text = READINESS.read_text(encoding="utf-8", errors="replace")
    checks += 1

    required_markers = [
        "Restic-Repository-Check",
        "restic check",
        "no errors were found",
        "Bewusst nicht im Backup-Preflight oder Standard-Healthcheck",
        "exklusiven Repository-Lock",
    ]
    for marker in required_markers:
        checks += 1
        if marker not in text:
            findings.append("restic_check_marker_missing=%s" % re.sub(r"[^A-Za-z0-9_]+", "_", marker).strip("_"))

    stamp = parse_timestamp(text)
    age_h = age_hours(stamp)
    checks += 1
    if stamp is None:
        findings.append("restic_check_timestamp_missing")
    elif age_h > args.max_age_hours:
        findings.append("restic_check_too_old_h=%.1f" % age_h)

    snapshot_matches = re.findall(r"([0-9]+) Snapshots geprueft", text)
    snapshots = int(snapshot_matches[-1]) if snapshot_matches else 0
    checks += 1
    if snapshots <= 0:
        findings.append("restic_check_snapshot_count_missing")

    documented_success = 1 if "no errors were found" in text else 0
    lock_preflight = 0 if "kein Backup-Preflight" in text or "nicht im Backup-Preflight" in text else 1
    checks += 2
    if documented_success != 1:
        findings.append("restic_check_success_missing")
    if lock_preflight != 0:
        findings.append("restic_check_lock_preflight_not_excluded")

    status = "ok" if not findings else "failed"
    last_check = stamp.strftime("%Y-%m-%dT%H:%M:%SZ") if stamp else "unknown"
    summary = (
        "restic_repository_check_status=%s checks=%d findings=%d last_check=%s age_h=%.1f snapshots=%d documented_success=%d max_age_h=%.1f lock_preflight=%d"
        % (status, checks, len(findings), last_check, age_h, snapshots, documented_success, args.max_age_hours, lock_preflight)
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
