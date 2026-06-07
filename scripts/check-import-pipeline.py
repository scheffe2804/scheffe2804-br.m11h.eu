#!/usr/bin/env python3
"""Read-only guard for BR-Wissen import pipeline health.

The guard deliberately prints only counters, ages and status markers. It never
prints source contents, dump contents, credentials or secret values.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
LOG_DIR = STORAGE_ROOT / "logs"
DEFAULT_MAX_AGE_HOURS = float(os.getenv("BR_IMPORT_LOG_MAX_AGE_HOURS", "72"))
SUDO = Path("/usr/bin/sudo")
PYTHON = Path("/usr/bin/python3.13")
SYSTEMCTL = Path("/usr/bin/systemctl")
DOCKER = Path("/usr/bin/docker")


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(cwd) if cwd else None, text=True, capture_output=True, check=False)


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


def latest_log(pattern: str) -> Path | None:
    files = [path for path in LOG_DIR.glob(pattern) if path.is_file()]
    if not files:
        return None
    return max(files, key=lambda path: path.stat().st_mtime)


def read_log(path: Path) -> tuple[str, str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace"), "direct"
    except PermissionError:
        # Some logs are produced by root inside the container. chris has sudo on
        # this host; use non-interactive sudo only to read the local log text.
        if not helper_available(SUDO) or not helper_available(PYTHON):
            return "", "permission_denied"
        proc = run([
            str(SUDO),
            "-n",
            str(PYTHON),
            "-c",
            "from pathlib import Path; import sys; sys.stdout.write(Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace'))",
            str(path),
        ])
        if proc.returncode == 0:
            return proc.stdout, "sudo"
        return "", "permission_denied"


def age_hours(path: Path | None) -> float | None:
    if path is None:
        return None
    return (time.time() - path.stat().st_mtime) / 3600.0


def timer_active(unit: str) -> bool:
    if not helper_available(SYSTEMCTL):
        return False
    proc = run([str(SYSTEMCTL), "is-active", "--quiet", unit])
    return proc.returncode == 0


def db_metrics() -> dict[str, int]:
    sql = """
SELECT 'sources_without_document=' || count(*)
FROM sources s LEFT JOIN documents d ON d.source_id=s.id
WHERE d.id IS NULL;
SELECT 'approved_sources_without_chunks=' || count(*)
FROM (
  SELECT s.id
  FROM sources s
  LEFT JOIN documents d ON d.source_id=s.id
  LEFT JOIN chunks c ON c.document_id=d.id
  WHERE s.citation_allowed=true
  GROUP BY s.id
  HAVING count(c.id)=0
) AS chunkless;
SELECT 'chunk_class_mismatches=' || count(*)
FROM chunks c JOIN documents d ON d.id=c.document_id JOIN sources s ON s.id=d.source_id
WHERE c.source_class <> s.source_class;
SELECT 'source_sha_missing=' || count(*)
FROM sources WHERE coalesce(sha256,'')='';
SELECT 'document_sha_missing=' || count(*)
FROM documents WHERE coalesce(sha256,'')='';
SELECT 'recent_checked_72h=' || count(*)
FROM sources WHERE last_checked_at >= now() - interval '72 hours';
"""
    proc = run([
        str(DOCKER),
        "compose",
        "exec",
        "-T",
        "db",
        "psql",
        "-U",
        "br_app",
        "-d",
        "br_wissen",
        "-Atc",
        sql,
    ], cwd=ROOT)
    metrics: dict[str, int] = {
        "sources_without_document": 0,
        "approved_sources_without_chunks": 0,
        "chunk_class_mismatches": 0,
        "source_sha_missing": 0,
        "document_sha_missing": 0,
        "recent_checked_72h": 0,
    }
    if proc.returncode != 0:
        metrics["db_query_failed"] = 1
        return metrics
    for line in proc.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            metrics[key] = int(value)
        except ValueError:
            metrics[key] = -1
    return metrics


def parse_key_int(text: str, key: str) -> int | None:
    prefix = key + "="
    for line in text.splitlines():
        if line.startswith(prefix):
            try:
                return int(line[len(prefix) :].strip())
            except ValueError:
                return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen import pipeline guard")
    parser.add_argument("--summary", action="store_true", help="print one compact status line")
    parser.add_argument("--max-age-hours", type=float, default=DEFAULT_MAX_AGE_HOURS)
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    details: list[str] = []

    for unit in ["br-wissen-import-m00h.timer", "br-wissen-import-bag.timer"]:
        checks += 1
        active = timer_active(unit)
        details.append("timer_%s=%s" % (unit.replace(".", "_"), "active" if active else "inactive"))
        if not active:
            findings.append("inactive timer: %s" % unit)

    m00h_log = latest_log("import-m00h-*.log")
    bag_log = latest_log("import-bag-feed-*.log")
    ages = {"m00h": age_hours(m00h_log), "bag": age_hours(bag_log)}

    checks += 1
    if m00h_log is None:
        findings.append("missing m00h import log")
    else:
        text, method = read_log(m00h_log)
        details.append("m00h_latest_log=%s" % m00h_log.name)
        details.append("m00h_log_read=%s" % method)
        if ages["m00h"] is not None:
            details.append("m00h_latest_age_hours=%.1f" % ages["m00h"])
            if ages["m00h"] > args.max_age_hours:
                findings.append("stale m00h import log")
        if "# sha256" not in text:
            findings.append("m00h import log lacks checksum marker")

    checks += 1
    if bag_log is None:
        findings.append("missing BAG import log")
    else:
        text, method = read_log(bag_log)
        details.append("bag_latest_log=%s" % bag_log.name)
        details.append("bag_log_read=%s" % method)
        if ages["bag"] is not None:
            details.append("bag_latest_age_hours=%.1f" % ages["bag"])
            if ages["bag"] > args.max_age_hours:
                findings.append("stale BAG import log")
        imported = parse_key_int(text, "imported")
        failed = parse_key_int(text, "failed")
        details.append("bag_imported=%s" % ("unknown" if imported is None else imported))
        details.append("bag_failed=%s" % ("unknown" if failed is None else failed))
        if imported is None or imported <= 0:
            findings.append("BAG import log lacks positive imported count")
        if failed is None or failed != 0:
            findings.append("BAG import log reports failures or lacks failed=0")

    metrics = db_metrics()
    for key in sorted(metrics):
        details.append("%s=%s" % (key, metrics[key]))
    for key in [
        "db_query_failed",
        "sources_without_document",
        "approved_sources_without_chunks",
        "chunk_class_mismatches",
        "source_sha_missing",
        "document_sha_missing",
    ]:
        checks += 1
        if metrics.get(key, 0) != 0:
            findings.append("%s=%s" % (key, metrics.get(key)))
    checks += 1
    if metrics.get("recent_checked_72h", 0) <= 0:
        findings.append("no recently checked/imported sources within 72h")

    status = "ok" if not findings else "failed"
    if args.summary:
        m00h_age = "none" if ages["m00h"] is None else "%.1f" % ages["m00h"]
        bag_age = "none" if ages["bag"] is None else "%.1f" % ages["bag"]
        print(
            "import_pipeline_status=%s checks=%d findings=%d m00h_latest_age_h=%s bag_latest_age_h=%s recent_checked_72h=%s"
            % (status, checks, len(findings), m00h_age, bag_age, metrics.get("recent_checked_72h", 0))
        )
    else:
        print("import_pipeline_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        for detail in details:
            print(detail)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
