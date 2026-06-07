#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen import scripts.

The guard validates the m00h and BAG import source files for expected fail-fast,
path, logging, checksum, Docker, feed, storage and database markers. It only reads
project source files and systemd unit sources; it never reads imported source
contents, logs, dumps, backup env contents, credentials, answers or documents. It
does not run imports, docker, rsync, network requests, systemctl or sudo.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SYSTEMD_DIR = ROOT / "systemd"
M00H_SCRIPT = ROOT / "scripts" / "import-m00h-betriebsrat.sh"
BAG_WRAPPER = ROOT / "scripts" / "import-bag-feed-docker.sh"
BAG_IMPORTER = ROOT / "scripts" / "import-bag-feed.py"
IMPORT_PIPELINE = ROOT / "scripts" / "check-import-pipeline.py"


M00H_LITERALS = [
    "set -euo pipefail",
    "SRC_HOST=\"${BR_M00H_HOST:-m00h}\"",
    "SRC_PATH=\"${BR_M00H_SOURCE_PATH:-/srv/tailshare/Betriebsrat/}\"",
    "DEST_ROOT=\"${BR_STORAGE_ROOT:-/srv/br-wissensdatenbank}\"",
    "DEST_PATH=\"${DEST_ROOT}/imports/m00h/\"",
    "LOG_FILE=\"${LOG_DIR}/import-m00h-${STAMP}.log\"",
    "mkdir -p \"$DEST_PATH\" \"$LOG_DIR\"",
    "chmod 750 \"$DEST_ROOT\" \"$DEST_PATH\" \"$LOG_DIR\"",
    "mode=${1:-sync}",
    "if [[ \"${1:-sync}\" == \"dry-run\" ]]; then",
    "rsync -azn --delete --itemize-changes --protect-args",
    "rsync -az --delete --itemize-changes --protect-args",
    "echo \"# sha256\"",
    "find \"$DEST_PATH\" -type f -print0 | sort -z | xargs -0 sha256sum",
    "} | tee \"$LOG_FILE\"",
    "chmod 640 \"$LOG_FILE\"",
]


BAG_WRAPPER_LITERALS = [
    "set -euo pipefail",
    "ROOT=\"/home/chris/web/br.m11h.eu\"",
    "LIMIT=\"${1:-25}\"",
    "cd \"$ROOT\"",
    "docker compose exec -T app python - \"$LIMIT\" < scripts/import-bag-feed.py",
]


BAG_IMPORTER_LITERALS = [
    "FEED_URL = \"https://www.bundesarbeitsgericht.de/feed/entscheidung/neueste\"",
    "BASE_DIR = ROOT / \"sources\" / \"rechtsprechung\" / \"bag\"",
    "User-Agent",
    "urlopen(req, timeout=60)",
    "slug_from_url",
    "plain_text_from_html",
    "source_uid = \"bag-entscheidung-\" + slug",
    "out_dir.mkdir(parents=True, exist_ok=True)",
    "sha = hashlib.sha256(html_data).hexdigest()",
    "html_path.write_bytes(html_data)",
    "text_path.write_text(text, encoding=\"utf-8\")",
    "html_path.chmod(0o640)",
    "text_path.chmod(0o640)",
    "json.dumps({",
    "\"gericht\": \"BAG\"",
    "\"feed\": FEED_URL",
    "INSERT INTO sources",
    "ON CONFLICT (source_uid) DO UPDATE",
    "status='freigegeben'",
    "citation_allowed=true",
    "INSERT INTO documents",
    "DELETE FROM chunks WHERE document_id=%s",
    "INSERT INTO chunks",
    "source_class,citation_label,citation_url,internal_ref",
    "citation_label = \"BAG %s Rn. %s\"",
    "url + \"#rd-\" + rn",
    "BR_DATABASE_URL",
    "conn.commit()",
    "import-bag-feed-%s.log",
    "imported=%d",
    "failed=%d",
    "log.chmod(0o640)",
    "if failures and not results:",
]


IMPORT_PIPELINE_LITERALS = [
    "Read-only guard for BR-Wissen import pipeline health",
    "DEFAULT_MAX_AGE_HOURS = float(os.getenv(\"BR_IMPORT_LOG_MAX_AGE_HOURS\", \"72\"))",
    "SUDO = Path(\"/usr/bin/sudo\")",
    "PYTHON = Path(\"/usr/bin/python3.13\")",
    "SYSTEMCTL = Path(\"/usr/bin/systemctl\")",
    "DOCKER = Path(\"/usr/bin/docker\")",
    "def helper_available(path: Path) -> bool:",
    "def latest_log(pattern: str) -> Path | None:",
    "def read_log(path: Path) -> tuple[str, str]:",
    "str(SUDO)",
    "str(PYTHON)",
    "def timer_active(unit: str) -> bool:",
    "str(SYSTEMCTL)",
    "def db_metrics() -> dict[str, int]:",
    "str(DOCKER)",
    "sources_without_document=",
    "approved_sources_without_chunks=",
    "chunk_class_mismatches=",
    "recent_checked_72h=",
    "import_pipeline_status=%s checks=%d findings=%d m00h_latest_age_h=%s bag_latest_age_h=%s recent_checked_72h=%s",
]


SYSTEMD_EXPECTED = {
    "br-wissen-import-m00h.service": [
        "Description=BR Wissensdatenbank m00h import check",
        "Wants=network-online.target",
        "After=network-online.target docker.service",
        "Type=oneshot",
        "User=chris",
        "WorkingDirectory=/home/chris/web/br.m11h.eu",
        "ExecStart=/home/chris/web/br.m11h.eu/scripts/import-m00h-betriebsrat.sh sync",
    ],
    "br-wissen-import-bag.service": [
        "Description=BR Wissensdatenbank BAG official decisions import",
        "Wants=network-online.target",
        "After=network-online.target docker.service",
        "Type=oneshot",
        "User=chris",
        "WorkingDirectory=/home/chris/web/br.m11h.eu",
        "ExecStart=/home/chris/web/br.m11h.eu/scripts/import-bag-feed-docker.sh 25",
    ],
    "br-wissen-import-m00h.timer": [
        "Description=Daily BR Wissensdatenbank m00h import check",
        "OnCalendar=*-*-* 04:17:00",
        "Persistent=true",
        "RandomizedDelaySec=20m",
        "WantedBy=timers.target",
    ],
    "br-wissen-import-bag.timer": [
        "Description=Daily BR Wissensdatenbank BAG official decisions import",
        "OnCalendar=*-*-* 04:43:00",
        "Persistent=true",
        "RandomizedDelaySec=20m",
        "WantedBy=timers.target",
    ],
}


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str]) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % path.name)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require_literals(text: str, literals: list[str], label: str, findings: list[str]) -> int:
    checks = 0
    for literal in literals:
        checks += 1
        if literal not in text:
            findings.append("%s_missing_literal=%s" % (label, safe(literal)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen import source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    checks = 0

    m00h_text = read_source(M00H_SCRIPT, findings)
    bag_wrapper_text = read_source(BAG_WRAPPER, findings)
    bag_importer_text = read_source(BAG_IMPORTER, findings)
    import_pipeline_text = read_source(IMPORT_PIPELINE, findings)
    checks += 4

    checks += require_literals(m00h_text, M00H_LITERALS, "m00h", findings)
    checks += require_literals(bag_wrapper_text, BAG_WRAPPER_LITERALS, "bag_wrapper", findings)
    checks += require_literals(bag_importer_text, BAG_IMPORTER_LITERALS, "bag_importer", findings)
    checks += require_literals(import_pipeline_text, IMPORT_PIPELINE_LITERALS, "import_pipeline", findings)

    checks += 1
    if m00h_text.find("rsync -azn") > m00h_text.find("rsync -az --delete"):
        findings.append("m00h_dry_run_not_before_sync")
    checks += 1
    if m00h_text.find("echo \"# sha256\"") > m00h_text.find("chmod 640 \"$LOG_FILE\""):
        findings.append("m00h_checksum_after_log_chmod")
    checks += 1
    if bag_importer_text.find("html_path.write_bytes") > bag_importer_text.find("html_path.chmod(0o640)"):
        findings.append("bag_html_chmod_before_write")
    checks += 1
    if bag_importer_text.find("with psycopg.connect") > bag_importer_text.find("conn.commit()"):
        findings.append("bag_commit_before_connect")

    for unit, literals in SYSTEMD_EXPECTED.items():
        unit_text = read_source(SYSTEMD_DIR / unit, findings)
        checks += 1
        checks += require_literals(unit_text, literals, unit.replace(".", "_"), findings)

    status = "ok" if not findings else "failed"
    summary = "import_source_hardening_status=%s checks=%d findings=%d scripts=4 units=4 m00h_literals=%d bag_wrapper_literals=%d bag_importer_literals=%d import_pipeline_literals=%d" % (
        status,
        checks,
        len(findings),
        len(M00H_LITERALS),
        len(BAG_WRAPPER_LITERALS),
        len(BAG_IMPORTER_LITERALS),
        len(IMPORT_PIPELINE_LITERALS),
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
