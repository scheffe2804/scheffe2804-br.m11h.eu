#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen operational wrappers.

The guard validates operational shell wrappers for expected fail-fast behaviour,
curated helper paths, explicit opt-in/runtime boundaries and no-secret markers.
It only reads project source files; it does not run Docker, rsync, OCR, imports,
exports, repairs, backups, restores, regressions, restic, sudo or systemctl and
never reads secrets, dumps, logs, answers, exports or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SCRIPTS = ROOT / "scripts"


@dataclass(frozen=True)
class WrapperSpec:
    label: str
    script: str
    literals: list[str]


WRAPPERS: list[WrapperSpec] = [
    WrapperSpec(
        "backup_wrapper",
        "backup-br-wissen.sh",
        [
            "set -euo pipefail",
            "DATE_BIN=\"/usr/bin/date\"",
            "MKDIR_BIN=\"/usr/bin/mkdir\"",
            "TOUCH_BIN=\"/usr/bin/touch\"",
            "CHMOD_BIN=\"/usr/bin/chmod\"",
            "DOCKER_BIN=\"/usr/bin/docker\"",
            "FIND_BIN=\"/usr/bin/find\"",
            "SORT_BIN=\"/usr/bin/sort\"",
            "AWK_BIN=\"/usr/bin/awk\"",
            "RM_BIN=\"/usr/bin/rm\"",
            "TEE_BIN=\"/usr/bin/tee\"",
            "ALLOWED_RESTIC_PATHS=(/usr/bin/restic /usr/local/bin/restic)",
            "run_preflight()",
            "protocol_file_status=included",
            "restic_bin=${RESTIC_BIN}",
            "status=backup_done",
        ],
    ),
    WrapperSpec(
        "restore_drill_wrapper",
        "run-restore-smoke-drill.sh",
        [
            "set -euo pipefail",
            "DATE_BIN=\"/usr/bin/date\"",
            "MKDIR_BIN=\"/usr/bin/mkdir\"",
            "TOUCH_BIN=\"/usr/bin/touch\"",
            "CHMOD_BIN=\"/usr/bin/chmod\"",
            "FIND_BIN=\"/usr/bin/find\"",
            "SORT_BIN=\"/usr/bin/sort\"",
            "AWK_BIN=\"/usr/bin/awk\"",
            "RM_BIN=\"/usr/bin/rm\"",
            "TEE_BIN=\"/usr/bin/tee\"",
            "storage_capacity_preflight=running",
            "restore_drill_status=ok",
        ],
    ),
    WrapperSpec(
        "restore_smoke_wrapper",
        "restore-smoke-br-wissen.sh",
        [
            "set -euo pipefail",
            "DATE_BIN=\"/usr/bin/date\"",
            "DOCKER_BIN=\"/usr/bin/docker\"",
            "GREP_BIN=\"/usr/bin/grep\"",
            "RM_BIN=\"/usr/bin/rm\"",
            "SUDO_BIN=\"/usr/bin/sudo\"",
            "TEST_BIN=\"/usr/bin/test\"",
            "BASH_BIN=\"/usr/bin/bash\"",
            "RESTIC_BIN=\"/usr/bin/restic\"",
            "PYTHON_BIN=\"/usr/bin/python3.13\"",
            "FIND_BIN=\"/usr/bin/find\"",
            "WC_BIN=\"/usr/bin/wc\"",
            "TR_BIN=\"/usr/bin/tr\"",
            "STAT_BIN=\"/usr/bin/stat\"",
            "SORT_BIN=\"/usr/bin/sort\"",
            "AWK_BIN=\"/usr/bin/awk\"",
            "BASENAME_BIN=\"/usr/bin/basename\"",
            "SLEEP_BIN=\"/usr/bin/sleep\"",
            "SEQ_BIN=\"/usr/bin/seq\"",
            "PRINTF_BIN=\"/usr/bin/printf\"",
            "case \"$TARGET\" in",
            "--network none",
            "restore_status=ok",
        ],
    ),
    WrapperSpec(
        "m00h_import_wrapper",
        "import-m00h-betriebsrat.sh",
        [
            "set -euo pipefail",
            "DATE_BIN=\"/usr/bin/date\"",
            "MKDIR_BIN=\"/usr/bin/mkdir\"",
            "CHMOD_BIN=\"/usr/bin/chmod\"",
            "RSYNC_BIN=\"/usr/bin/rsync\"",
            "FIND_BIN=\"/usr/bin/find\"",
            "SORT_BIN=\"/usr/bin/sort\"",
            "XARGS_BIN=\"/usr/bin/xargs\"",
            "SHA256SUM_BIN=\"/usr/bin/sha256sum\"",
            "TEE_BIN=\"/usr/bin/tee\"",
            "if [[ \"${1:-sync}\" == \"dry-run\" ]]; then",
            "\"$RSYNC_BIN\" -azn --delete --itemize-changes --protect-args",
            "\"$RSYNC_BIN\" -az --delete --itemize-changes --protect-args",
            "\"$CHMOD_BIN\" 640 \"$LOG_FILE\"",
        ],
    ),
    WrapperSpec(
        "bag_import_wrapper",
        "import-bag-feed-docker.sh",
        [
            "set -euo pipefail",
            "ROOT=\"/home/chris/web/br.m11h.eu\"",
            "DOCKER_BIN=\"/usr/bin/docker\"",
            "cd \"$ROOT\"",
            "\"$DOCKER_BIN\" compose exec -T app python - \"$LIMIT\" < scripts/import-bag-feed.py",
        ],
    ),
    WrapperSpec(
        "regression_wrapper",
        "run-regressions-docker.sh",
        [
            "set -euo pipefail",
            "ROOT=\"/home/chris/web/br.m11h.eu\"",
            "DOCKER_BIN=\"/usr/bin/docker\"",
            "cd \"$ROOT\"",
            "\"$DOCKER_BIN\" compose exec -T app python - < scripts/run-regressions.py",
        ],
    ),
    WrapperSpec(
        "answer_export_wrapper",
        "export-answer-docker.sh",
        [
            "set -euo pipefail",
            "ROOT=\"/home/chris/web/br.m11h.eu\"",
            "DOCKER_BIN=\"/usr/bin/docker\"",
            "Usage: export-answer-docker.sh <answer_uid>",
            "if [[ $# -ne 1 ]]; then",
            "cd \"$ROOT\"",
            "\"$DOCKER_BIN\" compose exec -T app python - \"$1\" < scripts/export-answer.py",
        ],
    ),
    WrapperSpec(
        "repair_wrapper",
        "repair-short-text-sources-docker.sh",
        [
            "set -euo pipefail",
            "ROOT=\"/home/chris/web/br.m11h.eu\"",
            "DOCKER_BIN=\"/usr/bin/docker\"",
            "cd \"$ROOT\"",
            "\"$DOCKER_BIN\" compose exec -T app python - \"$@\" < scripts/repair-short-text-sources.py",
        ],
    ),
    WrapperSpec(
        "cloudflare_pattern_helper",
        "check-cloudflare-staging-pattern.sh",
        [
            "set -euo pipefail",
            "Read-only helper. Does not print env vars or tunnel tokens.",
            "DOCKER_BIN=\"/usr/bin/docker\"",
            "--filter ancestor=cloudflare/cloudflared:latest",
            "Do not inspect or print full cloudflared commands/env without secret review",
        ],
    ),
    WrapperSpec(
        "ocr_wrapper",
        "ocr-single-pdf.sh",
        [
            "set -euo pipefail",
            "BASENAME_BIN=\"/usr/bin/basename\"",
            "DATE_BIN=\"/usr/bin/date\"",
            "MKDIR_BIN=\"/usr/bin/mkdir\"",
            "SHA256SUM_BIN=\"/usr/bin/sha256sum\"",
            "CUT_BIN=\"/usr/bin/cut\"",
            "ALLOWED_OCRMYPDF_PATHS=(/usr/bin/ocrmypdf /usr/local/bin/ocrmypdf)",
            "PDFTOTEXT_BIN=\"/usr/bin/pdftotext\"",
            "WC_BIN=\"/usr/bin/wc\"",
            "TEE_BIN=\"/usr/bin/tee\"",
            "CHMOD_BIN=\"/usr/bin/chmod\"",
            "ocr_status=missing_ocrmypdf",
            "\"$OCRMYPDF_BIN\" --skip-text --deskew --rotate-pages --language deu+eng",
            "\"$PDFTOTEXT_BIN\" -layout \"$OCR_OUT\" \"$TEXT_OUT\"",
        ],
    ),
]


SELF_FORBIDDEN_MARKERS = [
    "subprocess" + ".run",
    "os" + ".system",
    "Path" + ".unlink(",
    "shutil" + ".rmtree",
    "docker compose" + " up",
    "docker compose" + " down",
    "docker compose" + " restart",
    "systemctl" + " start",
    "systemctl" + " restart",
    "restic" + " check",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    if path.is_symlink():
        findings.append("symlink_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen operational wrapper source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    wrapper_count = 0
    literal_count = 0

    for spec in WRAPPERS:
        text = read_source(SCRIPTS / spec.script, findings, spec.label)
        checks += 1
        wrapper_count += 1
        for literal in spec.literals:
            checks += 1
            literal_count += 1
            if literal not in text:
                findings.append("%s_missing=%s" % (spec.label, safe(literal)))

    self_text = read_source(SCRIPTS / "check-operational-wrapper-source-hardening.py", findings, "self")
    checks += 1
    for marker in SELF_FORBIDDEN_MARKERS:
        checks += 1
        if marker in self_text:
            findings.append("self_forbidden=%s" % safe(marker))

    checks += 1
    if self_text.find("WRAPPERS: list[WrapperSpec]") > self_text.find("for spec in WRAPPERS:"):
        findings.append("wrapper_specs_after_loop")

    status = "ok" if not findings else "failed"
    summary = "operational_wrapper_source_hardening_status=%s checks=%d findings=%d wrappers=%d required_literals=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        wrapper_count,
        literal_count,
        len(SELF_FORBIDDEN_MARKERS),
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
