#!/usr/bin/env python3
"""Read-only source hardening guard for the BR-Wissen app healthcheck.

The guard validates the healthcheck source and its Docker wrapper for expected
read-only database/file integrity checks, summary behaviour and wrapper markers.
It only reads project source files; it does not run the healthcheck, Docker,
database queries, imports, backups, restores or regressions and never reads
secrets, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
HEALTHCHECK = ROOT / "scripts" / "healthcheck-br-wissen.py"
WRAPPER = ROOT / "scripts" / "healthcheck-br-wissen-docker.sh"


HEALTHCHECK_LITERALS = [
    "This check is intentionally read-only",
    "STORAGE_ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))",
    "DATABASE_URL = os.environ[\"BR_DATABASE_URL\"]",
    "psycopg.connect(DATABASE_URL)",
    "cur.execute(sql, params)",
    "for table in [\"sources\", \"documents\", \"chunks\", \"queries\", \"answers\", \"answer_statements\", \"answer_citations\"]",
    "def source_class_counts()",
    "def source_type_counts()",
    "def chunkless_sources(approved_only: bool)",
    "WHERE s.citation_allowed=true",
    "HAVING count(c.id)=0",
    "def duplicate_document_sha_groups()",
    "WHERE d.sha256 IS NOT NULL AND d.sha256 <> ''",
    "def ocr_status_counts()",
    "def repaired_ocr_integrity()",
    "WHERE d.ocr_status='ocr_repaired_tesseract'",
    "def export_counts()",
    "index.html",
    "export.pdf",
    "def recent_answers()",
    "statements_without_citation",
    "def source_integrity()",
    "status NOT IN ('importiert','technisch_geprueft','inhaltlich_eingeordnet','freigegeben','veraltet','gesperrt')",
    "source_class NOT IN ('GRUEN','BLAU','GELB','GRAU','ROT')",
    "freigegeben_not_allowed",
    "citation_allowed_not_freigegeben",
    "hint_only_wrong_class",
    "green_missing_public_url",
    "source_sha_missing",
    "document_sha_missing",
    "sources_without_documents",
    "chunk_class_mismatches",
    "recent_gelb_answer_citations",
    "UNION ALL",
    "storage_prefix = str(STORAGE_ROOT.resolve()) + os.sep",
    "if not path.is_absolute() or not str(path).startswith(storage_prefix):",
    "if not path.exists():",
    "Usage: healthcheck-br-wissen.py [--summary [--pretty]]",
    "summary_only = \"--summary\" in sys.argv[1:]",
    "pretty_summary = \"--pretty\" in sys.argv[1:]",
    "return 0 if not failures else 1",
]


FAILURE_MARKERS = [
    "empty core table count",
    "approved sources without chunks",
    "repaired OCR documents without chunks",
    "repaired OCR documents with missing text paths",
    "repaired OCR min text size below threshold",
    "recent answer without citation",
    "html/pdf export count mismatch",
    "invalid source status values",
    "invalid source class values",
    "source integrity violation: %s",
    "source/document paths missing on disk",
    "source/document paths outside storage root",
]


SUMMARY_MARKERS = [
    '"status": result["status"]',
    '"failures": failures',
    '"counts": {key: counts[key] for key in ["sources", "documents", "chunks", "queries", "answers"]}',
    '"approved_chunkless_sources": len(approved_chunkless)',
    '"duplicate_document_sha_groups": len(duplicate_sha)',
    '"repaired_ocr_integrity": repaired',
    '"exports": exports',
    '"source_integrity": {',
    '"invalid_status": len(integrity.get("invalid_status") or [])',
    '"invalid_class": len(integrity.get("invalid_class") or [])',
    '"missing_path_count": integrity.get("missing_path_count") or 0',
    '"outside_storage_path_count": integrity.get("outside_storage_path_count") or 0',
    "json.dumps(summary, ensure_ascii=False",
]


WRAPPER_LITERALS = [
    "set -euo pipefail",
    "ROOT=\"/home/chris/web/br.m11h.eu\"",
    "DOCKER_BIN=\"/usr/bin/docker\"",
    "cd \"$ROOT\"",
    "\"$DOCKER_BIN\" compose exec -T app python - \"$@\" < scripts/healthcheck-br-wissen.py",
]


FORBIDDEN_HEALTHCHECK_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
    "COMMIT",
    "conn.commit",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
    "subprocess.run",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen healthcheck source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    health_text = read_source(HEALTHCHECK, findings, "healthcheck")
    wrapper_text = read_source(WRAPPER, findings, "healthcheck_wrapper")
    checks += 2

    for literal in HEALTHCHECK_LITERALS:
        checks += 1
        if literal not in health_text:
            findings.append("healthcheck_missing_literal=%s" % safe(literal))

    for marker in FAILURE_MARKERS:
        checks += 1
        if marker not in health_text:
            findings.append("failure_marker_missing=%s" % safe(marker))

    for marker in SUMMARY_MARKERS:
        checks += 1
        if marker not in health_text:
            findings.append("summary_marker_missing=%s" % safe(marker))

    for literal in WRAPPER_LITERALS:
        checks += 1
        if literal not in wrapper_text:
            findings.append("wrapper_missing_literal=%s" % safe(literal))

    for marker in FORBIDDEN_HEALTHCHECK_MARKERS:
        checks += 1
        if marker in health_text:
            findings.append("forbidden_healthcheck_marker=%s" % safe(marker))

    checks += 1
    if health_text.find("summary_only =") > health_text.find("json.dumps(summary"):
        findings.append("summary_mode_after_summary_output")
    checks += 1
    if health_text.find("failures: list[str]") > health_text.find("return 0 if not failures else 1"):
        findings.append("failures_declared_after_return")
    checks += 1
    if wrapper_text.find("cd \"$ROOT\"") > wrapper_text.find("compose exec -T app python"):
        findings.append("wrapper_docker_before_cd")

    status = "ok" if not findings else "failed"
    summary = "healthcheck_source_hardening_status=%s checks=%d findings=%d health_literals=%d failure_markers=%d summary_markers=%d wrapper_literals=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(HEALTHCHECK_LITERALS),
        len(FAILURE_MARKERS),
        len(SUMMARY_MARKERS),
        len(WRAPPER_LITERALS),
        len(FORBIDDEN_HEALTHCHECK_MARKERS),
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
