#!/usr/bin/env python3
"""Read-only regression freshness guard for BR-Wissen.

The guard verifies that the core regression queries still have recent enough
answers with statements, direct citations, required source classes/sources and
export artifacts. It does not create new answers, exports or database rows and it
does not print answer text, source text, secret values, dump contents or log
contents.
"""

from __future__ import annotations

import argparse
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))

CASES: list[dict[str, Any]] = [
    {
        "name": "ocr_tariff_jobservice_corona",
        "query_uid": "test-ocr-corona-jobservice",
        "allowed_classes": {"GRUEN", "BLAU"},
        "required_classes": {"BLAU"},
        "required_sources": {"evg-member-db-jobservice---corona-beihilfen-zusatzvereinbarung-85583f7c51f9"},
    },
    {
        "name": "bag_tarifkollision_green_only",
        "query_uid": "test-bag-tarifkollision-4a-tvg",
        "allowed_classes": {"GRUEN"},
        "required_classes": {"GRUEN"},
        "required_sources": {"bag-entscheidung-4-azr-101-25"},
    },
    {
        "name": "dsgvo_bdsg_green_only",
        "query_uid": "test-dsgvo-art-5-6-bdsg-26",
        "allowed_classes": {"GRUEN"},
        "required_classes": {"GRUEN"},
        "required_sources": {"gesetz-dsgvo", "gesetz-bdsg"},
    },
    {
        "name": "tariff_demografietv_dedupe",
        "query_uid": "test-tarif-demografie-evg",
        "allowed_classes": {"GRUEN", "BLAU"},
        "required_classes": {"BLAU"},
        "required_sources": {"m00h-25-05-21-2025-04-30-demografietv-bus-2025-final-unterzeichnet"},
    },
]


def sql_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(ROOT), text=True, capture_output=True, check=False)


def parse_key_values(stdout: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def db_case_metrics(query_uid: str) -> tuple[int, dict[str, str]]:
    query_lit = sql_quote(query_uid)
    sql = f"""
WITH latest AS (
  SELECT a.id, a.answer_uid, a.created_at, coalesce(a.html_path,'') AS html_path, coalesce(a.pdf_path,'') AS pdf_path
  FROM answers a
  JOIN queries q ON q.id=a.query_id
  WHERE q.query_uid={query_lit}
  ORDER BY a.created_at DESC
  LIMIT 1
), rows AS (
  SELECT st.id AS statement_id, cit.id AS citation_id, cit.chunk_id, cit.source_class, s.source_uid, d.sha256 AS document_sha256
  FROM latest l
  JOIN answer_statements st ON st.answer_id=l.id
  LEFT JOIN answer_citations cit ON cit.statement_id=st.id
  LEFT JOIN chunks c ON c.id=cit.chunk_id
  LEFT JOIN documents d ON d.id=c.document_id
  LEFT JOIN sources s ON s.id=d.source_id
), duplicate_chunks AS (
  SELECT chunk_id FROM rows WHERE chunk_id IS NOT NULL GROUP BY chunk_id HAVING count(*) > 1
), mixed_sha AS (
  SELECT document_sha256 FROM rows WHERE document_sha256 IS NOT NULL AND source_uid IS NOT NULL GROUP BY document_sha256 HAVING count(DISTINCT source_uid) > 1
)
SELECT 'answer_uid=' || coalesce((SELECT answer_uid FROM latest), '')
UNION ALL SELECT 'created_at_epoch=' || coalesce((SELECT extract(epoch FROM created_at)::bigint::text FROM latest), '0')
UNION ALL SELECT 'html_path=' || coalesce((SELECT html_path FROM latest), '')
UNION ALL SELECT 'pdf_path=' || coalesce((SELECT pdf_path FROM latest), '')
UNION ALL SELECT 'statement_count=' || (SELECT count(*)::text FROM rows)
UNION ALL SELECT 'citation_count=' || (SELECT count(citation_id)::text FROM rows)
UNION ALL SELECT 'statements_without_citation=' || (SELECT count(*)::text FROM rows WHERE citation_id IS NULL)
UNION ALL SELECT 'source_classes=' || coalesce((SELECT string_agg(DISTINCT source_class, ',' ORDER BY source_class) FROM rows WHERE source_class IS NOT NULL), '')
UNION ALL SELECT 'source_uids=' || coalesce((SELECT string_agg(DISTINCT source_uid, ',' ORDER BY source_uid) FROM rows WHERE source_uid IS NOT NULL), '')
UNION ALL SELECT 'duplicate_chunk_ids=' || (SELECT count(*)::text FROM duplicate_chunks)
UNION ALL SELECT 'mixed_document_sha_groups=' || (SELECT count(*)::text FROM mixed_sha);
"""
    proc = run([
        "docker", "compose", "exec", "-T", "db", "psql", "-U", "br_app", "-d", "br_wissen", "-Atc", sql
    ])
    return proc.returncode, parse_key_values(proc.stdout)


def age_hours_from_epoch(value: str) -> float:
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return 999999.0
    if epoch <= 0:
        return 999999.0
    return max(0.0, (datetime.now(timezone.utc).timestamp() - epoch) / 3600.0)


def guarded_file_size(path_value: str) -> tuple[bool, int]:
    if not path_value:
        return False, 0
    path = Path(path_value)
    storage_prefix = str(STORAGE_ROOT.resolve()) + os.sep
    if not path.is_absolute() or not str(path).startswith(storage_prefix):
        return False, 0
    try:
        return path.is_file(), path.stat().st_size if path.is_file() else 0
    except PermissionError:
        proc = run(["sudo", "-n", "stat", "-c", "%s", str(path)])
        if proc.returncode != 0:
            return False, 0
        try:
            return True, int(proc.stdout.strip())
        except ValueError:
            return False, 0


def split_set(value: str) -> set[str]:
    return {part for part in value.split(",") if part}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen regression freshness")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=float(os.getenv("BR_REGRESSION_MAX_AGE_HOURS", "720")),
        help="maximum allowed age of latest core regression answers",
    )
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    case_summaries: list[str] = []
    max_age_h = 0.0
    min_age_h = 999999.0
    exported_cases = 0

    for case in CASES:
        checks += 1
        code, metrics = db_case_metrics(str(case["query_uid"]))
        name = str(case["name"])
        if code != 0:
            findings.append("case_db_query_failed=%s" % name)
            continue

        answer_uid = metrics.get("answer_uid", "")
        if not answer_uid:
            findings.append("case_missing_answer=%s" % name)
            continue

        age_h = age_hours_from_epoch(metrics.get("created_at_epoch", "0"))
        max_age_h = max(max_age_h, age_h)
        min_age_h = min(min_age_h, age_h)
        checks += 1
        if age_h > args.max_age_hours:
            findings.append("case_answer_too_old=%s age_h=%.1f" % (name, age_h))

        statement_count = int(metrics.get("statement_count") or 0)
        citation_count = int(metrics.get("citation_count") or 0)
        statements_without_citation = int(metrics.get("statements_without_citation") or 0)
        checks += 3
        if statement_count <= 0:
            findings.append("case_no_statements=%s" % name)
        if citation_count != statement_count:
            findings.append("case_citation_statement_mismatch=%s" % name)
        if statements_without_citation != 0:
            findings.append("case_statements_without_citation=%s" % name)

        source_classes = split_set(metrics.get("source_classes", ""))
        source_uids = split_set(metrics.get("source_uids", ""))
        allowed_classes = set(case["allowed_classes"])
        required_classes = set(case["required_classes"])
        required_sources = set(case["required_sources"])
        checks += 3
        if not source_classes <= allowed_classes:
            findings.append("case_disallowed_classes=%s" % name)
        if not required_classes <= source_classes:
            findings.append("case_required_classes_missing=%s" % name)
        if not required_sources <= source_uids:
            findings.append("case_required_sources_missing=%s" % name)

        checks += 2
        if int(metrics.get("duplicate_chunk_ids") or 0) != 0:
            findings.append("case_duplicate_chunk_ids=%s" % name)
        if int(metrics.get("mixed_document_sha_groups") or 0) != 0:
            findings.append("case_mixed_document_sha_groups=%s" % name)

        html_ok, html_size = guarded_file_size(metrics.get("html_path", ""))
        pdf_ok, pdf_size = guarded_file_size(metrics.get("pdf_path", ""))
        manifest_path = str(Path(metrics.get("html_path", "")).parent / "manifest.json") if metrics.get("html_path") else ""
        manifest_ok, manifest_size = guarded_file_size(manifest_path)
        checks += 3
        if not html_ok:
            findings.append("case_missing_html=%s" % name)
        if not pdf_ok or pdf_size < 10_000:
            findings.append("case_missing_or_small_pdf=%s" % name)
        if not manifest_ok or manifest_size < 100:
            findings.append("case_missing_or_small_manifest=%s" % name)
        if html_ok and pdf_ok and manifest_ok:
            exported_cases += 1

        case_summaries.append("%s:%s:age_h=%.1f" % (name, answer_uid, age_h))

    if min_age_h == 999999.0:
        min_age_h = 0.0
    status = "ok" if not findings else "failed"

    if args.summary:
        print(
            "regression_freshness_status=%s checks=%d findings=%d cases=%d exported_cases=%d max_age_h=%.1f min_age_h=%.1f"
            % (status, checks, len(findings), len(CASES), exported_cases, max_age_h, min_age_h)
        )
    else:
        print("regression_freshness_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("cases=%d" % len(CASES))
        print("exported_cases=%d" % exported_cases)
        print("max_age_h=%.1f" % max_age_h)
        print("min_age_h=%.1f" % min_age_h)
        for item in case_summaries:
            print("case=%s" % item)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
