#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen data/integrity guards.

The guard validates answer/export safety, audit-trail and DB-schema guard sources
for expected counter-only SQL checks, metadata-only export checks, explicit
legacy audit exceptions, schema/index expectations and compact summaries. It only
reads project source files; it does not run Docker, database queries, backups,
restores, imports or regressions and never reads secrets, dumps, logs, answers,
exports or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
ANSWER_EXPORT = ROOT / "scripts" / "check-answer-export-safety.py"
AUDIT_TRAIL = ROOT / "scripts" / "check-audit-trail.py"
DB_SCHEMA = ROOT / "scripts" / "check-db-schema.py"


ANSWER_EXPORT_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only safety guard for generated answers and exports"),
    ("docstring_no_text", "without\nprinting answer text, source text, dump contents or secret values"),
    ("storage_root", "STORAGE_ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))"),
    ("export_root", "EXPORT_ROOT = STORAGE_ROOT / \"exports\""),
    ("path_markers", "PATH_MARKERS = ["),
    ("secret_markers", "SECRET_MARKERS = ["),
    ("direct_file_markers", "DIRECT_FILE_MARKERS = [\"file://\", \"../\", \"..\\\\\"]"),
    ("db_metrics", "def db_metrics()"),
    ("answers_without_statements", "answers_without_statements="),
    ("statements_without_citation", "statements_without_citation="),
    ("citations_without_chunk_or_ref", "citations_without_chunk_or_ref="),
    ("recent_gelb_citations", "recent_gelb_citations="),
    ("class_mismatches", "answer_class_mismatches="),
    ("partial_export_paths", "answers_with_partial_export_paths="),
    ("docker_psql", "docker",),
    ("psql_readonly", "psql"),
    ("db_export_paths", "def db_export_paths()"),
    ("export_path_query", "SELECT answer_uid || E'\\\\t' || coalesce(html_path,'') || E'\\\\t' || coalesce(pdf_path,'')"),
    ("marker_hits", "def marker_hits(text: str, markers: list[str])"),
    ("windows_drive_regex", r"\b[A-Za-z]:\\"),
    ("read_text_guarded", "def read_text_guarded(path: Path)"),
    ("sudo_read_guarded", "sudo"),
    ("sha256_guarded", "def sha256_file_guarded(path: Path)"),
    ("read_json_guarded", "def read_json_guarded(path: Path)"),
    ("export_checks", "def export_checks(paths: list[tuple[str, str, str]])"),
    ("storage_prefix", "storage_prefix = str(STORAGE_ROOT.resolve()) + os.sep"),
    ("outside_storage", "path outside storage"),
    ("noindex", "html_missing_noindex"),
    ("watermark", "html_missing_internal_watermark"),
    ("manifest", "manifest.json"),
    ("manifest_version", "manifest_version_mismatch"),
    ("manifest_answer", "manifest_answer_mismatch"),
    ("manifest_policy", "manifest_policy_mismatch"),
    ("manifest_hash", "manifest_file_hash_mismatch"),
    ("summary", "answer_export_safety_status=%s checks=%d findings=%d answers_without_statements=%s statements_without_citation=%s html_checked=%s pdf_checked=%s"),
]


AUDIT_TRAIL_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only audit-trail guard for BR-Wissen"),
    ("docstring_counters_only", "checks audit coverage and consistency using counters only"),
    ("docstring_no_details", "never\nprints answer text, source content, secret values or audit detail JSON"),
    ("root", "ROOT = Path(\"/home/chris/web/br.m11h.eu\")"),
    ("legacy_export_gaps", "LEGACY_EXPORT_AUDIT_GAPS = {"),
    ("legacy_answer_gap", "LEGACY_ANSWER_CREATE_AUDIT_GAPS = {\"a-src-test-0784dcd7\"}"),
    ("run_sql", "def run_sql(sql: str)"),
    ("docker_psql", "docker",),
    ("scalar_metrics", "def scalar_metrics()"),
    ("audit_rows", "audit_rows="),
    ("actor_empty", "audit_actor_empty="),
    ("action_empty", "audit_action_empty="),
    ("object_uid_empty", "audit_object_uid_empty="),
    ("future_rows", "audit_future_rows="),
    ("unknown_actions", "audit_unknown_actions="),
    ("known_actions", "action NOT IN ("),
    ("answer_create_rows", "answer_create_audit_rows="),
    ("export_rows", "validated_export_audit_rows="),
    ("manifest_backfill_rows", "manifest_backfill_audit_rows="),
    ("uid_list", "def uid_list(sql: str)"),
    ("missing_create_sql", "NOT EXISTS (\n          SELECT 1 FROM audit_log l"),
    ("unexpected_create", "unexpected answer create audit gaps=%d"),
    ("missing_exports_sql", "coalesce(a.html_path,'')<>'' AND coalesce(a.pdf_path,'')<>''"),
    ("unexpected_exports", "unexpected export audit gaps=%d"),
    ("summary", "audit_trail_status=%s checks=%d findings=%d audit_rows=%s answer_create_audit_rows=%s export_audit_rows=%s legacy_export_gaps=%d"),
]


DB_SCHEMA_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only DB schema/index guard for BR-Wissen"),
    ("root", "ROOT = Path(\"/home/chris/web/br.m11h.eu\")"),
    ("expected_extension", "EXPECTED_EXTENSION = \"vector\""),
    ("expected_tables", "EXPECTED_TABLES = {"),
    ("sources_table", '"sources"'),
    ("documents_table", '"documents"'),
    ("chunks_table", '"chunks"'),
    ("queries_table", '"queries"'),
    ("answers_table", '"answers"'),
    ("answer_statements_table", '"answer_statements"'),
    ("answer_citations_table", '"answer_citations"'),
    ("cases_table", '"cases"'),
    ("audit_log_table", '"audit_log"'),
    ("expected_columns", "EXPECTED_COLUMNS = {"),
    ("expected_indexes", "EXPECTED_INDEXES = {"),
    ("vector_index", "idx_chunks_tsv"),
    ("source_index", "idx_sources_class_status"),
    ("audit_index", "idx_audit_log_action_created"),
    ("psql", "def psql(sql: str)"),
    ("pg_extension", "SELECT extname FROM pg_extension"),
    ("pg_tables", "SELECT tablename FROM pg_tables WHERE schemaname='public'"),
    ("pg_indexes", "SELECT indexname FROM pg_indexes WHERE schemaname='public'"),
    ("information_schema", "information_schema.columns"),
    ("missing_extension", "missing extension: %s"),
    ("missing_tables", "missing tables: %d"),
    ("missing_columns", "missing columns %s: %d"),
    ("missing_indexes", "missing indexes: %d"),
    ("summary", "db_schema_status=%s checks=%d findings=%d tables=%d indexes=%d expected_indexes=%d"),
]


FORBIDDEN_COMMON_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
    "conn.commit",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
    "docker compose up",
    "docker compose down",
    "docker compose restart",
    "docker compose rm",
    "docker rm",
    "docker volume rm",
    "docker rmi",
    "docker system prune",
    "pg_dump",
    "restic ",
    "/srv/br-wissensdatenbank/backups",
    "/srv/br-wissensdatenbank/logs",
    "/srv/br-wissensdatenbank/secrets",
    "/run/br-secrets/",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def check_markers(findings: list[str], text: str, markers: list[tuple[str, str]], prefix: str) -> int:
    checks = 0
    for label, marker in markers:
        checks += 1
        if marker not in text:
            findings.append("%s_missing=%s" % (prefix, safe(label)))
    return checks


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen data/integrity source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    answer_text = read_source(ANSWER_EXPORT, findings, "answer_export_safety")
    audit_text = read_source(AUDIT_TRAIL, findings, "audit_trail")
    db_text = read_source(DB_SCHEMA, findings, "db_schema")
    checks += 3

    checks += check_markers(findings, answer_text, ANSWER_EXPORT_MARKERS, "answer_export")
    checks += check_markers(findings, audit_text, AUDIT_TRAIL_MARKERS, "audit")
    checks += check_markers(findings, db_text, DB_SCHEMA_MARKERS, "db_schema")

    for prefix, text in [
        ("answer_export", answer_text),
        ("audit", audit_text),
        ("db_schema", db_text),
    ]:
        checks += check_forbidden(findings, text, FORBIDDEN_COMMON_MARKERS, prefix)

    checks += 1
    if answer_text.find("PATH_MARKERS") > answer_text.find("marker_hits(text, PATH_MARKERS)"):
        findings.append("answer_export_path_markers_after_use")
    checks += 1
    if audit_text.find("LEGACY_EXPORT_AUDIT_GAPS") > audit_text.find("missing_exports - LEGACY_EXPORT_AUDIT_GAPS"):
        findings.append("audit_legacy_gaps_after_use")
    checks += 1
    if db_text.find("EXPECTED_TABLES") > db_text.find("EXPECTED_TABLES - tables"):
        findings.append("db_schema_expected_tables_after_use")

    status = "ok" if not findings else "failed"
    summary = "data_integrity_source_hardening_status=%s checks=%d findings=%d answer_export_markers=%d audit_markers=%d db_schema_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(ANSWER_EXPORT_MARKERS),
        len(AUDIT_TRAIL_MARKERS),
        len(DB_SCHEMA_MARKERS),
        len(FORBIDDEN_COMMON_MARKERS) * 3,
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
