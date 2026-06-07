#!/usr/bin/env python3
"""Read-only DB schema/index guard for BR-Wissen."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


ROOT = Path("/home/chris/web/br.m11h.eu")
DOCKER = Path("/usr/bin/docker")

EXPECTED_EXTENSION = "vector"
EXPECTED_TABLES = {
    "sources",
    "documents",
    "chunks",
    "queries",
    "answers",
    "answer_statements",
    "answer_citations",
    "cases",
    "audit_log",
}
EXPECTED_COLUMNS = {
    "sources": {"id", "source_uid", "title", "source_type", "source_class", "public_url", "internal_ref", "local_path", "status", "confidentiality", "citation_allowed", "hint_only", "valid_from", "source_date", "last_checked_at", "sha256", "metadata", "created_at", "updated_at"},
    "documents": {"id", "source_id", "document_uid", "title", "original_path", "text_path", "ocr_path", "table_path", "sha256", "page_count", "ocr_status", "created_at", "updated_at"},
    "chunks": {"id", "document_id", "chunk_uid", "heading", "locator", "content", "content_tsv", "embedding", "source_class", "citation_label", "citation_url", "internal_ref", "created_at"},
    "queries": {"id", "query_uid", "query_type", "title", "question", "selected_source_profile", "status", "created_by", "created_at"},
    "answers": {"id", "query_id", "answer_uid", "status", "html_path", "pdf_path", "fingerprint", "created_at", "updated_at"},
    "answer_statements": {"id", "answer_id", "section", "statement_text", "created_at"},
    "answer_citations": {"id", "statement_id", "chunk_id", "citation_label", "citation_url", "internal_ref", "source_class", "created_at"},
    "cases": {"id", "case_uid", "title", "topic", "status", "created_at", "updated_at"},
    "audit_log": {"id", "actor", "action", "object_type", "object_uid", "details", "created_at"},
}
EXPECTED_INDEXES = {
    "sources_source_uid_key",
    "documents_document_uid_key",
    "chunks_chunk_uid_key",
    "queries_query_uid_key",
    "answers_answer_uid_key",
    "cases_case_uid_key",
    "idx_chunks_tsv",
    "idx_sources_class_status",
    "idx_documents_source",
    "idx_sources_citation_status",
    "idx_sources_last_checked",
    "idx_documents_sha256",
    "idx_chunks_document",
    "idx_chunks_source_class",
    "idx_answers_query",
    "idx_answers_created_at",
    "idx_answers_export_paths",
    "idx_answer_statements_answer",
    "idx_answer_citations_statement",
    "idx_answer_citations_chunk",
    "idx_answer_citations_source_class",
    "idx_audit_log_action_created",
    "idx_audit_log_object",
}


def helper_available(path: Path) -> bool:
    return path.exists() and not path.is_symlink() and path.is_file()


def psql(sql: str) -> list[str]:
    if not helper_available(DOCKER):
        return ["__query_failed__"]
    proc = subprocess.run(
        [str(DOCKER), "compose", "exec", "-T", "db", "psql", "-U", "br_app", "-d", "br_wissen", "-Atc", sql],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return ["__query_failed__"]
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen DB schema")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    extensions = set(psql("SELECT extname FROM pg_extension"))
    tables = set(psql("SELECT tablename FROM pg_tables WHERE schemaname='public'"))
    indexes = set(psql("SELECT indexname FROM pg_indexes WHERE schemaname='public'"))
    column_rows = psql("SELECT table_name || '.' || column_name FROM information_schema.columns WHERE table_schema='public'")
    columns_by_table: dict[str, set[str]] = {table: set() for table in EXPECTED_TABLES}
    for row in column_rows:
        if "." in row:
            table, column = row.split(".", 1)
            columns_by_table.setdefault(table, set()).add(column)

    if EXPECTED_EXTENSION not in extensions:
        findings.append("missing extension: %s" % EXPECTED_EXTENSION)
    missing_tables = sorted(EXPECTED_TABLES - tables)
    if missing_tables:
        findings.append("missing tables: %d" % len(missing_tables))
    for table, expected_columns in sorted(EXPECTED_COLUMNS.items()):
        missing = sorted(expected_columns - columns_by_table.get(table, set()))
        if missing:
            findings.append("missing columns %s: %d" % (table, len(missing)))
    missing_indexes = sorted(EXPECTED_INDEXES - indexes)
    if missing_indexes:
        findings.append("missing indexes: %d" % len(missing_indexes))

    status = "ok" if not findings else "failed"
    checks = 1 + len(EXPECTED_TABLES) + len(EXPECTED_COLUMNS) + len(EXPECTED_INDEXES)
    if args.summary:
        print(
            "db_schema_status=%s checks=%d findings=%d tables=%d indexes=%d expected_indexes=%d"
            % (status, checks, len(findings), len(tables), len(indexes), len(EXPECTED_INDEXES))
        )
    else:
        print("db_schema_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("tables=%d" % len(tables))
        print("indexes=%d" % len(indexes))
        print("expected_indexes=%d" % len(EXPECTED_INDEXES))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
