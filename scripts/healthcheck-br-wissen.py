#!/usr/bin/env python3
"""Operational health check for the BR knowledge base.

This check is intentionally read-only. It verifies the current database/file
state without creating answers or modifying sources.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

import psycopg


STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
DATABASE_URL = os.environ["BR_DATABASE_URL"]


def rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [desc.name for desc in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
    result = rows(sql, params)
    return result[0] if result else {}


def table_counts() -> dict[str, int]:
    result: dict[str, int] = {}
    for table in ["sources", "documents", "chunks", "queries", "answers", "answer_statements", "answer_citations"]:
        result[table] = int(one("SELECT count(*) AS n FROM %s" % table)["n"])
    return result


def source_class_counts() -> list[dict[str, Any]]:
    return rows(
        """
        SELECT source_class, count(*) AS sources,
               sum(CASE WHEN citation_allowed THEN 1 ELSE 0 END) AS approved
        FROM sources
        GROUP BY source_class
        ORDER BY source_class
        """
    )


def source_type_counts() -> list[dict[str, Any]]:
    return rows(
        """
        SELECT source_type, source_class, count(*) AS sources,
               sum(CASE WHEN citation_allowed THEN 1 ELSE 0 END) AS approved
        FROM sources
        GROUP BY source_type, source_class
        ORDER BY source_class, source_type
        """
    )


def chunkless_sources(approved_only: bool) -> list[dict[str, Any]]:
    where = "WHERE s.citation_allowed=true" if approved_only else ""
    return rows(
        """
        SELECT s.source_uid, s.title, s.source_class, s.source_type, s.citation_allowed,
               count(c.id) AS chunk_count
        FROM sources s
        LEFT JOIN documents d ON d.source_id=s.id
        LEFT JOIN chunks c ON c.document_id=d.id
        %s
        GROUP BY s.id
        HAVING count(c.id)=0
        ORDER BY s.source_class, s.source_type, s.source_uid
        LIMIT 50
        """
        % where
    )


def duplicate_document_sha_groups() -> list[dict[str, Any]]:
    return rows(
        """
        SELECT d.sha256, count(*) AS document_count, count(DISTINCT s.source_uid) AS source_count,
               array_agg(DISTINCT s.source_uid ORDER BY s.source_uid) AS source_uids
        FROM documents d
        JOIN sources s ON s.id=d.source_id
        WHERE d.sha256 IS NOT NULL AND d.sha256 <> ''
        GROUP BY d.sha256
        HAVING count(*) > 1 OR count(DISTINCT s.source_uid) > 1
        ORDER BY document_count DESC, source_count DESC, d.sha256
        LIMIT 50
        """
    )


def ocr_status_counts() -> list[dict[str, Any]]:
    return rows(
        """
        SELECT COALESCE(ocr_status, 'unknown') AS ocr_status, count(*) AS documents
        FROM documents
        GROUP BY COALESCE(ocr_status, 'unknown')
        ORDER BY ocr_status
        """
    )


def repaired_ocr_integrity() -> dict[str, Any]:
    documents = rows(
        """
        SELECT d.id, d.text_path, count(c.id) AS chunk_count
        FROM documents d
        LEFT JOIN chunks c ON c.document_id=d.id
        WHERE d.ocr_status='ocr_repaired_tesseract'
        GROUP BY d.id
        ORDER BY d.id
        """
    )
    sizes: list[int] = []
    missing_text_paths = 0
    repaired_without_chunks = 0
    for document in documents:
        if int(document.get("chunk_count") or 0) == 0:
            repaired_without_chunks += 1
        text_path = document.get("text_path")
        if not text_path:
            missing_text_paths += 1
            continue
        path = Path(str(text_path))
        if not path.exists():
            missing_text_paths += 1
            continue
        sizes.append(path.stat().st_size)
    return {
        "repaired_documents": len(documents),
        "repaired_without_chunks": repaired_without_chunks,
        "missing_text_paths": missing_text_paths,
        "min_text_size": min(sizes) if sizes else None,
        "max_text_size": max(sizes) if sizes else None,
    }


def export_counts() -> dict[str, Any]:
    export_root = STORAGE_ROOT / "exports"
    dirs = [path for path in export_root.iterdir() if path.is_dir()] if export_root.exists() else []
    html_count = sum(1 for path in dirs if (path / "index.html").exists())
    pdf_count = sum(1 for path in dirs if (path / "export.pdf").exists())
    return {"export_dirs": len(dirs), "html_exports": html_count, "pdf_exports": pdf_count}


def recent_answers() -> list[dict[str, Any]]:
    return rows(
        """
        SELECT a.answer_uid, a.status, a.created_at, q.query_uid,
               count(st.id) AS statement_count,
               count(cit.id) AS citation_count,
               sum(CASE WHEN cit.id IS NULL THEN 1 ELSE 0 END) AS statements_without_citation
        FROM answers a
        JOIN queries q ON q.id=a.query_id
        LEFT JOIN answer_statements st ON st.answer_id=a.id
        LEFT JOIN answer_citations cit ON cit.statement_id=st.id
        GROUP BY a.id, q.id
        ORDER BY a.created_at DESC
        LIMIT 10
        """
    )


def source_integrity() -> dict[str, Any]:
    invalid_status = rows(
        """
        SELECT status, count(*) AS sources
        FROM sources
        WHERE status NOT IN ('importiert','technisch_geprueft','inhaltlich_eingeordnet','freigegeben','veraltet','gesperrt')
        GROUP BY status
        ORDER BY status
        """
    )
    invalid_class = rows(
        """
        SELECT source_class, count(*) AS sources
        FROM sources
        WHERE source_class NOT IN ('GRUEN','BLAU','GELB','GRAU','ROT')
        GROUP BY source_class
        ORDER BY source_class
        """
    )
    counts = one(
        """
        SELECT
          (SELECT count(*) FROM sources WHERE status='freigegeben' AND citation_allowed=false) AS freigegeben_not_allowed,
          (SELECT count(*) FROM sources WHERE citation_allowed=true AND status <> 'freigegeben') AS citation_allowed_not_freigegeben,
          (SELECT count(*) FROM sources WHERE hint_only=true AND source_class NOT IN ('GELB','GRAU')) AS hint_only_wrong_class,
          (SELECT count(*) FROM sources WHERE hint_only=true AND citation_allowed=true) AS hint_only_approved,
          (SELECT count(*) FROM sources WHERE source_class='GRUEN' AND coalesce(public_url,'')='') AS green_missing_public_url,
          (SELECT count(*) FROM sources WHERE coalesce(sha256,'')='') AS source_sha_missing,
          (SELECT count(*) FROM documents WHERE coalesce(sha256,'')='') AS document_sha_missing,
          (SELECT count(*) FROM sources s LEFT JOIN documents d ON d.source_id=s.id WHERE d.id IS NULL) AS sources_without_documents,
          (SELECT count(*) FROM chunks c JOIN documents d ON d.id=c.document_id JOIN sources s ON s.id=d.source_id WHERE c.source_class <> s.source_class) AS chunk_class_mismatches,
          (SELECT count(DISTINCT d.id) FROM documents d LEFT JOIN chunks c ON c.document_id=d.id JOIN sources s ON s.id=d.source_id WHERE s.citation_allowed=true GROUP BY d.id HAVING count(c.id)=0 LIMIT 1) AS approved_document_without_chunks_sample,
          (SELECT count(*) FROM answer_citations WHERE source_class='GELB' AND created_at >= now() - interval '30 days') AS recent_gelb_answer_citations
        """
    )
    path_rows = rows(
        """
        SELECT 'source' AS kind, source_uid AS uid, local_path AS path
        FROM sources
        WHERE local_path IS NOT NULL AND local_path <> ''
        UNION ALL
        SELECT 'document_original' AS kind, document_uid AS uid, original_path AS path
        FROM documents
        WHERE original_path IS NOT NULL AND original_path <> ''
        UNION ALL
        SELECT 'document_text' AS kind, document_uid AS uid, text_path AS path
        FROM documents
        WHERE text_path IS NOT NULL AND text_path <> ''
        UNION ALL
        SELECT 'document_ocr' AS kind, document_uid AS uid, ocr_path AS path
        FROM documents
        WHERE ocr_path IS NOT NULL AND ocr_path <> ''
        """
    )
    missing_paths: list[dict[str, str]] = []
    outside_storage_paths: list[dict[str, str]] = []
    storage_prefix = str(STORAGE_ROOT.resolve()) + os.sep
    for item in path_rows:
        value = str(item.get("path") or "")
        path = Path(value)
        if not path.is_absolute() or not str(path).startswith(storage_prefix):
            outside_storage_paths.append({"kind": str(item.get("kind")), "uid": str(item.get("uid"))})
            continue
        if not path.exists():
            missing_paths.append({"kind": str(item.get("kind")), "uid": str(item.get("uid"))})
    return {
        "invalid_status": invalid_status,
        "invalid_class": invalid_class,
        "counts": counts,
        "missing_paths": missing_paths[:25],
        "missing_path_count": len(missing_paths),
        "outside_storage_paths": outside_storage_paths[:25],
        "outside_storage_path_count": len(outside_storage_paths),
    }


def main() -> int:
    summary_only = "--summary" in sys.argv[1:]
    pretty_summary = "--pretty" in sys.argv[1:]
    if any(arg not in {"--summary", "--pretty"} for arg in sys.argv[1:]) or (pretty_summary and not summary_only):
        print("Usage: healthcheck-br-wissen.py [--summary [--pretty]]", file=sys.stderr)
        return 2
    counts = table_counts()
    approved_chunkless = chunkless_sources(approved_only=True)
    all_chunkless = chunkless_sources(approved_only=False)
    duplicate_sha = duplicate_document_sha_groups()
    repaired = repaired_ocr_integrity()
    exports = export_counts()
    recent = recent_answers()
    integrity = source_integrity()

    failures: list[str] = []
    if counts["sources"] <= 0 or counts["documents"] <= 0 or counts["chunks"] <= 0:
        failures.append("empty core table count")
    if approved_chunkless:
        failures.append("approved sources without chunks: %d" % len(approved_chunkless))
    if int(repaired.get("repaired_without_chunks") or 0) != 0:
        failures.append("repaired OCR documents without chunks")
    if int(repaired.get("missing_text_paths") or 0) != 0:
        failures.append("repaired OCR documents with missing text paths")
    if int(repaired.get("repaired_documents") or 0) > 0 and int(repaired.get("min_text_size") or 0) < 200:
        failures.append("repaired OCR min text size below threshold")
    for item in recent:
        if int(item.get("statements_without_citation") or 0) != 0:
            failures.append("recent answer without citation: %s" % item.get("answer_uid"))
    if exports["html_exports"] != exports["pdf_exports"]:
        failures.append("html/pdf export count mismatch")
    integrity_counts = integrity.get("counts") or {}
    if integrity.get("invalid_status"):
        failures.append("invalid source status values")
    if integrity.get("invalid_class"):
        failures.append("invalid source class values")
    for key in [
        "freigegeben_not_allowed",
        "citation_allowed_not_freigegeben",
        "hint_only_wrong_class",
        "green_missing_public_url",
        "source_sha_missing",
        "document_sha_missing",
        "sources_without_documents",
        "chunk_class_mismatches",
        "recent_gelb_answer_citations",
    ]:
        if int(integrity_counts.get(key) or 0) != 0:
            failures.append("source integrity violation: %s" % key)
    if int(integrity.get("missing_path_count") or 0) != 0:
        failures.append("source/document paths missing on disk")
    if int(integrity.get("outside_storage_path_count") or 0) != 0:
        failures.append("source/document paths outside storage root")

    result = {
        "status": "ok" if not failures else "failed",
        "failures": failures,
        "counts": counts,
        "source_class_counts": source_class_counts(),
        "source_type_counts": source_type_counts(),
        "approved_chunkless_sources": approved_chunkless,
        "all_chunkless_sources_sample": all_chunkless,
        "duplicate_document_sha_groups": duplicate_sha,
        "ocr_status_counts": ocr_status_counts(),
        "repaired_ocr_integrity": repaired,
        "exports": exports,
        "recent_answers": recent,
        "source_integrity": integrity,
    }
    if summary_only:
        summary = {
            "status": result["status"],
            "failures": failures,
            "counts": {key: counts[key] for key in ["sources", "documents", "chunks", "queries", "answers"]},
            "approved_chunkless_sources": len(approved_chunkless),
            "duplicate_document_sha_groups": len(duplicate_sha),
            "repaired_ocr_integrity": repaired,
            "exports": exports,
            "source_integrity": {
                "invalid_status": len(integrity.get("invalid_status") or []),
                "invalid_class": len(integrity.get("invalid_class") or []),
                "counts": integrity.get("counts") or {},
                "missing_path_count": integrity.get("missing_path_count") or 0,
                "outside_storage_path_count": integrity.get("outside_storage_path_count") or 0,
            },
        }
        indent = 2 if pretty_summary else None
        print(json.dumps(summary, ensure_ascii=False, indent=indent, separators=(",", ":"), default=str))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
