#!/usr/bin/env python3
"""Read-only report for duplicate document SHA groups.

The report does not delete, merge, or reclassify anything. It only makes the
known duplicate-import situation auditable and highlights whether all duplicate
documents have chunks and whether canonical answer-time SHA dedupe can handle
them.
"""

import json
import os
from typing import Any

import psycopg


DATABASE_URL = os.environ["BR_DATABASE_URL"]


def rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [desc.name for desc in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]


def duplicate_groups() -> list[dict[str, Any]]:
    groups = rows(
        """
        SELECT d.sha256,
               count(*) AS document_count,
               count(DISTINCT s.source_uid) AS source_count,
               sum(CASE WHEN s.citation_allowed THEN 1 ELSE 0 END) AS approved_sources,
               min(d.created_at) AS first_seen,
               max(d.created_at) AS last_seen
        FROM documents d
        JOIN sources s ON s.id=d.source_id
        WHERE d.sha256 IS NOT NULL AND d.sha256 <> ''
        GROUP BY d.sha256
        HAVING count(*) > 1 OR count(DISTINCT s.source_uid) > 1
        ORDER BY document_count DESC, source_count DESC, d.sha256
        """
    )
    for group in groups:
        group["documents"] = rows(
            """
            SELECT d.id AS document_id, d.title AS document_title, s.local_path, d.text_path,
                   d.ocr_status, d.created_at, d.updated_at,
                   s.source_uid, s.title AS source_title, s.source_class, s.source_type,
                   s.status AS source_status, s.citation_allowed,
                   count(c.id) AS chunk_count
            FROM documents d
            JOIN sources s ON s.id=d.source_id
            LEFT JOIN chunks c ON c.document_id=d.id
            WHERE d.sha256=%s
            GROUP BY d.id, s.id
            ORDER BY s.source_type, s.source_uid, d.id
            """,
            (group["sha256"],),
        )
        chunkless = [doc for doc in group["documents"] if int(doc.get("chunk_count") or 0) == 0]
        source_classes = sorted({doc["source_class"] for doc in group["documents"] if doc.get("source_class")})
        source_types = sorted({doc["source_type"] for doc in group["documents"] if doc.get("source_type")})
        group["chunkless_documents"] = len(chunkless)
        group["source_classes"] = source_classes
        group["source_types"] = source_types
        group["answer_dedupe_status"] = "ok_sha_based" if not chunkless else "check_chunkless_duplicate"
    return groups


def main() -> int:
    groups = duplicate_groups()
    summary = {
        "duplicate_sha_groups": len(groups),
        "duplicate_documents": sum(int(group["document_count"] or 0) for group in groups),
        "groups_with_chunkless_documents": sum(1 for group in groups if int(group["chunkless_documents"] or 0) > 0),
        "groups": groups,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    return 0 if summary["groups_with_chunkless_documents"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
