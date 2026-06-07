#!/usr/bin/env python3
"""Backfill technical manifests for existing BR-Wissen exports.

This script writes manifest.json files only for already exported answers. It does
not alter answer text, source text, citations, HTML or PDF content.
"""

from __future__ import annotations

import os
import shutil
import json
from pathlib import Path

import psycopg

from export_manifest import write_export_manifest


STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))


def validation_for(cur, answer_id: int) -> dict[str, int]:
    cur.execute(
        """
        SELECT count(st.id) AS statement_count, count(cit.id) AS citation_count,
               sum(CASE WHEN cit.id IS NULL THEN 1 ELSE 0 END) AS statements_without_citation
        FROM answer_statements st LEFT JOIN answer_citations cit ON cit.statement_id=st.id
        WHERE st.answer_id=%s
        """,
        (answer_id,),
    )
    cols = [d.name for d in cur.description]
    row = dict(zip(cols, cur.fetchone()))
    return {key: int(row.get(key) or 0) for key in ["statement_count", "citation_count", "statements_without_citation"]}


def statements_for(cur, answer_id: int) -> list[dict[str, object]]:
    cur.execute(
        """
        SELECT st.id, st.section, st.statement_text,
               cit.citation_label, cit.citation_url, cit.internal_ref, cit.source_class,
               COALESCE(c.chunk_uid, c_ref.chunk_uid) AS chunk_uid,
               COALESCE(c.locator, c_ref.locator) AS locator,
               COALESCE(d.title, d_ref.title) AS document_title,
               COALESCE(s.source_uid, s_ref.source_uid) AS source_uid,
               COALESCE(s.title, s_ref.title) AS source_title,
               COALESCE(s.source_type, s_ref.source_type) AS source_type
        FROM answer_statements st
        JOIN answer_citations cit ON cit.statement_id=st.id
        LEFT JOIN chunks c ON c.id=cit.chunk_id
        LEFT JOIN documents d ON d.id=c.document_id
        LEFT JOIN sources s ON s.id=d.source_id
        LEFT JOIN sources s_ref ON c.id IS NULL AND s_ref.source_uid=split_part(cit.internal_ref, ':', 1)
        LEFT JOIN documents d_ref ON c.id IS NULL AND d_ref.source_id=s_ref.id
        LEFT JOIN chunks c_ref ON c.id IS NULL AND c_ref.document_id=d_ref.id AND replace(c_ref.locator, ' ', '')=replace(split_part(cit.internal_ref, ':', 2), ' ', '')
        WHERE st.answer_id=%s ORDER BY st.id
        """,
        (answer_id,),
    )
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def main() -> int:
    db_url = os.environ["BR_DATABASE_URL"]
    written = 0
    skipped = 0
    failed = 0
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.*, q.query_uid, q.title, q.question
                FROM answers a JOIN queries q ON q.id=a.query_id
                WHERE coalesce(a.html_path,'')<>'' AND coalesce(a.pdf_path,'')<>''
                ORDER BY a.created_at
                """
            )
            cols = [d.name for d in cur.description]
            answers = [dict(zip(cols, row)) for row in cur.fetchall()]
            for answer in answers:
                answer_uid = str(answer.get("answer_uid"))
                html_path = Path(str(answer.get("html_path") or ""))
                pdf_path = Path(str(answer.get("pdf_path") or ""))
                export_dir = html_path.parent if html_path.name else STORAGE_ROOT / "exports" / answer_uid
                if not html_path.exists() or not pdf_path.exists():
                    skipped += 1
                    continue
                try:
                    validation = validation_for(cur, int(answer["id"]))
                    if validation["statement_count"] <= 0 or validation["statements_without_citation"] != 0:
                        skipped += 1
                        continue
                    statements = statements_for(cur, int(answer["id"]))
                    manifest_path = write_export_manifest(
                        export_dir=export_dir,
                        answer=answer,
                        statements=statements,
                        validation=validation,
                        html_path=html_path,
                        pdf_path=pdf_path,
                        generated_by="manifest-backfill",
                    )
                    try:
                        shutil.chown(manifest_path, user="chris", group="chris")
                    except Exception:
                        pass
                    cur.execute(
                        """
                        INSERT INTO audit_log (actor, action, object_type, object_uid, details)
                        VALUES (%s,%s,%s,%s,%s::jsonb)
                        """,
                        (
                            "cli",
                            "export_manifest_backfill",
                            "answer",
                            answer_uid,
                            json.dumps({"manifest_file": "manifest.json", "manifest_version": 1}, ensure_ascii=False),
                        ),
                    )
                    written += 1
                except Exception:
                    failed += 1
    print("manifest_backfill_status=%s written=%d skipped=%d failed=%d" % ("ok" if failed == 0 else "failed", written, skipped, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
