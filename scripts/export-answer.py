#!/usr/bin/env python3
"""Export a validated answer to protected HTML/PDF files.

This helper mirrors the web export guard: every statement must have a citation.
"""

import os
import sys
import shutil
import json
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from export_manifest import write_export_manifest


STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
TEMPLATE_DIR = Path("/app/templates")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: export-answer.py <answer_uid>", file=sys.stderr)
        return 2
    answer_uid = sys.argv[1]
    db_url = os.environ["BR_DATABASE_URL"]
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT a.*, q.query_uid, q.title, q.question FROM answers a JOIN queries q ON q.id=a.query_id WHERE a.answer_uid=%s", (answer_uid,))
            row = cur.fetchone()
            if not row:
                print("answer_not_found", file=sys.stderr)
                return 1
            cols = [d.name for d in cur.description]
            answer = dict(zip(cols, row))
            cur.execute(
                """
                SELECT count(st.id) AS statement_count, count(cit.id) AS citation_count,
                       sum(CASE WHEN cit.id IS NULL THEN 1 ELSE 0 END) AS statements_without_citation
                FROM answer_statements st LEFT JOIN answer_citations cit ON cit.statement_id=st.id
                WHERE st.answer_id=%s
                """,
                (answer["id"],),
            )
            validation_cols = [d.name for d in cur.description]
            validation = dict(zip(validation_cols, cur.fetchone()))
            validation = {k: int(validation[k] or 0) for k in validation}
            if validation["statement_count"] <= 0 or validation["statements_without_citation"] > 0:
                print("export_blocked_missing_citation", validation, file=sys.stderr)
                return 1
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
                (answer["id"],),
            )
            st_cols = [d.name for d in cur.description]
            statements = [dict(zip(st_cols, r)) for r in cur.fetchall()]

            export_dir = STORAGE_ROOT / "exports" / answer_uid
            export_dir.mkdir(parents=True, exist_ok=True)
            html_path = export_dir / "index.html"
            pdf_path = export_dir / "export.pdf"
            env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html"]))
            rendered = env.get_template("export_validated_answer.html").render(
                title="Betriebsrats-Wissensdatenbank",
                answer=answer,
                statements=statements,
                validation=validation,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            html_path.write_text(rendered, encoding="utf-8")
            HTML(string=rendered, base_url=str(export_dir)).write_pdf(str(pdf_path))
            os.chmod(html_path, 0o640)
            os.chmod(pdf_path, 0o640)
            manifest_path = write_export_manifest(
                export_dir=export_dir,
                answer=answer,
                statements=statements,
                validation=validation,
                html_path=html_path,
                pdf_path=pdf_path,
                generated_by="cli-export",
            )
            # In Docker this may run as root. If host user chris exists in the
            # mounted filesystem ownership context, prefer chris-readable files.
            try:
                shutil.chown(html_path, user="chris", group="chris")
                shutil.chown(pdf_path, user="chris", group="chris")
                shutil.chown(manifest_path, user="chris", group="chris")
                shutil.chown(export_dir, user="chris", group="chris")
            except Exception:
                pass
            cur.execute("UPDATE answers SET html_path=%s, pdf_path=%s, updated_at=now() WHERE id=%s", (str(html_path), str(pdf_path), answer["id"]))
            cur.execute(
                """
                INSERT INTO audit_log (actor, action, object_type, object_uid, details)
                VALUES (%s,%s,%s,%s,%s::jsonb)
                """,
                (
                    "cli",
                    "validated_answer_export_cli",
                    "answer",
                    answer_uid,
                    json.dumps(
                        {
                            "html_file": "index.html",
                            "pdf_file": "export.pdf",
                            "manifest_file": "manifest.json",
                            "statement_count": validation["statement_count"],
                            "citation_count": validation["citation_count"],
                            "statements_without_citation": validation["statements_without_citation"],
                            "source_classes": sorted({str(item.get("source_class")) for item in statements if item.get("source_class")}),
                            "manifest_version": 1,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
            conn.commit()
    print("exported", answer_uid, html_path, pdf_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
