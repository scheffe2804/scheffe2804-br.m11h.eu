#!/usr/bin/env python3
"""Create first citation chunks from imported text files.

This is a conservative technical chunker. It does not mark sources as citation
allowed and does not generate legal/tariff statements.
"""

import hashlib
import os
import re
from pathlib import Path

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
TEXT_DIR = ROOT / "text"


def chunk_text(text: str, max_chars: int = 3500) -> list[str]:
    # Split on common tariff/legal headings while preserving content.
    lines = text.splitlines()
    blocks: list[str] = []
    current: list[str] = []
    heading_re = re.compile(r"^\s*(§\s*\d+[a-zA-Z]?|[0-9]+\.\s+|Artikel\s+\d+|Anlage\s+\d+|Abschnitt\s+[A-Z0-9]+)")
    for line in lines:
        if heading_re.match(line) and current:
            blocks.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current).strip())

    result: list[str] = []
    for block in blocks:
        block = re.sub(r"\n{3,}", "\n\n", block).strip()
        if not block:
            continue
        if len(block) <= max_chars:
            result.append(block)
            continue
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", block) if p.strip()]
        buf = ""
        for para in paragraphs:
            if len(buf) + len(para) + 2 > max_chars and buf:
                result.append(buf.strip())
                buf = para
            else:
                buf = (buf + "\n\n" + para).strip()
        if buf:
            result.append(buf.strip())
    return result


def main() -> None:
    db_url = os.environ.get("BR_DATABASE_URL")
    if not db_url:
        raise SystemExit("BR_DATABASE_URL missing")
    inserted = 0
    deleted = 0
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, document_uid, title, text_path FROM documents WHERE text_path IS NOT NULL ORDER BY document_uid")
            docs = cur.fetchall()
            for doc_id, doc_uid, title, text_path in docs:
                path = Path(text_path)
                if not path.exists():
                    continue
                cur.execute("DELETE FROM chunks WHERE document_id=%s", (doc_id,))
                deleted += cur.rowcount or 0
                text = path.read_text(encoding="utf-8", errors="replace")
                chunks = chunk_text(text)
                for idx, content in enumerate(chunks, start=1):
                    digest = hashlib.sha256((doc_uid + str(idx) + content[:200]).encode("utf-8", errors="ignore")).hexdigest()[:16]
                    chunk_uid = "%s-chunk-%04d-%s" % (doc_uid, idx, digest)
                    first_line = next((line.strip() for line in content.splitlines() if line.strip()), "")[:200]
                    locator = "Chunk %04d" % idx
                    citation_label = "%s, %s" % (title, locator)
                    cur.execute(
                        """
                        INSERT INTO chunks (document_id, chunk_uid, heading, locator, content, source_class, citation_label, internal_ref)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (doc_id, chunk_uid, first_line, locator, content, "BLAU", citation_label, "internal:%s:%s" % (doc_uid, locator)),
                    )
                    inserted += 1
            conn.commit()
    print("deleted_chunks=%d inserted_chunks=%d" % (deleted, inserted))


if __name__ == "__main__":
    main()
