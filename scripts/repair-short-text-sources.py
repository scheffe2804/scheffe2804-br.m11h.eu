#!/usr/bin/env python3
"""Repair approved sources that have documents with too-short text and no chunks.

The script is intentionally conservative:
- defaults to dry-run
- never changes original PDFs
- writes only text/OCR working files and chunk rows
- processes only sources that are already citation_allowed and have no chunks
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
LOG_DIR = ROOT / "logs"
OCR_TEXT_DIR = ROOT / "ocr" / "text-repair"


def text_size(path_value: str | None) -> int | None:
    if not path_value:
        return None
    path = Path(path_value)
    if not path.exists():
        return None
    return path.stat().st_size


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def pdf_page_count(pdf_path: Path) -> int | None:
    try:
        proc = subprocess.run(["pdfinfo", str(pdf_path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        return None
    match = re.search(r"^Pages:\s+(\d+)\s*$", proc.stdout, re.MULTILINE)
    return int(match.group(1)) if match else None


def ocr_pdf_to_text(pdf_path: Path, language: str, max_pages: int | None) -> str:
    if not shutil.which("pdftoppm"):
        raise RuntimeError("pdftoppm not available")
    if not shutil.which("tesseract"):
        raise RuntimeError("tesseract not available")
    page_count = pdf_page_count(pdf_path)
    last_page = page_count
    if max_pages and page_count:
        last_page = min(page_count, max_pages)
    with tempfile.TemporaryDirectory(prefix="br-ocr-repair-") as tmp_name:
        tmp = Path(tmp_name)
        prefix = tmp / "page"
        cmd = ["pdftoppm", "-r", "220", "-png"]
        if last_page:
            cmd.extend(["-f", "1", "-l", str(last_page)])
        cmd.extend([str(pdf_path), str(prefix)])
        run(cmd)
        images = sorted(tmp.glob("page-*.png"))
        if not images:
            raise RuntimeError("pdftoppm produced no page images")
        parts: list[str] = []
        for idx, image in enumerate(images, start=1):
            out_base = tmp / ("ocr-%04d" % idx)
            run(["tesseract", str(image), str(out_base), "-l", language, "--psm", "6"])
            text_path = out_base.with_suffix(".txt")
            parts.append(text_path.read_text(encoding="utf-8", errors="replace"))
        return "\n\n".join(parts).strip()


def chunk_text(text: str, max_chars: int = 3500) -> list[str]:
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
        if len(block) < 80:
            continue
        if len(block) <= max_chars:
            result.append(block)
            continue
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", block) if p.strip()]
        buf = ""
        for para in paragraphs:
            if len(buf) + len(para) + 2 > max_chars and buf:
                if len(buf.strip()) >= 80:
                    result.append(buf.strip())
                buf = para
            else:
                buf = (buf + "\n\n" + para).strip()
        if len(buf.strip()) >= 80:
            result.append(buf.strip())
    return result


def replace_chunks(cur: Any, doc: dict[str, Any], text: str) -> int:
    chunks = chunk_text(text)
    cur.execute("DELETE FROM chunks WHERE document_id=%s", (doc["document_id"],))
    inserted = 0
    for idx, content in enumerate(chunks, start=1):
        digest = hashlib.sha256((doc["document_uid"] + str(idx) + content[:200]).encode("utf-8", errors="ignore")).hexdigest()[:16]
        chunk_uid = "%s-repair-%04d-%s" % (doc["document_uid"], idx, digest)
        first_line = next((line.strip() for line in content.splitlines() if line.strip()), "")[:200]
        locator = "OCR-Chunk %04d" % idx
        citation_label = "%s, %s" % (doc["document_title"], locator)
        cur.execute(
            """
            INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,internal_ref)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (doc["document_id"], chunk_uid, first_line, locator, content, doc["source_class"], citation_label, "%s:%s" % (doc["source_uid"], locator)),
        )
        inserted += 1
    return inserted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write repaired text and chunks")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--min-text-bytes", type=int, default=80)
    parser.add_argument("--min-repaired-bytes", type=int, default=200)
    parser.add_argument("--max-pages", type=int, default=0, help="0 means all pages")
    parser.add_argument("--language", default="deu+eng")
    parser.add_argument("--include-repaired", action="store_true", help="include ocr_repaired_tesseract documents for a full rerun")
    args = parser.parse_args()

    db_url = os.environ.get("BR_DATABASE_URL")
    if not db_url:
        raise SystemExit("BR_DATABASE_URL missing")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    OCR_TEXT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = LOG_DIR / ("repair-short-text-sources-%s.log" % stamp)

    processed = []
    skipped = []
    errors = []
    repaired = 0
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id AS source_id, s.source_uid, s.title AS source_title, s.source_class,
                       d.id AS document_id, d.document_uid, d.title AS document_title,
                       d.original_path, d.text_path, d.ocr_status,
                       count(c.id) AS chunk_count
                FROM sources s
                JOIN documents d ON d.source_id=s.id
                LEFT JOIN chunks c ON c.document_id=d.id
                WHERE s.citation_allowed=true
                GROUP BY s.id, d.id
                HAVING count(c.id)=0 OR (%s AND d.ocr_status='ocr_repaired_tesseract')
                ORDER BY s.title
                LIMIT %s
                """,
                (args.include_repaired, args.limit),
            )
            columns = [desc.name for desc in cur.description]
            docs = [dict(zip(columns, row)) for row in cur.fetchall()]
            for doc in docs:
                current_size = text_size(doc.get("text_path"))
                original = Path(doc["original_path"])
                if current_size is not None and current_size >= args.min_text_bytes and not args.include_repaired:
                    skipped.append((doc["source_uid"], "text_not_short", current_size))
                    continue
                if not original.exists():
                    errors.append((doc["source_uid"], "original_missing", str(original)))
                    continue
                try:
                    text = ocr_pdf_to_text(original, args.language, args.max_pages or None)
                    repaired_size = len(text.encode("utf-8", errors="replace"))
                    chunks = chunk_text(text)
                    processed.append((doc["source_uid"], current_size, repaired_size, len(chunks)))
                    if repaired_size < args.min_repaired_bytes or not chunks:
                        skipped.append((doc["source_uid"], "repaired_text_too_short", repaired_size))
                        continue
                    if args.apply:
                        target = Path(doc["text_path"]) if doc.get("text_path") else OCR_TEXT_DIR / (doc["document_uid"] + ".txt")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(text + "\n", encoding="utf-8")
                        inserted = replace_chunks(cur, doc, text)
                        cur.execute("UPDATE documents SET text_path=%s, ocr_status=%s, updated_at=now() WHERE id=%s", (str(target), "ocr_repaired_tesseract", doc["document_id"]))
                        repaired += inserted
                except Exception as exc:  # noqa: BLE001
                    errors.append((doc["source_uid"], "exception", str(exc)))
            if args.apply:
                conn.commit()
            else:
                conn.rollback()

    with log_path.open("w", encoding="utf-8") as log:
        log.write("# Repair short text sources\n")
        log.write("timestamp=%s\n" % stamp)
        log.write("mode=%s\n" % ("apply" if args.apply else "dry-run"))
        log.write("limit=%d\n" % args.limit)
        log.write("min_text_bytes=%d\n" % args.min_text_bytes)
        log.write("min_repaired_bytes=%d\n" % args.min_repaired_bytes)
        log.write("processed_count=%d\n" % len(processed))
        log.write("skipped_count=%d\n" % len(skipped))
        log.write("error_count=%d\n" % len(errors))
        log.write("inserted_chunks=%d\n" % repaired)
        for row in processed:
            log.write("processed source=%s old_bytes=%s repaired_bytes=%s chunks=%s\n" % row)
        for row in skipped:
            log.write("skipped source=%s reason=%s value=%s\n" % row)
        for row in errors:
            log.write("error source=%s reason=%s detail=%s\n" % row)
    print("mode=%s" % ("apply" if args.apply else "dry-run"))
    print("processed=%d skipped=%d errors=%d inserted_chunks=%d log=%s" % (len(processed), len(skipped), len(errors), repaired, log_path))
    for row in processed[:10]:
        print("processed source=%s old_bytes=%s repaired_bytes=%s chunks=%s" % row)
    for row in skipped[:10]:
        print("skipped source=%s reason=%s value=%s" % row)
    for row in errors[:10]:
        print("error source=%s reason=%s detail=%s" % row)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
