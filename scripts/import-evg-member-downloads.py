#!/usr/bin/env python3
"""Import EVG member-area documents that the authorized user downloaded manually.

No login, scraping, cookie reuse or anti-bot bypass is performed here. Put files
into /srv/br-wissensdatenbank/imports/evg-member/ and run this importer.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
IMPORT_DIR = ROOT / "imports" / "evg-member"
ARCHIVE_DIR = ROOT / "sources" / "evg" / "member-downloads"
TEXT_DIR = ROOT / "text" / "evg-member"
LOG_DIR = ROOT / "logs"
EXTRACT_DIR = IMPORT_DIR / "_extracted"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_stem(path: Path) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", path.stem).strip("-")[:140] or "evg-document"


def safe_zip_component(value: str, max_len: int = 120) -> str:
    """Return a filesystem-safe, bounded path component."""
    cleaned = re.sub(r"[^a-zA-Z0-9._() äöüÄÖÜß+-]+", "-", value).strip(" .-")
    if not cleaned:
        cleaned = "datei"
    if len(cleaned.encode("utf-8")) <= max_len:
        return cleaned
    suffix = ""
    if "." in cleaned:
        stem, ext = cleaned.rsplit(".", 1)
        suffix = "." + ext[:20]
    else:
        stem = cleaned
    digest = hashlib.sha256(cleaned.encode("utf-8", errors="ignore")).hexdigest()[:10]
    budget = max_len - len(suffix.encode("utf-8")) - len(digest) - 1
    out = ""
    for ch in stem:
        if len((out + ch).encode("utf-8")) > budget:
            break
        out += ch
    return (out.rstrip(" .-") + "-" + digest + suffix) or ("datei-" + digest + suffix)


def source_uid_for(path: Path, digest: str) -> str:
    return "evg-member-%s-%s" % (safe_stem(path).lower(), digest[:12])


def safe_extract_zip(zip_path: Path, target_root: Path) -> list[Path]:
    """Extract a zip below target_root without allowing path traversal."""
    extracted: list[Path] = []
    target_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts:
                raise RuntimeError("Unsicherer ZIP-Pfad in %s: %s" % (zip_path, info.filename))
            safe_parts = [safe_zip_component(part) for part in Path(name).parts]
            dest = target_root.joinpath(*safe_parts)
            resolved = dest.resolve()
            if not str(resolved).startswith(str(target_root.resolve()) + os.sep):
                raise RuntimeError("ZIP-Pfad verlaesst Zielordner: %s" % info.filename)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as out:
                shutil.copyfileobj(src, out)
            extracted.append(dest)
    return extracted


def pdf_to_text(pdf_path: Path, text_path: Path) -> bool:
    if not shutil.which("pdftotext"):
        return False
    subprocess.run(["pdftotext", "-layout", str(pdf_path), str(text_path)], check=True)
    return text_path.exists() and text_path.stat().st_size > 0


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
        if not block:
            continue
        if len(block) <= max_chars:
            result.append(block)
            continue
        paras = [p.strip() for p in re.split(r"\n\s*\n", block) if p.strip()]
        buf = ""
        for para in paras:
            if len(buf) + len(para) + 2 > max_chars and buf:
                result.append(buf.strip())
                buf = para
            else:
                buf = (buf + "\n\n" + para).strip()
        if buf:
            result.append(buf.strip())
    return result


def upsert_source(cur, source_uid: str, title: str, local_path: Path, digest: str) -> int:
    cur.execute(
        """
        INSERT INTO sources (source_uid,title,source_type,source_class,internal_ref,local_path,status,confidentiality,citation_allowed,hint_only,sha256,metadata,last_checked_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,now())
        ON CONFLICT (source_uid) DO UPDATE SET
            title=EXCLUDED.title,
            local_path=EXCLUDED.local_path,
            status=EXCLUDED.status,
            citation_allowed=false,
            sha256=EXCLUDED.sha256,
            metadata=EXCLUDED.metadata,
            last_checked_at=now(),
            updated_at=now()
        RETURNING id
        """,
        (source_uid, title, "evg_member_download", "BLAU", "evg-mitgliederbereich:%s" % local_path.name, str(local_path), "technisch_geprueft", "intern", False, False, digest, '{"origin":"manual-evg-member-download","auto_citation_allowed":false}'),
    )
    return int(cur.fetchone()[0])


def upsert_document(cur, source_id: int, doc_uid: str, title: str, original_path: Path, text_path: Path, digest: str) -> int:
    cur.execute(
        """
        INSERT INTO documents (source_id,document_uid,title,original_path,text_path,sha256,ocr_status)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (document_uid) DO UPDATE SET
            title=EXCLUDED.title,
            original_path=EXCLUDED.original_path,
            text_path=EXCLUDED.text_path,
            sha256=EXCLUDED.sha256,
            ocr_status=EXCLUDED.ocr_status,
            updated_at=now()
        RETURNING id
        """,
        (source_id, doc_uid, title, str(original_path), str(text_path), digest, "pdf_text"),
    )
    return int(cur.fetchone()[0])


def replace_chunks(cur, doc_id: int, doc_uid: str, title: str, text_path: Path) -> int:
    text = text_path.read_text(encoding="utf-8", errors="replace")
    chunks = chunk_text(text)
    cur.execute("DELETE FROM chunks WHERE document_id=%s", (doc_id,))
    inserted = 0
    for idx, content in enumerate(chunks, start=1):
        if len(content.strip()) < 80:
            continue
        digest = hashlib.sha256((doc_uid + str(idx) + content[:200]).encode("utf-8", errors="ignore")).hexdigest()[:16]
        chunk_uid = "%s-chunk-%04d-%s" % (doc_uid, idx, digest)
        first_line = next((line.strip() for line in content.splitlines() if line.strip()), "")[:200]
        locator = "Chunk %04d" % idx
        citation_label = "%s, %s" % (title, locator)
        cur.execute(
            """
            INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,internal_ref)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (doc_id, chunk_uid, first_line, locator, content, "BLAU", citation_label, "evg-member:%s:%s" % (doc_uid, locator)),
        )
        inserted += 1
    return inserted


def main() -> None:
    db_url = os.environ.get("BR_DATABASE_URL")
    if not db_url:
        raise SystemExit("BR_DATABASE_URL missing")
    IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    TEXT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if EXTRACT_DIR.exists():
        shutil.rmtree(EXTRACT_DIR)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = LOG_DIR / ("import-evg-member-%s.log" % stamp)
    zip_files = sorted([p for p in IMPORT_DIR.rglob("*") if p.is_file() and p.suffix.lower() == ".zip" and EXTRACT_DIR not in p.parents])
    extracted_files = []
    zip_errors = []
    for z in zip_files:
        try:
            digest = sha256_file(z)[:12]
            target = EXTRACT_DIR / (safe_stem(z) + "-" + digest)
            if target.exists():
                shutil.rmtree(target)
            extracted_files.extend(safe_extract_zip(z, target))
        except Exception as exc:  # noqa: BLE001
            zip_errors.append((z.name, str(exc)))
    direct_pdfs = [p for p in IMPORT_DIR.rglob("*") if p.is_file() and p.suffix.lower() == ".pdf" and EXTRACT_DIR not in p.parents]
    extracted_pdfs = [p for p in extracted_files if p.is_file() and p.suffix.lower() == ".pdf"]
    files = sorted(direct_pdfs + extracted_pdfs)
    imported = []
    errors = []
    chunks_total = 0
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            # Re-import idempotently. These are technical imports and must be
            # reviewed/re-approved after a fresh import if citation use is desired.
            cur.execute("DELETE FROM sources WHERE source_uid LIKE 'evg-member-%' OR source_type='evg_member_download'")
            for src in files:
                try:
                    digest = sha256_file(src)
                    uid = source_uid_for(src, digest)
                    archived = ARCHIVE_DIR / (uid + ".pdf")
                    if not archived.exists() or sha256_file(archived) != digest:
                        shutil.copy2(src, archived)
                    text_path = TEXT_DIR / (uid + ".txt")
                    if not pdf_to_text(archived, text_path):
                        raise RuntimeError("pdftotext konnte keinen Text extrahieren")
                    rel = src.relative_to(IMPORT_DIR)
                    title = "EVG Mitgliederbereich/Tailshare: %s" % src.stem
                    source_id = upsert_source(cur, uid, title, archived, digest)
                    doc_id = upsert_document(cur, source_id, uid + "-doc", title, archived, text_path, digest)
                    inserted = replace_chunks(cur, doc_id, uid + "-doc", title, text_path)
                    chunks_total += inserted
                    imported.append((uid, str(rel), inserted))
                except Exception as exc:  # noqa: BLE001
                    errors.append((src.name, str(exc)))
            conn.commit()
    with log_path.open("w", encoding="utf-8") as log:
        log.write("# EVG member manual import\n")
        log.write("timestamp=%s\n" % stamp)
        log.write("input_dir=%s\n" % IMPORT_DIR)
        log.write("zip_count=%d\n" % len(zip_files))
        log.write("zip_extracted_files=%d\n" % len(extracted_files))
        log.write("zip_errors=%d\n" % len(zip_errors))
        log.write("candidate_pdf_count=%d\n" % len(files))
        log.write("imported_count=%d\n" % len(imported))
        log.write("chunks_total=%d\n" % chunks_total)
        for uid, name, chunks in imported:
            log.write("imported %s file=%s chunks=%d\n" % (uid, name, chunks))
        for name, err in zip_errors:
            log.write("ZIP_ERROR file=%s %s\n" % (name, err))
        for name, err in errors:
            log.write("ERROR file=%s %s\n" % (name, err))
    print("input_dir=%s" % IMPORT_DIR)
    print("zip_files=%d zip_errors=%d extracted_files=%d" % (len(zip_files), len(zip_errors), len(extracted_files)))
    print("imported_sources=%d chunks=%d errors=%d log=%s" % (len(imported), chunks_total, len(errors), log_path))


if __name__ == "__main__":
    main()
