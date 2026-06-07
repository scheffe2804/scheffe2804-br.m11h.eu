#!/usr/bin/env python3
"""Import public EVG pages and PDFs without crawling protected /meine-evg/.

This script intentionally avoids URLs below /meine-evg/ because EVG's robots.txt
disallows that area and the site also blocks automated requests there. Imported
sources are NOT citation-approved automatically.
"""

from __future__ import annotations

import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
BASE_DIR = ROOT / "sources" / "evg" / "public"
TEXT_DIR = ROOT / "text" / "evg-public"
LOG_DIR = ROOT / "logs"
BASE_URL = "https://www.evg-online.org"


PUBLIC_PAGES = [
    {
        "uid": "evg-public-tarifvertraege",
        "title": "EVG: Tarifverträge",
        "url": "https://www.evg-online.org/unsere-themen/tarifvertraege/",
        "class": "BLAU",
        "type": "evg_public_page",
        "hint_only": False,
    },
    {
        "uid": "evg-public-db-tarifrunde-2025",
        "title": "EVG: DB-Tarifrunde 2025",
        "url": "https://www.evg-online.org/unsere-themen/dein-geld/db-tarifrunde-2025/",
        "class": "BLAU",
        "type": "evg_public_page",
        "hint_only": False,
    },
    {
        "uid": "evg-public-ne-tarifrunde-2025",
        "title": "EVG: NE-Tarifrunde 2024/2025",
        "url": "https://www.evg-online.org/unsere-themen/tarifmeldungen/ne-tarifrunde-2025/",
        "class": "BLAU",
        "type": "evg_public_page",
        "hint_only": False,
    },
    {
        "uid": "evg-public-dein-geld",
        "title": "EVG: Dein Geld / Deine Zeit",
        "url": "https://www.evg-online.org/unsere-themen/dein-geld/",
        "class": "BLAU",
        "type": "evg_public_page",
        "hint_only": False,
    },
    {
        "uid": "evg-public-wie-entstehen-tarifvertraege",
        "title": "EVG: Wie entstehen Tarifverträge?",
        "url": "https://www.evg-online.org/unsere-themen/was-tarifvertraege-dir-bringen-und-wie-sie-entstehen/",
        "class": "GELB",
        "type": "evg_public_page",
        "hint_only": True,
    },
    {
        "uid": "evg-public-br-wahlen-2026",
        "title": "EVG: BR-Wahlen 2026",
        "url": "https://www.evg-online.org/unsere-themen/weitere-themenseiten/br-wahlen-2026/",
        "class": "GELB",
        "type": "evg_public_page",
        "hint_only": True,
    },
    {
        "uid": "evg-public-db-cargo",
        "title": "EVG: DB Cargo",
        "url": "https://www.evg-online.org/unsere-themen/weitere-themenseiten/db-cargo/",
        "class": "GELB",
        "type": "evg_public_page",
        "hint_only": True,
    },
]


PUBLIC_PDFS = [
    # DB-Tarifrunde 2025 public downloads
    ("evg-pdf-db-tr2025-faq", "EVG DB-Tarifrunde 2025: FAQ zum Tarifabschluss", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-03-07-evg_TR2025_FAQ_Tarifabschluss_250307.pdf"),
    ("evg-pdf-db-tr2025-mehr-respekt", "EVG DB-Tarifrunde 2025: Mehr Respekt für Kolleginnen", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-03-07_Tarifabschluss_-_Mehr_Respekt_fuer_Kolleginnen.pdf"),
    ("evg-pdf-db-tr2025-zug", "EVG DB-Tarifrunde 2025: Im Fokus EVG-ZUG", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-19-evg_TR2025_Aushang_ZUG_250218.pdf"),
    ("evg-pdf-db-tr2025-arbeitszeit", "EVG DB-Tarifrunde 2025: Neue Regelungen zur Arbeitszeit", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-21-evg_TR2025_Aushang_regelungen_AZ_250221.pdf"),
    ("evg-pdf-db-tr2025-zeitstrahl", "EVG DB-Tarifrunde 2025: Zeitstrahl", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-19-EVG_DB_Tarifrunde_Zeitstrahl.pdf"),
    ("evg-pdf-db-tr2025-erfolge", "EVG DB-Tarifrunde 2025: Erfolge der Tarifrunde", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-19-EVG_Tarifabschluss_Aushang_A4_v2.pdf"),
    ("evg-pdf-db-tr2025-bahnbau", "EVG DB-Tarifrunde 2025: DB Bahnbau", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-24-evg_TR2025_Aushang_Bahnbau_250224.pdf"),
    ("evg-pdf-db-tr2025-cargo", "EVG DB-Tarifrunde 2025: DB Cargo", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-19-EVG_DB-Cargo_Aushang_A4.pdf"),
    ("evg-pdf-db-tr2025-lokfuehrer", "EVG DB-Tarifrunde 2025: Lokführer:innen FGr4", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-21-evg_TR2025_Aushang_Lokfuehrer_innen_250221_FINAL.pdf"),
    ("evg-pdf-db-tr2025-services", "EVG DB-Tarifrunde 2025: DB Services", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-26-evg_TR2025_Aushang_Services_250226.pdf"),
    ("evg-pdf-db-tr2025-zeitarbeit", "EVG DB-Tarifrunde 2025: DB Zeitarbeit", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-21-evg_TR2025_Aushang_DB_Zeitarbeit_250221.pdf"),
    ("evg-pdf-db-tr2025-dialog", "EVG DB-Tarifrunde 2025: DB Dialog", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-24-evg_TR2025_Aushang_DB_Dialog_250224.pdf"),
    ("evg-pdf-db-tr2025-fahrwegdienste", "EVG DB-Tarifrunde 2025: DB Fahrwegdienste", "BLAU", False, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/Tarif_und_Wahlmodell/DB-Tarifrunde_2025/Downloads/25-02-24-evg_TR2025_Aushang_DB_Fahrwege_250224.pdf"),
    # BR election public downloads: useful as EVG campaign/context, not legal source.
    ("evg-pdf-brw2026-briefwahl", "EVG BR-Wahlen 2026: Briefwahlunterlagen", "GELB", True, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/BR-Wahlen-2026/26-04-27-evg_BRW2026_Aushang_Briefwahl_260478.pdf"),
    ("evg-pdf-brw2026-flyer", "EVG BR-Wahlen 2026: Flyer", "GELB", True, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/BR-Wahlen-2026/26-04-18-Flyer-BR-Wahl-WEB_260415.pdf"),
    ("evg-pdf-brw2026-aushang", "EVG BR-Wahlen 2026: Aushang", "GELB", True, "https://www.evg-online.org/fileadmin/dateien/dokumente/nachgebaute-seiten/BR-Wahlen-2026/26-04-18-Aushang-BR-Wahl-WEB_260415.pdf"),
]


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.skip = 0
        self.parts: list[str] = []
        self.link_stack: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "svg", "noscript"}:
            self.skip += 1
        if tag in {"p", "div", "section", "article", "h1", "h2", "h3", "h4", "li", "br", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg", "noscript"} and self.skip:
            self.skip -= 1
        if tag in {"p", "div", "section", "article", "h1", "h2", "h3", "h4", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.parts.append(data)

    def text(self) -> str:
        raw = html.unescape("".join(self.parts))
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        raw = re.sub(r"\n\s*\n\s*\n+", "\n\n", raw)
        return raw.strip()


def safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")[:140]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fetch(url: str, dest: Path) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.path.startswith("/meine-evg/"):
        raise RuntimeError("Refusing protected/disallowed EVG path: %s" % url)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "br-wissensdatenbank-m11h/1.0 (+internal source archiving; no protected area crawl)",
            "Accept": "text/html,application/pdf,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        dest.write_bytes(response.read())


def page_text(path: Path) -> str:
    parser = TextExtractor()
    parser.feed(path.read_text(encoding="utf-8", errors="replace"))
    return parser.text()


def pdf_to_text(pdf_path: Path, text_path: Path) -> bool:
    if not shutil.which("pdftotext"):
        return False
    subprocess.run(["pdftotext", "-layout", str(pdf_path), str(text_path)], check=True)
    return text_path.exists() and text_path.stat().st_size > 0


def chunk_text(text: str, max_chars: int = 3200) -> list[str]:
    lines = [line.strip() for line in text.splitlines()]
    blocks: list[str] = []
    cur: list[str] = []
    heading_re = re.compile(r"^(#{1,4}\s+|[0-9]+\.\s+|[A-ZÄÖÜ][^.!?]{3,90}$|FAQ|Downloads)$")
    for line in lines:
        if not line:
            if cur:
                cur.append("")
            continue
        if heading_re.match(line) and cur:
            blocks.append("\n".join(cur).strip())
            cur = [line]
        else:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur).strip())
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


def upsert_source(cur, source_uid: str, title: str, source_type: str, source_class: str, public_url: str, local_path: Path, hint_only: bool, digest: str) -> int:
    cur.execute(
        """
        INSERT INTO sources (source_uid,title,source_type,source_class,public_url,local_path,status,confidentiality,citation_allowed,hint_only,sha256,metadata,last_checked_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,now())
        ON CONFLICT (source_uid) DO UPDATE SET
            title=EXCLUDED.title,
            source_type=EXCLUDED.source_type,
            source_class=EXCLUDED.source_class,
            public_url=EXCLUDED.public_url,
            local_path=EXCLUDED.local_path,
            status=EXCLUDED.status,
            confidentiality=EXCLUDED.confidentiality,
            citation_allowed=false,
            hint_only=EXCLUDED.hint_only,
            sha256=EXCLUDED.sha256,
            metadata=EXCLUDED.metadata,
            last_checked_at=now(),
            updated_at=now()
        RETURNING id
        """,
        (source_uid, title, source_type, source_class, public_url, str(local_path), "technisch_geprueft", "intern", False, hint_only, digest, '{"origin":"evg-public-import","auto_citation_allowed":false}'),
    )
    return int(cur.fetchone()[0])


def upsert_document(cur, source_id: int, doc_uid: str, title: str, original_path: Path, text_path: Path | None, digest: str, status: str) -> int:
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
        (source_id, doc_uid, title, str(original_path), str(text_path) if text_path else None, digest, status),
    )
    return int(cur.fetchone()[0])


def replace_chunks(cur, doc_id: int, doc_uid: str, title: str, text_path: Path, source_class: str, public_url: str) -> int:
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
        locator = "Abschnitt %04d" % idx
        citation_label = "%s, %s" % (title, locator)
        cur.execute(
            """
            INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,citation_url,internal_ref)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (doc_id, chunk_uid, first_line, locator, content, source_class, citation_label, public_url, "evg-public:%s:%s" % (doc_uid, locator)),
        )
        inserted += 1
    return inserted


def main() -> None:
    db_url = os.environ.get("BR_DATABASE_URL")
    if not db_url:
        raise SystemExit("BR_DATABASE_URL missing")
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    TEXT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = LOG_DIR / ("import-evg-public-%s.log" % stamp)
    imported = []
    errors = []
    chunks_total = 0

    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            for item in PUBLIC_PAGES:
                try:
                    uid = item["uid"]
                    html_path = BASE_DIR / (uid + ".html")
                    text_path = TEXT_DIR / (uid + ".txt")
                    fetch(item["url"], html_path)
                    text_path.write_text(page_text(html_path), encoding="utf-8")
                    digest = sha256_file(html_path)
                    source_id = upsert_source(cur, uid, item["title"], item["type"], item["class"], item["url"], html_path, bool(item["hint_only"]), digest)
                    doc_id = upsert_document(cur, source_id, uid + "-doc", item["title"], html_path, text_path, digest, "html_text")
                    inserted = replace_chunks(cur, doc_id, uid + "-doc", item["title"], text_path, item["class"], item["url"])
                    chunks_total += inserted
                    imported.append((uid, inserted))
                except Exception as exc:  # noqa: BLE001 - log and continue source inventory
                    errors.append((item["uid"], str(exc)))

            for uid, title, source_class, hint_only, url in PUBLIC_PDFS:
                try:
                    pdf_name = safe_name(Path(urllib.parse.urlparse(url).path).name or (uid + ".pdf"))
                    pdf_path = BASE_DIR / pdf_name
                    text_path = TEXT_DIR / (uid + ".txt")
                    fetch(url, pdf_path)
                    text_ok = pdf_to_text(pdf_path, text_path)
                    digest = sha256_file(pdf_path)
                    source_id = upsert_source(cur, uid, title, "evg_public_pdf", source_class, url, pdf_path, hint_only, digest)
                    doc_id = upsert_document(cur, source_id, uid + "-doc", title, pdf_path, text_path if text_ok else None, digest, "pdf_text" if text_ok else "pdf_imported_no_text")
                    inserted = replace_chunks(cur, doc_id, uid + "-doc", title, text_path, source_class, url) if text_ok else 0
                    chunks_total += inserted
                    imported.append((uid, inserted))
                except Exception as exc:  # noqa: BLE001
                    errors.append((uid, str(exc)))
            conn.commit()

    with log_path.open("w", encoding="utf-8") as log:
        log.write("# EVG public import\n")
        log.write("timestamp=%s\n" % stamp)
        log.write("protected_area_skipped=/meine-evg/\n")
        log.write("imported_count=%d\n" % len(imported))
        log.write("chunks_total=%d\n" % chunks_total)
        for uid, count in imported:
            log.write("imported %s chunks=%d\n" % (uid, count))
        for uid, err in errors:
            log.write("ERROR %s %s\n" % (uid, err))
    print("imported_sources=%d chunks=%d errors=%d log=%s" % (len(imported), chunks_total, len(errors), log_path))
    if errors:
        for uid, err in errors:
            print("ERROR %s %s" % (uid, err), file=sys.stderr)


if __name__ == "__main__":
    main()
