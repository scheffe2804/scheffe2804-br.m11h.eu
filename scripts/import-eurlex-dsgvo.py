#!/usr/bin/env python3
"""Import the German GDPR/DSGVO text from EUR-Lex as citable article chunks.

The source is the official EUR-Lex HTML view for CELEX 32016R0679.  The import
is deliberately conservative: it stores one chunk per article and does not
create any interpretation beyond the source text.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
SOURCE_UID = "gesetz-dsgvo"
DOC_UID = SOURCE_UID + "-doc"
TITLE = "Datenschutz-Grundverordnung (DSGVO)"
SOURCE_URL = "https://eur-lex.europa.eu/legal-content/DE/TXT/HTML/?uri=CELEX:32016R0679"
CELEX_URL = "https://eur-lex.europa.eu/legal-content/DE/TXT/?uri=CELEX:32016R0679"


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        if tag.lower() in {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        return re.sub(r"\n\s*\n+", "\n", "\n".join(lines))


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "br.m11h.eu Quellenimport (private Betriebsrats-Wissensdatenbank)"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def extract_articles(text: str) -> list[tuple[str, str, str]]:
    start_marker = "HABEN FOLGENDE VERORDNUNG ERLASSEN:"
    start = text.find(start_marker)
    if start < 0:
        raise SystemExit("Could not find DSGVO regulation body marker")
    body = text[start:]
    matches = list(re.finditer(r"(?m)^Artikel\s*\xa0?\s*([0-9]+[a-z]?)\s*$", body))
    if len(matches) < 90:
        raise SystemExit("Unexpectedly few DSGVO articles found: %d" % len(matches))

    articles: list[tuple[str, str, str]] = []
    for idx, match in enumerate(matches):
        article = match.group(1)
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        block = body[match.start():end].strip()
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        heading = "Artikel " + article
        if len(lines) > 1 and not lines[1].lower().startswith("artikel"):
            heading = lines[1]
        content = "\n".join(lines)
        articles.append(("Art. " + article, heading, content))
    return articles


def main() -> int:
    out_dir = ROOT / "sources" / "eurlex" / "dsgvo"
    log_dir = ROOT / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    html_path = out_dir / "celex-32016r0679-de.html"
    text_path = out_dir / "celex-32016r0679-de.txt"
    html_data = fetch(SOURCE_URL)
    html_sha = hashlib.sha256(html_data).hexdigest()
    parser = TextExtractor()
    parser.feed(html_data.decode("utf-8", "replace"))
    text = parser.text()

    # Validate before touching the existing local archive. EUR-Lex may return a
    # transient consent/error/navigation page; that must not overwrite a known
    # good local source copy.
    articles = extract_articles(text)
    if len(articles) != 99:
        raise SystemExit("Expected 99 DSGVO articles, found %d" % len(articles))

    html_path.write_bytes(html_data)
    html_path.chmod(0o640)
    text_path.write_text(text, encoding="utf-8")
    text_path.chmod(0o640)

    db_url = os.environ["BR_DATABASE_URL"]
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sources (source_uid,title,source_type,source_class,public_url,local_path,status,confidentiality,citation_allowed,hint_only,sha256,metadata,last_checked_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
                ON CONFLICT (source_uid) DO UPDATE SET title=EXCLUDED.title, sha256=EXCLUDED.sha256, local_path=EXCLUDED.local_path, public_url=EXCLUDED.public_url, updated_at=now(), citation_allowed=true, status='freigegeben', last_checked_at=now()
                RETURNING id
                """,
                (SOURCE_UID, TITLE, "eurlex_verordnung", "GRUEN", CELEX_URL, str(text_path), "freigegeben", "oeffentlich", True, False, html_sha, '{"celex":"32016R0679","source":"EUR-Lex"}'),
            )
            source_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO documents (source_id,document_uid,title,original_path,text_path,sha256,ocr_status)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (document_uid) DO UPDATE SET title=EXCLUDED.title, original_path=EXCLUDED.original_path, text_path=EXCLUDED.text_path, sha256=EXCLUDED.sha256, updated_at=now()
                RETURNING id
                """,
                (source_id, DOC_UID, TITLE, str(html_path), str(text_path), html_sha, "html_import"),
            )
            document_id = cur.fetchone()[0]
            cur.execute("DELETE FROM chunks WHERE document_id=%s", (document_id,))
            inserted = 0
            for locator, heading, content in articles:
                article_number = locator.replace("Art. ", "")
                chunk_uid = "%s-art-%s" % (SOURCE_UID, article_number.lower())
                citation_label = "DSGVO %s (%s)" % (locator, heading[:120])
                cur.execute(
                    """
                    INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,citation_url,internal_ref)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (chunk_uid) DO UPDATE SET content=EXCLUDED.content, citation_url=EXCLUDED.citation_url, citation_label=EXCLUDED.citation_label, heading=EXCLUDED.heading
                    """,
                    (document_id, chunk_uid, heading, locator, content, "GRUEN", citation_label, CELEX_URL, "%s:%s" % (SOURCE_UID, locator)),
                )
                inserted += 1
            conn.commit()

    log = log_dir / ("import-eurlex-dsgvo-%s.log" % datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    log.write_text("\n".join([
        "# Import EUR-Lex DSGVO",
        "timestamp=%s" % datetime.now(timezone.utc).isoformat(),
        "source_uid=%s" % SOURCE_UID,
        "title=%s" % TITLE,
        "source_url=%s" % SOURCE_URL,
        "celex_url=%s" % CELEX_URL,
        "html_path=%s" % html_path,
        "text_path=%s" % text_path,
        "html_sha256=%s" % html_sha,
        "chunks=%d" % inserted,
    ]) + "\n", encoding="utf-8")
    log.chmod(0o640)
    print("imported source_uid=%s chunks=%d" % (SOURCE_UID, inserted))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
