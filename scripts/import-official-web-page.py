#!/usr/bin/env python3
"""Archive one allowlisted official web page as a non-legal hint source.

This importer is deliberately unsuitable for laws, court decisions or tariff
texts. It stores official publisher information pages as GELB/hint-only and
never enables citation automatically.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sys
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
ALLOWED_HOSTS = {"express.evg-online.org", "www.evg-online.org", "www.deutschebahn.com", "db.jobs"}
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        if tag.lower() in {"script", "style", "svg", "noscript"}:
            self.skip += 1
        if tag.lower() in {"p", "div", "section", "article", "h1", "h2", "h3", "li", "br", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "svg", "noscript"} and self.skip:
            self.skip -= 1
        if tag.lower() in {"p", "div", "section", "article", "h1", "h2", "h3", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip:
            self.parts.append(data)

    def text(self) -> str:
        value = html.unescape("".join(self.parts))
        value = re.sub(r"[ \t\r\f\v]+", " ", value)
        value = re.sub(r"\n\s*\n\s*\n+", "\n\n", value)
        return value.strip()


def chunks(text: str, max_chars: int = 3000) -> list[str]:
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
    result: list[str] = []
    current = ""
    for paragraph in paragraphs:
        if current and len(current) + len(paragraph) + 2 > max_chars:
            result.append(current)
            current = paragraph
        else:
            current = (current + "\n\n" + paragraph).strip()
    if current:
        result.append(current)
    return [part for part in result if len(part) >= 120]


def atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".%s." % path.name, dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temp_path.chmod(mode)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def main() -> int:
    if len(sys.argv) != 5:
        print("Usage: import-official-web-page.py <source_uid> <title> <publisher> <url>", file=sys.stderr)
        return 2
    source_uid, title, publisher, url = sys.argv[1:5]
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise SystemExit("URL host is not allowlisted")
    req = urllib.request.Request(url, headers={"User-Agent": "br.m11h.eu official source archive (private Betriebsrats-Wissensdatenbank)"})
    with urllib.request.urlopen(req, timeout=60) as response:
        content_length = int(response.headers.get("Content-Length") or 0)
        if content_length > MAX_DOWNLOAD_BYTES:
            raise RuntimeError("Official page exceeds download limit")
        html_data = response.read(MAX_DOWNLOAD_BYTES + 1)
        if len(html_data) > MAX_DOWNLOAD_BYTES:
            raise RuntimeError("Official page exceeds download limit")
    parser = TextExtractor()
    parser.feed(html_data.decode("utf-8", "replace"))
    text = parser.text()
    text_chunks = chunks(text)
    if len(text) < 1000 or not text_chunks:
        raise SystemExit("Downloaded page did not contain enough usable text")

    source_dir = ROOT / "sources" / "official-web" / source_uid
    text_dir = ROOT / "text" / "official-web"
    log_dir = ROOT / "logs"
    source_dir.mkdir(parents=True, exist_ok=True)
    text_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    html_path = source_dir / "snapshot.html"
    text_path = text_dir / (source_uid + ".txt")
    digest = hashlib.sha256(html_data).hexdigest()
    atomic_write(html_path, html_data)
    atomic_write(text_path, text.encode("utf-8"))
    retrieved_at = datetime.now(timezone.utc).isoformat()
    metadata = json.dumps({"publisher": publisher, "origin": parsed.hostname, "retrieved_at": retrieved_at, "snapshot_sha256": digest}, ensure_ascii=False)

    with psycopg.connect(os.environ["BR_DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sources (source_uid,title,source_type,source_class,public_url,local_path,status,confidentiality,citation_allowed,hint_only,sha256,metadata,last_checked_at)
                VALUES (%s,%s,'official_publisher_page','GELB',%s,%s,'technisch_geprueft','oeffentlich',false,true,%s,%s::jsonb,now())
                ON CONFLICT (source_uid) DO UPDATE SET title=EXCLUDED.title, public_url=EXCLUDED.public_url, local_path=EXCLUDED.local_path, sha256=EXCLUDED.sha256, metadata=EXCLUDED.metadata, last_checked_at=now(), updated_at=now(), status='technisch_geprueft', citation_allowed=false, hint_only=true
                RETURNING id
                """,
                (source_uid, title, url, str(text_path), digest, metadata),
            )
            source_id = cur.fetchone()[0]
            document_uid = source_uid + "-doc"
            cur.execute(
                """
                INSERT INTO documents (source_id,document_uid,title,original_path,text_path,sha256,ocr_status)
                VALUES (%s,%s,%s,%s,%s,%s,'html_text')
                ON CONFLICT (document_uid) DO UPDATE SET title=EXCLUDED.title, original_path=EXCLUDED.original_path, text_path=EXCLUDED.text_path, sha256=EXCLUDED.sha256, updated_at=now()
                RETURNING id
                """,
                (source_id, document_uid, title, str(html_path), str(text_path), digest),
            )
            document_id = cur.fetchone()[0]
            cur.execute("DELETE FROM chunks WHERE document_id=%s", (document_id,))
            for index, content in enumerate(text_chunks, start=1):
                locator = "Abschnitt %04d" % index
                cur.execute(
                    """
                    INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,citation_url,internal_ref)
                    VALUES (%s,%s,%s,%s,%s,'GELB',%s,%s,%s)
                    """,
                    (document_id, "%s-chunk-%04d" % (source_uid, index), content.splitlines()[0][:180], locator, content, "%s, %s" % (title, locator), url, "%s:%s" % (source_uid, locator)),
                )
        conn.commit()

    log_path = log_dir / ("import-official-web-%s-%s.log" % (source_uid, datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    log_path.write_text("timestamp=%s\nsource_uid=%s\nurl=%s\nsha256=%s\nchunks=%d\nstatus=ok\n" % (retrieved_at, source_uid, url, digest, len(text_chunks)), encoding="utf-8")
    log_path.chmod(0o640)
    print("imported source_uid=%s class=GELB citation_allowed=false chunks=%d" % (source_uid, len(text_chunks)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
