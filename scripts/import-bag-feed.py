#!/usr/bin/env python3
"""Small official BAG decision importer.

Imports a limited number of recent decisions from the official Bundesarbeits-
gericht RSS feed.  Each decision is a separate GRUEN source; each cited chunk is
one numbered BAG paragraph/Randnummer.  This script is intentionally conservative
and defaults to a small pilot import.
"""

from __future__ import annotations

import hashlib
import html
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
import json

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
FEED_URL = "https://www.bundesarbeitsgericht.de/feed/entscheidung/neueste"
BASE_DIR = ROOT / "sources" / "rechtsprechung" / "bag"


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[no-untyped-def]
        if tag.lower() in {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "blockquote", "a"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data)

    def text(self) -> str:
        lines = [line.strip() for line in "".join(self.parts).splitlines() if line.strip()]
        return re.sub(r"\n\s*\n+", "\n", "\n".join(lines))


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "br.m11h.eu BAG Quellenimport (private Betriebsrats-Wissensdatenbank)"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def slug_from_url(url: str) -> str:
    path = urllib.parse.urlparse(url).path.strip("/")
    slug = path.split("/")[-1]
    return re.sub(r"[^0-9a-z-]+", "-", slug.lower()).strip("-")


def plain_text_from_html(html_data: bytes) -> str:
    parser = TextExtractor()
    parser.feed(html_data.decode("utf-8", "replace"))
    return parser.text()


def meta_value(text: str, label: str) -> str:
    pattern = r"(?m)^" + re.escape(label) + r"\n([^\n]+)"
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ""


def title_from_text(text: str, fallback: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        if line == "Details" and idx >= 2:
            return lines[idx - 2]
    return fallback


def clean_feed_description(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value or "")
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def source_title(aktenzeichen: str, decision_title: str, feed_description: str) -> str:
    topic = clean_feed_description(feed_description) or decision_title
    if topic == aktenzeichen:
        return "BAG " + aktenzeichen
    return "BAG " + aktenzeichen + " - " + topic


def decision_body(text: str) -> str:
    start_positions = [pos for pos in [text.find("Tenor\n"), text.find("Tatbestand\n"), text.find("Entscheidungsgründe\n")] if pos >= 0]
    if not start_positions:
        raise SystemExit("Could not locate decision body")
    start = min(start_positions)
    end = text.find("Seite drucken", start)
    if end < 0:
        end = len(text)
    return text[start:end].strip()


def numbered_paragraphs(body: str) -> list[tuple[str, str]]:
    matches = list(re.finditer(r"(?m)^(\d+)$", body))
    paragraphs: list[tuple[str, str]] = []
    for idx, match in enumerate(matches):
        number = match.group(1)
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        content = body[match.end():end].strip()
        content = re.sub(r"\n+", "\n", content)
        if content:
            paragraphs.append((number, content))
    return paragraphs


def feed_items(limit: int) -> list[dict[str, str]]:
    feed = fetch(FEED_URL)
    root = ET.fromstring(feed)
    items: list[dict[str, str]] = []
    for item in root.findall("./channel/item")[:limit]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        description = html.unescape((item.findtext("description") or "").strip())
        pub_date = (item.findtext("pubDate") or "").strip()
        if title and link:
            items.append({"title": title, "link": link, "description": description, "pub_date": pub_date})
    return items


def import_decision(cur, item: dict[str, str]) -> tuple[str, int]:  # type: ignore[no-untyped-def]
    url = item["link"]
    slug = slug_from_url(url)
    source_uid = "bag-entscheidung-" + slug
    out_dir = BASE_DIR / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    html_data = fetch(url)
    sha = hashlib.sha256(html_data).hexdigest()
    text = plain_text_from_html(html_data)
    title = title_from_text(text, item["title"])
    aktenzeichen = meta_value(text, "Aktenzeichen") or item["title"]
    ecli = meta_value(text, "ECLI")
    art = meta_value(text, "Art")
    date_value = meta_value(text, "Datum")
    senat = meta_value(text, "Senat")
    body = decision_body(text)
    paragraphs = numbered_paragraphs(body)
    if not paragraphs:
        raise SystemExit("No numbered paragraphs found for %s" % url)

    html_path = out_dir / (slug + ".html")
    text_path = out_dir / (slug + ".txt")
    html_path.write_bytes(html_data)
    text_path.write_text(text, encoding="utf-8")
    html_path.chmod(0o640)
    text_path.chmod(0o640)

    metadata = json.dumps({
        "gericht": "BAG",
        "aktenzeichen": aktenzeichen,
        "ecli": ecli,
        "art": art,
        "datum": date_value,
        "senat": senat,
        "feed": FEED_URL,
        "feed_description": clean_feed_description(item.get("description", "")),
        "feed_pub_date": item.get("pub_date", ""),
    }, ensure_ascii=False)
    cur.execute(
        """
        INSERT INTO sources (source_uid,title,source_type,source_class,public_url,local_path,status,confidentiality,citation_allowed,hint_only,sha256,metadata,last_checked_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
        ON CONFLICT (source_uid) DO UPDATE SET title=EXCLUDED.title, sha256=EXCLUDED.sha256, local_path=EXCLUDED.local_path, public_url=EXCLUDED.public_url, updated_at=now(), citation_allowed=true, status='freigegeben', last_checked_at=now(), metadata=EXCLUDED.metadata
        RETURNING id
        """,
        (source_uid, source_title(aktenzeichen, title, item.get("description", "")), "rechtsprechung_bag", "GRUEN", url, str(text_path), "freigegeben", "oeffentlich", True, False, sha, metadata),
    )
    source_id = cur.fetchone()[0]
    doc_uid = source_uid + "-doc"
    cur.execute(
        """
        INSERT INTO documents (source_id,document_uid,title,original_path,text_path,sha256,ocr_status)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (document_uid) DO UPDATE SET title=EXCLUDED.title, original_path=EXCLUDED.original_path, text_path=EXCLUDED.text_path, sha256=EXCLUDED.sha256, updated_at=now()
        RETURNING id
        """,
        (source_id, doc_uid, "BAG " + aktenzeichen, str(html_path), str(text_path), sha, "html_import"),
    )
    document_id = cur.fetchone()[0]
    cur.execute("DELETE FROM chunks WHERE document_id=%s", (document_id,))
    inserted = 0
    for rn, content in paragraphs:
        chunk_uid = "%s-rn-%s" % (source_uid, rn)
        citation_label = "BAG %s Rn. %s" % (aktenzeichen, rn)
        if ecli:
            citation_label += " (%s)" % ecli
        cur.execute(
            """
            INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,citation_url,internal_ref)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (chunk_uid) DO UPDATE SET content=EXCLUDED.content, citation_url=EXCLUDED.citation_url, citation_label=EXCLUDED.citation_label, heading=EXCLUDED.heading
            """,
            (document_id, chunk_uid, "BAG " + aktenzeichen + " Rn. " + rn, "Rn. " + rn, content, "GRUEN", citation_label, url + "#rd-" + rn, "%s:Rn.%s" % (source_uid, rn)),
        )
        inserted += 1
    return source_uid, inserted


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    (ROOT / "logs").mkdir(parents=True, exist_ok=True)
    items = feed_items(limit)
    if not items:
        raise SystemExit("No BAG feed items found")
    results: list[tuple[str, int]] = []
    failures: list[tuple[str, str]] = []
    with psycopg.connect(os.environ["BR_DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            for item in items:
                try:
                    results.append(import_decision(cur, item))
                except Exception as exc:
                    failures.append((item.get("link") or item.get("title") or "unknown", "%s: %s" % (type(exc).__name__, exc)))
        conn.commit()
    log = ROOT / "logs" / ("import-bag-feed-%s.log" % datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    log.write_text("\n".join(
        [
            "# Import BAG Feed",
            "timestamp=%s" % datetime.now(timezone.utc).isoformat(),
            "feed_url=%s" % FEED_URL,
            "limit=%d" % limit,
            "imported=%d" % len(results),
            "failed=%d" % len(failures),
        ]
        + ["%s chunks=%d" % (uid, count) for uid, count in results]
        + ["FAILED %s :: %s" % (target, error) for target, error in failures]
    ) + "\n", encoding="utf-8")
    log.chmod(0o640)
    for uid, count in results:
        print("imported source_uid=%s chunks=%d" % (uid, count))
    for target, error in failures:
        print("failed target=%s error=%s" % (target, error), file=sys.stderr)
    if failures and not results:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
