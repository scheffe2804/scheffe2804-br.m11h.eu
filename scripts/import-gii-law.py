#!/usr/bin/env python3
"""Import one law from gesetze-im-internet.de and create linked paragraph chunks.

Usage inside app container or host with psycopg installed:
  import-gii-law.py betrvg "Betriebsverfassungsgesetz (BetrVG)" gesetz-betrvg
"""

import hashlib
import os
import re
import sys
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
BASE_URL = "https://www.gesetze-im-internet.de"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "br.m11h.eu Quellenimport (private Betriebsrats-Wissensdatenbank)"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        return resp.read()


def text_of(elem: ET.Element) -> str:
    parts = []
    for t in elem.itertext():
        s = re.sub(r"\s+", " ", t).strip()
        if s:
            parts.append(s)
    return "\n".join(parts)


def find_norms(root: ET.Element) -> list[tuple[str, str, str]]:
    norms: list[tuple[str, str, str]] = []
    for norm in root.iter():
        if not norm.tag.endswith("norm"):
            continue
        content = text_of(norm)
        if not content:
            continue
        label = ""
        heading = ""
        for child in norm.iter():
            tag = child.tag.split("}")[-1]
            val = " ".join(child.itertext()).strip()
            if tag == "enbez" and val:
                label = val
            if tag == "titel" and val and not heading:
                heading = val
        # Only use actual paragraph/article norm labels as answer-citable chunks.
        if label and (label.strip().startswith("§") or label.strip().lower().startswith("art")):
            norms.append((label.strip(), heading.strip(), content.strip()))
    return norms


def url_for_label(slug: str, label: str) -> str:
    value = label.replace("§", "").strip()
    value = re.sub(r"^Art\.?\s*", "", value, flags=re.I).strip()
    value = value.replace(" ", "")
    value = urllib.parse.quote(value, safe="")
    if label.strip().lower().startswith("art"):
        # gesetze-im-internet commonly uses __art_1.html for articles where present.
        return "%s/%s/__art_%s.html" % (BASE_URL, slug, value)
    return "%s/%s/__%s.html" % (BASE_URL, slug, value)


def main() -> int:
    if len(sys.argv) < 4:
        print("Usage: import-gii-law.py <slug> <title> <source_uid>", file=sys.stderr)
        return 2
    slug, title, source_uid = sys.argv[1], sys.argv[2], sys.argv[3]
    source_url = "%s/%s/" % (BASE_URL, slug)
    out_dir = ROOT / "sources" / "gesetze" / slug
    xml_dir = out_dir / "xml"
    log_dir = ROOT / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    xml_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    zip_url = source_url + "xml.zip"
    zip_data = fetch(zip_url)
    zip_path = out_dir / (slug + ".xml.zip")
    zip_path.write_bytes(zip_data)
    zip_path.chmod(0o640)
    zip_sha = hashlib.sha256(zip_data).hexdigest()

    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
        z.extractall(xml_dir)
    for p in xml_dir.rglob("*"):
        if p.is_file():
            p.chmod(0o640)
    xml_files = sorted(xml_dir.glob("*.xml"))
    if not xml_files:
        raise SystemExit("No XML in %s" % zip_path)
    xml_path = xml_files[0]
    xml_data = xml_path.read_bytes()
    xml_sha = hashlib.sha256(xml_data).hexdigest()
    root = ET.fromstring(xml_data)
    norms = find_norms(root)
    if not norms:
        raise SystemExit("No citable norms found for %s" % slug)

    db_url = os.environ["BR_DATABASE_URL"]
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sources (source_uid,title,source_type,source_class,public_url,local_path,status,confidentiality,citation_allowed,hint_only,sha256,metadata)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (source_uid) DO UPDATE SET title=EXCLUDED.title, sha256=EXCLUDED.sha256, local_path=EXCLUDED.local_path, updated_at=now(), citation_allowed=true, status='freigegeben'
                RETURNING id
                """,
                (source_uid, title, "gesetz", "GRUEN", source_url, str(xml_path), "freigegeben", "oeffentlich", True, False, xml_sha, '{}'),
            )
            sid = cur.fetchone()[0]
            doc_uid = source_uid + "-doc"
            cur.execute(
                """
                INSERT INTO documents (source_id,document_uid,title,original_path,text_path,sha256,ocr_status)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (document_uid) DO UPDATE SET title=EXCLUDED.title, sha256=EXCLUDED.sha256, original_path=EXCLUDED.original_path, updated_at=now()
                RETURNING id
                """,
                (sid, doc_uid, title, str(xml_path), str(xml_path), xml_sha, "xml_import"),
            )
            doc_id = cur.fetchone()[0]
            cur.execute("DELETE FROM chunks WHERE document_id=%s", (doc_id,))
            inserted = 0
            for label, heading, content in norms:
                key = re.sub(r"[^0-9A-Za-z]+", "-", label).strip("-").lower()
                chunk_uid = "%s-%s" % (source_uid, key)
                citation = "%s %s" % (title.split("(")[-1].rstrip(")") if "(" in title else title, label)
                if heading:
                    citation += " (%s)" % heading[:120]
                cur.execute(
                    """
                    INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,citation_url,internal_ref)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (chunk_uid) DO UPDATE SET content=EXCLUDED.content, citation_url=EXCLUDED.citation_url, citation_label=EXCLUDED.citation_label
                    """,
                    (doc_id, chunk_uid, heading or label, label, content, "GRUEN", citation, url_for_label(slug, label), "%s:%s" % (source_uid, label)),
                )
                inserted += 1
            conn.commit()

    log = log_dir / ("import-%s-%s.log" % (slug, datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")))
    log.write_text("\n".join([
        "# Import gesetze-im-internet",
        "timestamp=%s" % datetime.now(timezone.utc).isoformat(),
        "slug=%s" % slug,
        "title=%s" % title,
        "source_url=%s" % source_url,
        "zip_url=%s" % zip_url,
        "zip_sha256=%s" % zip_sha,
        "xml_path=%s" % xml_path,
        "xml_sha256=%s" % xml_sha,
        "zip_entries=%s" % ",".join(names),
        "chunks=%d" % inserted,
    ]) + "\n", encoding="utf-8")
    log.chmod(0o640)
    print("imported slug=%s chunks=%d" % (slug, inserted))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
