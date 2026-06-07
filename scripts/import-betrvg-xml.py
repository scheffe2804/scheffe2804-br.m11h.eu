#!/usr/bin/env python3
"""Register official BetrVG XML and create paragraph chunks."""

import hashlib
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import psycopg


ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
XML_PATH = ROOT / "sources/gesetze/betrvg/xml/BJNR000130972.xml"
SOURCE_URL = "https://www.gesetze-im-internet.de/betrvg/"


def text_of(elem: ET.Element) -> str:
    parts = []
    for t in elem.itertext():
        s = re.sub(r"\s+", " ", t).strip()
        if s:
            parts.append(s)
    return "\n".join(parts)


def find_norms(root: ET.Element) -> list[tuple[str, str, str]]:
    norms = []
    for norm in root.iter():
        if not norm.tag.endswith("norm"):
            continue
        text = text_of(norm)
        if not text:
            continue
        # Prefer official enbez/kbez style fields if present.
        label = ""
        heading = ""
        for child in norm.iter():
            tag = child.tag.split("}")[-1]
            val = " ".join(child.itertext()).strip()
            if tag == "enbez" and val:
                label = val
            if tag == "titel" and val and not heading:
                heading = val
        if not label:
            m = re.search(r"§\s*([0-9]+[a-zA-Z]?)", text)
            if m:
                label = "§ " + m.group(1)
        if label and label.strip().startswith("§"):
            norms.append((label, heading, text))
    return norms


def main() -> None:
    if not XML_PATH.exists():
        raise SystemExit("missing XML: %s" % XML_PATH)
    data = XML_PATH.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    root = ET.fromstring(data)
    norms = find_norms(root)
    db_url = os.environ["BR_DATABASE_URL"]
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sources (source_uid,title,source_type,source_class,public_url,local_path,status,confidentiality,citation_allowed,hint_only,sha256,metadata)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (source_uid) DO UPDATE SET sha256=EXCLUDED.sha256, local_path=EXCLUDED.local_path, updated_at=now(), citation_allowed=true, status='freigegeben'
                RETURNING id
                """,
                ("gesetz-betrvg", "Betriebsverfassungsgesetz (BetrVG)", "gesetz", "GRUEN", SOURCE_URL, str(XML_PATH), "freigegeben", "oeffentlich", True, False, sha, '{}'),
            )
            source_id = cur.fetchone()[0]
            cur.execute(
                """
                INSERT INTO documents (source_id,document_uid,title,original_path,text_path,sha256,ocr_status)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (document_uid) DO UPDATE SET sha256=EXCLUDED.sha256, original_path=EXCLUDED.original_path, updated_at=now()
                RETURNING id
                """,
                (source_id, "gesetz-betrvg-doc", "Betriebsverfassungsgesetz (BetrVG)", str(XML_PATH), str(XML_PATH), sha, "xml_import"),
            )
            doc_id = cur.fetchone()[0]
            cur.execute("DELETE FROM chunks WHERE document_id=%s", (doc_id,))
            inserted = 0
            for idx, (label, heading, content) in enumerate(norms, start=1):
                para = label.replace("§", "").strip().replace(" ", "")
                url = SOURCE_URL + "__%s.html" % para
                chunk_uid = "gesetz-betrvg-%s" % para.lower()
                citation = "BetrVG %s" % label
                if heading:
                    citation += " (%s)" % heading[:120]
                cur.execute(
                    """
                    INSERT INTO chunks (document_id,chunk_uid,heading,locator,content,source_class,citation_label,citation_url,internal_ref)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (chunk_uid) DO UPDATE SET content=EXCLUDED.content, citation_url=EXCLUDED.citation_url
                    """,
                    (doc_id, chunk_uid, heading or label, label, content, "GRUEN", citation, url, "gesetz-betrvg:%s" % label),
                )
                inserted += 1
            conn.commit()
    print("betrvg_norm_chunks=%d" % inserted)


if __name__ == "__main__":
    main()
