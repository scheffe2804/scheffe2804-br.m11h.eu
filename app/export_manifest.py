from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MANIFEST_VERSION = 1


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def build_export_manifest(
    *,
    answer: dict[str, Any],
    statements: list[dict[str, Any]],
    validation: dict[str, Any],
    html_path: Path,
    pdf_path: Path,
    generated_by: str,
) -> dict[str, Any]:
    source_uids = sorted({str(item.get("source_uid")) for item in statements if item.get("source_uid")})
    source_classes = sorted({str(item.get("source_class")) for item in statements if item.get("source_class")})
    source_types = sorted({str(item.get("source_type")) for item in statements if item.get("source_type")})
    chunk_uids = sorted({str(item.get("chunk_uid")) for item in statements if item.get("chunk_uid")})
    citations = [
        {
            "source_class": item.get("source_class"),
            "source_uid": item.get("source_uid"),
            "source_type": item.get("source_type"),
            "chunk_uid": item.get("chunk_uid"),
            "locator": item.get("locator"),
            "citation_label_sha256": hashlib.sha256(str(item.get("citation_label") or "").encode("utf-8", errors="ignore")).hexdigest(),
        }
        for item in statements
    ]
    return {
        "manifest_version": MANIFEST_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": generated_by,
        "answer_uid": answer.get("answer_uid"),
        "query_uid": answer.get("query_uid"),
        "answer_status": answer.get("status"),
        "answer_fingerprint": answer.get("fingerprint"),
        "validation": {key: int(validation.get(key) or 0) for key in ["statement_count", "citation_count", "statements_without_citation"]},
        "source_classes": source_classes,
        "source_types": source_types,
        "source_uids": source_uids,
        "chunk_uids": chunk_uids,
        "citations": citations,
        "files": {
            "index.html": {
                "sha256": sha256_file(html_path),
                "bytes": html_path.stat().st_size,
            },
            "export.pdf": {
                "sha256": sha256_file(pdf_path),
                "bytes": pdf_path.stat().st_size,
            },
        },
        "policy": {
            "internal_only": True,
            "no_public_direct_links": True,
            "no_statement_without_citation": True,
            "no_secret_values_in_manifest": True,
            "citation_label_hashed": True,
        },
    }


def write_export_manifest(
    *,
    export_dir: Path,
    answer: dict[str, Any],
    statements: list[dict[str, Any]],
    validation: dict[str, Any],
    html_path: Path,
    pdf_path: Path,
    generated_by: str,
) -> Path:
    manifest = build_export_manifest(
        answer=answer,
        statements=statements,
        validation=validation,
        html_path=html_path,
        pdf_path=pdf_path,
        generated_by=generated_by,
    )
    manifest_path = export_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(manifest_path, 0o640)
    return manifest_path
