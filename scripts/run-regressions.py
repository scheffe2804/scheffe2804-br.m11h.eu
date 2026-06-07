#!/usr/bin/env python3
"""Run core BR knowledge-base regressions inside the app container.

The script intentionally uses the same application functions as the web UI:
it creates structured answers, validates citation coverage, checks duplicate
chunk/document-SHA conditions, exports protected HTML/PDF files, and prints a
compact machine-readable summary.
"""

import json
import sys
from pathlib import Path
from typing import Any

from main import (
    COOKIE_NAME,
    STORAGE_ROOT,
    answer_validation,
    create_structured_source_answer,
    create_structured_tariff_answer,
    db_one,
    db_rows,
    export_answer,
    serializer,
)


class DummyRequest:
    """Minimal request-like object for route functions that only need cookies."""

    def __init__(self) -> None:
        self.cookies = {
            COOKIE_NAME: serializer().dumps(
                {"user": "admin", "role": "admin", "iat": "regression-test"}
            )
        }


CASES: list[dict[str, Any]] = [
    {
        "name": "ocr_tariff_jobservice_corona",
        "query_uid": "test-ocr-corona-jobservice",
        "creator": "tariff",
        "allowed_classes": {"GRUEN", "BLAU"},
        "required_classes": {"BLAU"},
        "required_sources": {
            "evg-member-db-jobservice---corona-beihilfen-zusatzvereinbarung-85583f7c51f9"
        },
        "export_needles": {
            "Interne Quellenakte",
            "evg-member-db-jobservice---corona-beihilfen-zusatzvereinbarung-85583f7c51f9",
        },
    },
    {
        "name": "bag_tarifkollision_green_only",
        "query_uid": "test-bag-tarifkollision-4a-tvg",
        "creator": "official",
        "allowed_classes": {"GRUEN"},
        "required_classes": {"GRUEN"},
        "required_sources": {"bag-entscheidung-4-azr-101-25"},
        "export_needles": {"Interne Quellenakte", "bag-entscheidung-4-azr-101-25"},
    },
    {
        "name": "dsgvo_bdsg_green_only",
        "query_uid": "test-dsgvo-art-5-6-bdsg-26",
        "creator": "official",
        "allowed_classes": {"GRUEN"},
        "required_classes": {"GRUEN"},
        "required_sources": {"gesetz-dsgvo", "gesetz-bdsg"},
        "export_needles": {"Interne Quellenakte", "gesetz-dsgvo", "gesetz-bdsg"},
    },
    {
        "name": "tariff_demografietv_dedupe",
        "query_uid": "test-tarif-demografie-evg",
        "creator": "tariff",
        "allowed_classes": {"GRUEN", "BLAU"},
        "required_classes": {"BLAU"},
        "required_sources": {
            "m00h-25-05-21-2025-04-30-demografietv-bus-2025-final-unterzeichnet"
        },
        "export_needles": {
            "Interne Quellenakte",
            "m00h-25-05-21-2025-04-30-demografietv-bus-2025-final-unterzeichnet",
        },
    },
]


EXPORT_FORBIDDEN_MARKERS = [
    "/srv/",
    "/home/",
    "/run/",
    "/etc/",
    "file://",
    "../",
    "..\\",
    "BEGIN PRIVATE KEY",
    "Cf-Access-Jwt-Assertion",
    "Authorization:",
    "Proxy-Authorization:",
    "X-Auth-Token",
    "X-Api-Key",
]


def fail(message: str) -> None:
    raise AssertionError(message)


def answer_rows(answer_uid: str) -> list[dict[str, Any]]:
    return db_rows(
        """
        SELECT st.section, cit.chunk_id, cit.source_class, cit.citation_label,
               s.source_uid, s.source_type, d.sha256 AS document_sha256
        FROM answers a
        JOIN answer_statements st ON st.answer_id=a.id
        LEFT JOIN answer_citations cit ON cit.statement_id=st.id
        LEFT JOIN chunks c ON c.id=cit.chunk_id
        LEFT JOIN documents d ON d.id=c.document_id
        LEFT JOIN sources s ON s.id=d.source_id
        WHERE a.answer_uid=%s
        ORDER BY st.id
        """,
        (answer_uid,),
    )


def duplicate_items(values: list[Any]) -> list[Any]:
    return sorted({value for value in values if values.count(value) > 1})


def mixed_document_sha_sources(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sha_sources: dict[str, set[str]] = {}
    for row in rows:
        sha = row.get("document_sha256")
        source = row.get("source_uid")
        if not sha or not source:
            continue
        sha_sources.setdefault(str(sha), set()).add(str(source))
    return [
        {"document_sha256": sha, "sources": sorted(sources)}
        for sha, sources in sorted(sha_sources.items())
        if len(sources) > 1
    ]


def create_answer(request: DummyRequest, case: dict[str, Any]) -> str:
    creator_name = case["creator"]
    if creator_name == "official":
        response = create_structured_source_answer(request, case["query_uid"])
    elif creator_name == "tariff":
        response = create_structured_tariff_answer(request, case["query_uid"])
    else:
        fail("unsupported creator %s" % creator_name)
    location = response.headers.get("location", "")
    answer_uid = location.rsplit("/", 1)[-1]
    if not answer_uid:
        fail("missing answer uid for %s" % case["name"])
    return answer_uid


def check_export(request: DummyRequest, answer_uid: str, needles: set[str]) -> dict[str, Any]:
    export_answer(request, answer_uid)
    export_dir = STORAGE_ROOT / "exports" / answer_uid
    html_path = export_dir / "index.html"
    pdf_path = export_dir / "export.pdf"
    manifest_path = export_dir / "manifest.json"
    if not html_path.exists():
        fail("missing html export for %s" % answer_uid)
    if not pdf_path.exists():
        fail("missing pdf export for %s" % answer_uid)
    if not manifest_path.exists():
        fail("missing manifest export for %s" % answer_uid)
    pdf_size = pdf_path.stat().st_size
    if pdf_size < 10_000:
        fail("implausibly small pdf export for %s: %d" % (answer_uid, pdf_size))
    html = html_path.read_text(encoding="utf-8")
    missing_needles = sorted(needle for needle in needles if needle not in html)
    if missing_needles:
        fail("export %s missing needles %s" % (answer_uid, missing_needles))
    missing_required = sorted(needle for needle in ["noindex", "Internes Arbeitsdokument", "Keine Angabe ohne Quelle"] if needle not in html)
    if missing_required:
        fail("export %s missing required safety markers %s" % (answer_uid, missing_required))
    forbidden_hits = sorted(marker for marker in EXPORT_FORBIDDEN_MARKERS if marker in html)
    if forbidden_hits:
        fail("export %s contains forbidden marker(s): %s" % (answer_uid, forbidden_hits))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != 1:
        fail("export %s manifest version mismatch" % answer_uid)
    if manifest.get("answer_uid") != answer_uid:
        fail("export %s manifest answer mismatch" % answer_uid)
    policy = manifest.get("policy") or {}
    for key in ["internal_only", "no_public_direct_links", "no_statement_without_citation", "no_secret_values_in_manifest", "citation_label_hashed"]:
        if policy.get(key) is not True:
            fail("export %s manifest policy missing %s" % (answer_uid, key))
    files = manifest.get("files") or {}
    if "index.html" not in files or "export.pdf" not in files:
        fail("export %s manifest file entries missing" % answer_uid)
    return {
        "html_path": str(html_path),
        "pdf_path": str(pdf_path),
        "manifest_path": str(manifest_path),
        "pdf_size": pdf_size,
        "safety_markers_ok": True,
        "manifest_ok": True,
    }


def run_case(request: DummyRequest, case: dict[str, Any]) -> dict[str, Any]:
    query = db_one("SELECT query_uid FROM queries WHERE query_uid=%s", (case["query_uid"],))
    if not query:
        fail("missing query %s" % case["query_uid"])

    answer_uid = create_answer(request, case)
    answer = db_one("SELECT id FROM answers WHERE answer_uid=%s", (answer_uid,))
    if not answer:
        fail("answer not found after creation: %s" % answer_uid)
    validation = answer_validation(answer["id"])
    if validation["statement_count"] <= 0:
        fail("no statements for %s" % answer_uid)
    if validation["statements_without_citation"] != 0:
        fail("missing citations for %s: %s" % (answer_uid, validation))
    if validation["citation_count"] != validation["statement_count"]:
        fail("unexpected citation/statement count for %s: %s" % (answer_uid, validation))

    rows = answer_rows(answer_uid)
    source_classes = {row["source_class"] for row in rows if row.get("source_class")}
    source_uids = {row["source_uid"] for row in rows if row.get("source_uid")}
    source_types = {row["source_type"] for row in rows if row.get("source_type")}
    if not source_classes:
        fail("no source classes for %s" % answer_uid)
    if not source_classes <= case["allowed_classes"]:
        fail("disallowed source classes for %s: %s" % (answer_uid, sorted(source_classes)))
    if not case["required_classes"] <= source_classes:
        fail("required source classes missing for %s: %s" % (answer_uid, sorted(source_classes)))
    if not case["required_sources"] <= source_uids:
        fail(
            "required sources missing for %s: have=%s required=%s"
            % (answer_uid, sorted(source_uids), sorted(case["required_sources"]))
        )
    chunk_ids = [row["chunk_id"] for row in rows if row.get("chunk_id") is not None]
    duplicate_chunk_ids = duplicate_items(chunk_ids)
    if duplicate_chunk_ids:
        fail("duplicate chunk ids for %s: %s" % (answer_uid, duplicate_chunk_ids))
    mixed_sha = mixed_document_sha_sources(rows)
    if mixed_sha:
        fail("mixed duplicate document sha sources for %s: %s" % (answer_uid, mixed_sha))

    export = check_export(request, answer_uid, case["export_needles"])
    return {
        "name": case["name"],
        "query_uid": case["query_uid"],
        "answer_uid": answer_uid,
        "validation": validation,
        "source_classes": sorted(source_classes),
        "source_types": sorted(source_types),
        "source_uids": sorted(source_uids),
        "duplicate_chunk_ids": duplicate_chunk_ids,
        "mixed_document_sha_sources": mixed_sha,
        "export": export,
    }


def main() -> int:
    request = DummyRequest()
    results = [run_case(request, case) for case in CASES]
    print(json.dumps({"status": "ok", "results": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False, indent=2), file=sys.stderr)
        raise SystemExit(1)
