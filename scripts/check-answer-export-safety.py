#!/usr/bin/env python3
"""Read-only safety guard for generated answers and exports.

The guard checks metadata, citation coverage and generated HTML exports without
printing answer text, source text, dump contents or secret values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
STORAGE_ROOT = Path(os.getenv("BR_STORAGE_ROOT", "/srv/br-wissensdatenbank"))
EXPORT_ROOT = STORAGE_ROOT / "exports"

PATH_MARKERS = ["/srv/", "/home/", "/run/", "/etc/", "C:\\", "D:\\"]
SECRET_MARKERS = [
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "Cf-Access-Jwt-Assertion",
    "Authorization:",
    "Proxy-Authorization:",
    "X-Auth-Token",
    "X-Api-Key",
]
DIRECT_FILE_MARKERS = ["file://", "../", "..\\"]


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(cwd) if cwd else None, text=True, capture_output=True, check=False)


def db_metrics() -> dict[str, int]:
    sql = """
SELECT 'answers_without_statements=' || count(*)
FROM answers a
WHERE NOT EXISTS (SELECT 1 FROM answer_statements st WHERE st.answer_id=a.id);
SELECT 'statements_without_citation=' || count(*)
FROM answer_statements st LEFT JOIN answer_citations cit ON cit.statement_id=st.id
WHERE cit.id IS NULL;
SELECT 'citations_without_chunk_or_ref=' || count(*)
FROM answer_citations WHERE chunk_id IS NULL AND coalesce(internal_ref,'')='';
SELECT 'recent_gelb_citations=' || count(*)
FROM answer_citations WHERE source_class='GELB' AND created_at >= now() - interval '30 days';
SELECT 'answer_class_mismatches=' || count(*)
FROM answer_citations cit
JOIN chunks c ON c.id=cit.chunk_id
JOIN documents d ON d.id=c.document_id
JOIN sources s ON s.id=d.source_id
WHERE cit.source_class <> c.source_class OR cit.source_class <> s.source_class;
SELECT 'exports_without_html=' || count(*)
FROM answers WHERE html_path IS NOT NULL AND html_path <> '' AND pdf_path IS NOT NULL AND pdf_path <> '';
SELECT 'answers_with_partial_export_paths=' || count(*)
FROM answers WHERE (coalesce(html_path,'')='') <> (coalesce(pdf_path,'')='');
"""
    metrics = {
        "answers_without_statements": 0,
        "statements_without_citation": 0,
        "citations_without_chunk_or_ref": 0,
        "recent_gelb_citations": 0,
        "answer_class_mismatches": 0,
        "exports_without_html": 0,
        "answers_with_partial_export_paths": 0,
    }
    proc = run([
        "docker",
        "compose",
        "exec",
        "-T",
        "db",
        "psql",
        "-U",
        "br_app",
        "-d",
        "br_wissen",
        "-Atc",
        sql,
    ], cwd=ROOT)
    if proc.returncode != 0:
        metrics["db_query_failed"] = 1
        return metrics
    for line in proc.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            metrics[key] = int(value)
        except ValueError:
            metrics[key] = -1
    return metrics


def db_export_paths() -> list[tuple[str, str, str]]:
    proc = run([
        "docker",
        "compose",
        "exec",
        "-T",
        "db",
        "psql",
        "-U",
        "br_app",
        "-d",
        "br_wissen",
        "-Atc",
        "SELECT answer_uid || E'\\t' || coalesce(html_path,'') || E'\\t' || coalesce(pdf_path,'') FROM answers WHERE coalesce(html_path,'')<>'' OR coalesce(pdf_path,'')<>'' ORDER BY created_at DESC",
    ], cwd=ROOT)
    if proc.returncode != 0:
        return []
    out: list[tuple[str, str, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            out.append((parts[0], parts[1], parts[2]))
    return out


def marker_hits(text: str, markers: list[str]) -> list[str]:
    hits = []
    for marker in markers:
        if marker in text:
            hits.append(marker)
    # Windows path with arbitrary drive letter.
    if re.search(r"\b[A-Za-z]:\\", text):
        hits.append("WINDOWS_DRIVE_PATH")
    return sorted(set(hits))


def read_text_guarded(path: Path) -> tuple[str, str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace"), "direct"
    except PermissionError:
        proc = run([
            "sudo",
            "-n",
            "python3",
            "-c",
            "from pathlib import Path; import sys; sys.stdout.write(Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace'))",
            str(path),
        ])
        if proc.returncode == 0:
            return proc.stdout, "sudo"
        return "", "permission_denied"


def sha256_file_guarded(path: Path) -> tuple[str | None, str]:
    try:
        h = __import__("hashlib").sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest(), "direct"
    except PermissionError:
        proc = run([
            "sudo",
            "-n",
            "python3",
            "-c",
            "from pathlib import Path; import hashlib, sys; h=hashlib.sha256();\nwith Path(sys.argv[1]).open('rb') as f:\n    [h.update(block) for block in iter(lambda: f.read(1024*1024), b'')];\nprint(h.hexdigest())",
            str(path),
        ])
        if proc.returncode == 0:
            return proc.stdout.strip(), "sudo"
        return None, "permission_denied"


def read_json_guarded(path: Path) -> tuple[dict[str, object] | None, str]:
    text, method = read_text_guarded(path)
    if method == "permission_denied":
        return None, method
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None, "json_error"
    if not isinstance(data, dict):
        return None, "json_error"
    return data, method


def export_checks(paths: list[tuple[str, str, str]]) -> tuple[dict[str, int], list[str]]:
    counts = {
        "export_paths": len(paths),
        "html_checked": 0,
        "pdf_checked": 0,
        "missing_html": 0,
        "missing_pdf": 0,
        "small_pdf": 0,
        "html_path_marker_hits": 0,
        "html_secret_marker_hits": 0,
        "html_direct_file_marker_hits": 0,
        "html_missing_noindex": 0,
        "html_missing_internal_watermark": 0,
        "html_permission_denied": 0,
        "missing_manifest": 0,
        "manifest_permission_denied": 0,
        "manifest_json_error": 0,
        "manifest_version_mismatch": 0,
        "manifest_answer_mismatch": 0,
        "manifest_validation_mismatch": 0,
        "manifest_file_hash_mismatch": 0,
        "manifest_file_size_mismatch": 0,
        "manifest_file_hash_permission_denied": 0,
        "manifest_policy_mismatch": 0,
    }
    findings: list[str] = []
    storage_prefix = str(STORAGE_ROOT.resolve()) + os.sep
    for answer_uid, html_value, pdf_value in paths:
        for kind, value in [("html", html_value), ("pdf", pdf_value)]:
            if not value:
                continue
            path = Path(value)
            if not path.is_absolute() or not str(path).startswith(storage_prefix):
                findings.append("%s path outside storage for %s" % (kind, answer_uid))
        if html_value:
            html_path = Path(html_value)
            if not html_path.exists():
                counts["missing_html"] += 1
                findings.append("missing html export for %s" % answer_uid)
            else:
                counts["html_checked"] += 1
                text, read_method = read_text_guarded(html_path)
                if read_method == "permission_denied":
                    counts["html_permission_denied"] += 1
                    findings.append("html permission denied for %s" % answer_uid)
                    continue
                if "noindex" not in text.lower():
                    counts["html_missing_noindex"] += 1
                    findings.append("html missing noindex for %s" % answer_uid)
                if "Internes Arbeitsdokument" not in text:
                    counts["html_missing_internal_watermark"] += 1
                    findings.append("html missing watermark for %s" % answer_uid)
                path_hits = marker_hits(text, PATH_MARKERS)
                if path_hits:
                    counts["html_path_marker_hits"] += 1
                    findings.append("html path marker hit for %s" % answer_uid)
                secret_hits = marker_hits(text, SECRET_MARKERS)
                if secret_hits:
                    counts["html_secret_marker_hits"] += 1
                    findings.append("html secret/header marker hit for %s" % answer_uid)
                direct_hits = marker_hits(text, DIRECT_FILE_MARKERS)
                if direct_hits:
                    counts["html_direct_file_marker_hits"] += 1
                    findings.append("html direct file marker hit for %s" % answer_uid)
        if pdf_value:
            pdf_path = Path(pdf_value)
            if not pdf_path.exists():
                counts["missing_pdf"] += 1
                findings.append("missing pdf export for %s" % answer_uid)
            else:
                counts["pdf_checked"] += 1
                if pdf_path.stat().st_size < 10_000:
                    counts["small_pdf"] += 1
                    findings.append("small pdf export for %s" % answer_uid)
        if html_value and pdf_value:
            manifest_path = Path(html_value).parent / "manifest.json"
            if not manifest_path.exists():
                counts["missing_manifest"] += 1
                findings.append("missing manifest for %s" % answer_uid)
            else:
                manifest, method = read_json_guarded(manifest_path)
                if method == "permission_denied":
                    counts["manifest_permission_denied"] += 1
                    findings.append("manifest permission denied for %s" % answer_uid)
                elif method == "json_error" or manifest is None:
                    counts["manifest_json_error"] += 1
                    findings.append("manifest json error for %s" % answer_uid)
                else:
                    if int(manifest.get("manifest_version") or 0) != 1:
                        counts["manifest_version_mismatch"] += 1
                        findings.append("manifest version mismatch for %s" % answer_uid)
                    if manifest.get("answer_uid") != answer_uid:
                        counts["manifest_answer_mismatch"] += 1
                        findings.append("manifest answer mismatch for %s" % answer_uid)
                    validation = manifest.get("validation") if isinstance(manifest.get("validation"), dict) else {}
                    if int(validation.get("statements_without_citation") or 0) != 0:
                        counts["manifest_validation_mismatch"] += 1
                        findings.append("manifest validation mismatch for %s" % answer_uid)
                    policy = manifest.get("policy") if isinstance(manifest.get("policy"), dict) else {}
                    for key in ["internal_only", "no_public_direct_links", "no_statement_without_citation", "no_secret_values_in_manifest", "citation_label_hashed"]:
                        if policy.get(key) is not True:
                            counts["manifest_policy_mismatch"] += 1
                            findings.append("manifest policy mismatch for %s" % answer_uid)
                            break
                    files = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
                    for file_name, path_value in [("index.html", html_value), ("export.pdf", pdf_value)]:
                        file_meta = files.get(file_name) if isinstance(files.get(file_name), dict) else {}
                        path = Path(path_value)
                        if path.exists():
                            digest, digest_method = sha256_file_guarded(path)
                            if digest_method == "permission_denied" or digest is None:
                                counts["manifest_file_hash_permission_denied"] += 1
                                findings.append("manifest hash permission denied for %s" % answer_uid)
                            elif file_meta.get("sha256") != digest:
                                counts["manifest_file_hash_mismatch"] += 1
                                findings.append("manifest hash mismatch for %s" % answer_uid)
                            if int(file_meta.get("bytes") or -1) != path.stat().st_size:
                                counts["manifest_file_size_mismatch"] += 1
                                findings.append("manifest size mismatch for %s" % answer_uid)
    return counts, findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen answer/export safety")
    parser.add_argument("--summary", action="store_true", help="print one compact status line")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    metrics = db_metrics()
    for key, value in sorted(metrics.items()):
        checks += 1
        if key == "exports_without_html":
            continue
        if value != 0:
            findings.append("%s=%s" % (key, value))

    paths = db_export_paths()
    export_counts, export_findings = export_checks(paths)
    findings.extend(export_findings)
    checks += len(export_counts)
    for key, value in sorted(export_counts.items()):
        if key in {"export_paths", "html_checked", "pdf_checked"}:
            continue
        if value != 0:
            findings.append("%s=%s" % (key, value))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "answer_export_safety_status=%s checks=%d findings=%d answers_without_statements=%s statements_without_citation=%s html_checked=%s pdf_checked=%s"
            % (
                status,
                checks,
                len(findings),
                metrics.get("answers_without_statements", 0),
                metrics.get("statements_without_citation", 0),
                export_counts.get("html_checked", 0),
                export_counts.get("pdf_checked", 0),
            )
        )
    else:
        print("answer_export_safety_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        for key in sorted(metrics):
            print("%s=%s" % (key, metrics[key]))
        for key in sorted(export_counts):
            print("%s=%s" % (key, export_counts[key]))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
