#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen regression scripts.

The guard validates the opt-in regression runner, its Docker wrapper and the
read-only regression freshness guard for expected case, citation, export,
manifest, path and summary markers. It only reads project source files; it does
not run regressions, Docker, database queries, imports, backups or restores and
never reads secrets, dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
RUNNER = ROOT / "scripts" / "run-regressions.py"
WRAPPER = ROOT / "scripts" / "run-regressions-docker.sh"
FRESHNESS = ROOT / "scripts" / "check-regression-freshness.py"


RUNNER_MARKERS: list[tuple[str, str]] = [
    ("docstring_same_app_functions", "The script intentionally uses the same application functions as the web UI"),
    ("dummy_admin_cookie", "class DummyRequest"),
    ("cookie_serializer", "COOKIE_NAME: serializer().dumps"),
    ("case_list", "CASES: list[dict[str, Any]]"),
    ("case_ocr_tariff", '"name": "ocr_tariff_jobservice_corona"'),
    ("case_bag_green", '"name": "bag_tarifkollision_green_only"'),
    ("case_dsgvo_green", '"name": "dsgvo_bdsg_green_only"'),
    ("case_tariff_dedupe", '"name": "tariff_demografietv_dedupe"'),
    ("official_creator", "create_structured_source_answer"),
    ("tariff_creator", "create_structured_tariff_answer"),
    ("answer_validation", "answer_validation(answer[\"id\"])") ,
    ("answer_rows_join", "JOIN answer_statements st ON st.answer_id=a.id"),
    ("citation_join", "LEFT JOIN answer_citations cit ON cit.statement_id=st.id"),
    ("document_sha_check", "mixed_document_sha_sources"),
    ("duplicate_chunk_check", "duplicate_chunk_ids"),
    ("allowed_classes_check", "source_classes <= case[\"allowed_classes\"]"),
    ("required_classes_check", "case[\"required_classes\"] <= source_classes"),
    ("required_sources_check", "case[\"required_sources\"] <= source_uids"),
    ("export_answer_call", "export_answer(request, answer_uid)"),
    ("html_export", "index.html"),
    ("pdf_export", "export.pdf"),
    ("manifest_export", "manifest.json"),
    ("pdf_min_size", "pdf_size < 10_000"),
    ("safety_noindex", "noindex"),
    ("safety_internal_doc", "Internes Arbeitsdokument"),
    ("safety_no_source", "Keine Angabe ohne Quelle"),
    ("forbidden_export_markers", "EXPORT_FORBIDDEN_MARKERS"),
    ("forbidden_private_key", "BEGIN PRIVATE KEY"),
    ("forbidden_auth_header", "Authorization:"),
    ("manifest_version", "manifest.get(\"manifest_version\") != 1"),
    ("manifest_answer_uid", "manifest.get(\"answer_uid\") != answer_uid"),
    ("manifest_policy_internal", "internal_only"),
    ("manifest_policy_no_public", "no_public_direct_links"),
    ("manifest_policy_no_statement_without_citation", "no_statement_without_citation"),
    ("manifest_policy_no_secret_values", "no_secret_values_in_manifest"),
    ("manifest_policy_hashed_label", "citation_label_hashed"),
    ("summary_status", '"status": "ok"'),
    ("summary_results", '"results": results'),
]


RUNNER_FAILURE_MARKERS = [
    "missing answer uid",
    "missing html export",
    "missing pdf export",
    "missing manifest export",
    "implausibly small pdf export",
    "missing required safety markers",
    "contains forbidden marker",
    "manifest version mismatch",
    "manifest answer mismatch",
    "manifest policy missing",
    "no statements",
    "missing citations",
    "unexpected citation/statement count",
    "disallowed source classes",
    "required source classes missing",
    "required sources missing",
    "duplicate chunk ids",
    "mixed duplicate document sha sources",
]


WRAPPER_MARKERS = [
    "set -euo pipefail",
    "ROOT=\"/home/chris/web/br.m11h.eu\"",
    "DOCKER_BIN=\"/usr/bin/docker\"",
    "cd \"$ROOT\"",
    "\"$DOCKER_BIN\" compose exec -T app python - < scripts/run-regressions.py",
]


FRESHNESS_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "It does not create new answers, exports or database rows"),
    ("case_list", "CASES: list[dict[str, Any]]"),
    ("case_ocr_tariff", '"name": "ocr_tariff_jobservice_corona"'),
    ("case_bag_green", '"name": "bag_tarifkollision_green_only"'),
    ("case_dsgvo_green", '"name": "dsgvo_bdsg_green_only"'),
    ("case_tariff_dedupe", '"name": "tariff_demografietv_dedupe"'),
    ("sql_quote", "def sql_quote(value: str)"),
    ("latest_answer_cte", "WITH latest AS"),
    ("answers_join_queries", "JOIN queries q ON q.id=a.query_id"),
    ("statement_count", "statement_count="),
    ("citation_count", "citation_count="),
    ("statements_without_citation", "statements_without_citation="),
    ("source_classes", "source_classes="),
    ("source_uids", "source_uids="),
    ("duplicate_chunks", "duplicate_chunk_ids="),
    ("mixed_sha", "mixed_document_sha_groups="),
    ("docker_psql", '"docker", "compose", "exec", "-T", "db", "psql"'),
    ("max_age_env", "BR_REGRESSION_MAX_AGE_HOURS"),
    ("storage_prefix", "storage_prefix = str(STORAGE_ROOT.resolve()) + os.sep"),
    ("path_absolute_storage", "if not path.is_absolute() or not str(path).startswith(storage_prefix):"),
    ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
    ("stat_path", "STAT = Path(\"/usr/bin/stat\")"),
    ("helper_available", "def helper_available(path: Path) -> bool:"),
    ("sudo_stat_fallback", 'str(SUDO), "-n", str(STAT), "-c", "%s"'),
    ("pdf_min_size", "pdf_size < 10_000"),
    ("manifest_min_size", "manifest_size < 100"),
    ("summary", "regression_freshness_status=%s checks=%d findings=%d cases=%d exported_cases=%d max_age_h=%.1f min_age_h=%.1f"),
]


FORBIDDEN_RUNNER_MARKERS = [
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
    "subprocess.run",
]


FORBIDDEN_FRESHNESS_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
    "COMMIT",
    "conn.commit",
    "os.remove(",
    "Path.unlink(",
    "shutil.rmtree",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def check_named_markers(findings: list[str], text: str, markers: list[tuple[str, str]], prefix: str) -> int:
    checks = 0
    for label, marker in markers:
        checks += 1
        if marker not in text:
            findings.append("%s_missing=%s" % (prefix, safe(label)))
    return checks


def check_literals(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker not in text:
            findings.append("%s_missing=%s" % (prefix, safe(marker)))
    return checks


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen regression source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    runner_text = read_source(RUNNER, findings, "runner")
    wrapper_text = read_source(WRAPPER, findings, "wrapper")
    freshness_text = read_source(FRESHNESS, findings, "freshness")
    checks += 3

    checks += check_named_markers(findings, runner_text, RUNNER_MARKERS, "runner")
    checks += check_literals(findings, runner_text, RUNNER_FAILURE_MARKERS, "runner_failure")
    checks += check_literals(findings, wrapper_text, WRAPPER_MARKERS, "wrapper")
    checks += check_named_markers(findings, freshness_text, FRESHNESS_MARKERS, "freshness")
    checks += check_forbidden(findings, runner_text, FORBIDDEN_RUNNER_MARKERS, "runner")
    checks += check_forbidden(findings, freshness_text, FORBIDDEN_FRESHNESS_MARKERS, "freshness")

    checks += 1
    if runner_text.find("CASE") > runner_text.find("def run_case"):
        findings.append("runner_cases_after_run_case")
    checks += 1
    if runner_text.find("answer_validation") > runner_text.find("check_export"):
        findings.append("runner_validation_after_export")
    checks += 1
    if wrapper_text.find("cd \"$ROOT\"") > wrapper_text.find("compose exec -T app python"):
        findings.append("wrapper_docker_before_cd")
    checks += 1
    if freshness_text.find("def guarded_file_size") > freshness_text.find("manifest_size < 100"):
        findings.append("freshness_guarded_file_size_after_manifest_check")

    status = "ok" if not findings else "failed"
    summary = "regression_source_hardening_status=%s checks=%d findings=%d runner_markers=%d failure_markers=%d wrapper_markers=%d freshness_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(RUNNER_MARKERS),
        len(RUNNER_FAILURE_MARKERS),
        len(WRAPPER_MARKERS),
        len(FRESHNESS_MARKERS),
        len(FORBIDDEN_RUNNER_MARKERS) + len(FORBIDDEN_FRESHNESS_MARKERS),
    )
    if args.summary:
        print(summary)
    else:
        for part in summary.split():
            print(part)
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
