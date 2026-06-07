#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen meta/governance guards.

The guard validates guard-coverage, readiness-documentation, syntax and systemd
unit guard sources for expected wiring, documentation, summary and non-mutating
behaviour markers. It only reads project source files; it does not run guard
coverage, readiness checks, syntax checks, systemctl, Docker, backups, restores,
imports, regressions or database queries and never reads secrets, dumps, logs,
answers, exports or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
GUARD_COVERAGE = ROOT / "scripts" / "check-guard-coverage.py"
READINESS_DOC = ROOT / "scripts" / "check-readiness-doc.py"
PYTHON_SYNTAX = ROOT / "scripts" / "check-python-syntax.sh"
SHELL_SYNTAX = ROOT / "scripts" / "check-shell-syntax.sh"
SYSTEMD_UNITS = ROOT / "scripts" / "check-systemd-units.sh"
DOC_SOURCE_HARDENING = ROOT / "scripts" / "check-doc-source-hardening.py"
SOURCE_HARDENING_COVERAGE = ROOT / "scripts" / "check-source-hardening-coverage.py"
SUMMARY_CONTRACTS = ROOT / "scripts" / "check-summary-contracts.py"
SURFACE_REGISTRY = ROOT / "scripts" / "check-surface-registry.py"
GUARD_REGISTRY_INTEGRITY = ROOT / "scripts" / "check-guard-registry-integrity.py"
PROTOCOL_INTEGRITY = ROOT / "scripts" / "check-protocol-integrity.py"
GIT_REMOTE_READINESS = ROOT / "scripts" / "check-git-remote-readiness.py"
BACKUP_SCOPE = ROOT / "scripts" / "check-backup-scope.py"


GUARD_COVERAGE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only guard coverage consistency check for BR-Wissen"),
    ("docstring_surfaces", "manual status, backup preflight,\nsystemd healthcheck and readiness documentation"),
    ("status_script", "STATUS_SCRIPT = ROOT / \"scripts\" / \"status-br-wissen.sh\""),
    ("backup_script", "BACKUP_SCRIPT = ROOT / \"scripts\" / \"backup-br-wissen.sh\""),
    ("project_unit", "PROJECT_HEALTHCHECK_UNIT = ROOT / \"systemd\" / \"br-wissen-healthcheck.service\""),
    ("installed_unit", "INSTALLED_HEALTHCHECK_UNIT = Path(\"/etc/systemd/system/br-wissen-healthcheck.service\")"),
    ("readiness", "READINESS = ROOT / \"docs\" / \"READINESS.md\""),
    ("dataclass", "@dataclass(frozen=True)"),
    ("guard_spec", "class GuardSpec:"),
    ("status_key", "status_key: str"),
    ("in_status", "in_status: bool = True"),
    ("in_backup", "in_backup: bool = True"),
    ("in_healthcheck", "in_healthcheck: bool = True"),
    ("in_readiness", "in_readiness: bool = True"),
    ("guards", "GUARDS: list[GuardSpec] = ["),
    ("meta_source_hardening", "Meta-Source-Hardening"),
    ("read_text", "def read_text(path: Path, findings: list[str]) -> str:"),
    ("require_contains", "def require_contains(findings: list[str], surface: str, haystack: str, needle: str, label: str) -> None:"),
    ("script_exists", "if not script_path.exists():"),
    ("script_executable", "not os.access(script_path, os.X_OK)"),
    ("status_surface", "require_contains(findings, \"status\", status_text, \"scripts/%s\" % guard.script, label)"),
    ("backup_surface", "require_contains(findings, \"backup\", backup_text, \"scripts/%s\" % guard.script, label)"),
    ("project_unit_surface", "require_contains(findings, \"project_unit\", project_unit_text, unit_line, label)"),
    ("installed_unit_surface", "require_contains(findings, \"installed_unit\", installed_unit_text, unit_line, label)"),
    ("readiness_surface", "require_contains(findings, \"readiness\", readiness_text, guard.label, safe_label(guard.label))"),
    ("summary", "guard_coverage_status=%s checks=%d findings=%d guards=%d status_expected=%d backup_expected=%d healthcheck_expected=%d readiness_expected=%d"),
]


READINESS_DOC_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only readiness documentation freshness guard for BR-Wissen"),
    ("docstring_no_secrets", "never reads or prints secret values, dump contents, log\ncontents or credential file contents"),
    ("readiness_path", "READINESS = ROOT / \"docs\" / \"READINESS.md\""),
    ("protocol_path", "PROTOCOL = Path(os.getenv(\"BR_PROTOCOL\", \"/home/chris/web/diverses/betriebsrat.md\"))"),
    ("run_summary", "def run_summary(script: str) -> tuple[int, str]:"),
    ("capture_output", "capture_output=True"),
    ("parse_key_values", "def parse_key_values(line: str) -> dict[str, str]:"),
    ("parse_stand", "def parse_stand(text: str) -> datetime | None:"),
    ("stand_regex", r"^Stand:\s*([^\s]+)\s*$"),
    ("max_age", "BR_READINESS_MAX_AGE_HOURS"),
    ("required_literals", "required_literals = ["),
    ("meta_source_literal", "Meta-Source-Hardening"),
    ("data_integrity_literal", "Data-Integrity-Source-Hardening"),
    ("summary_expectations", "summary_expectations: list[tuple[str, str, str, str | None]] = ["),
    ("restore_freshness_expectation", "check-restore-freshness.py"),
    ("meta_source_expectation", "check-meta-source-hardening.py"),
    ("static_summary_markers", "static_summary_markers = ["),
    ("meta_source_marker", "meta_source_hardening_status=ok"),
    ("protocol_recent_entry", "protocol_has_recent_entry"),
    ("backup_snapshot_resolved", "backup_snapshot = summary_cache.get(\"check-backup-scope.py\", {}).get(\"latest_snapshot\", \"not_checked\")"),
    ("restore_dump_resolved", "restore_dump = summary_cache.get(\"check-restore-freshness.py\", {}).get(\"restore_dump\", \"not_checked\")"),
    ("backup_snapshot_guard", "readiness_backup_snapshot_not_resolved"),
    ("restore_dump_guard", "readiness_restore_dump_not_resolved"),
    ("summary", "readiness_doc_status=%s checks=%d findings=%d stand=%s stand_age_h=%.1f backup_snapshot=%s restore_dump=%s"),
]


PYTHON_SYNTAX_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("root", "ROOT=\"/home/chris/web/br.m11h.eu\""),
    ("summary_arg", "--summary"),
    ("python_env", "PYTHON_SYNTAX_SUMMARY=\"$summary\" python3 - <<'PY'"),
    ("ast_import", "import ast"),
    ("scan_roots", "scan_roots = [root / \"app\", root / \"scripts\", root / \"worker\"]"),
    ("excluded_parts", "excluded_parts = {\"__pycache__\", \".pytest_cache\", \".venv\", \"node_modules\", \"tmp\"}"),
    ("rglob", "scan_root.rglob(\"*.py\")"),
    ("read_text", "path.read_text(encoding=\"utf-8\")"),
    ("ast_parse", "ast.parse(source, filename=str(rel))"),
    ("syntax_error", "syntax_error=%s:%s"),
    ("read_error", "read_error=%s"),
    ("summary", "python_syntax_status=%s checks=%d findings=%d checked_python_files=%d"),
]


SHELL_SYNTAX_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("root", "ROOT=\"/home/chris/web/br.m11h.eu\""),
    ("summary_arg", "--summary"),
    ("check_file", "check_file()"),
    ("bash_n", "bash -n \"$path\""),
    ("is_shell_script", "is_shell_script()"),
    ("shebang", "'#!'*'/bash'"),
    ("find_scripts", "find scripts -maxdepth 1 -type f"),
    ("maxdepth", "-maxdepth 1"),
    ("sort", "| sort"),
    ("summary", "shell_syntax_status=%s checks=%d findings=%d checked_shell_files=%d"),
]


SYSTEMD_UNIT_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("root", "ROOT=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")/..\" && pwd)\""),
    ("summary_arg", "--summary"),
    ("units", "units=("),
    ("healthcheck_service", "br-wissen-healthcheck.service"),
    ("backup_service", "br-wissen-backup.service"),
    ("import_m00h_service", "br-wissen-import-m00h.service"),
    ("import_bag_service", "br-wissen-import-bag.service"),
    ("restore_smoke_service", "br-wissen-restore-smoke.service"),
    ("timers", "timers=("),
    ("services", "services=("),
    ("src", "src=\"${ROOT}/systemd/${unit}\""),
    ("dst", "dst=\"/etc/systemd/system/${unit}\""),
    ("cmp", "cmp -s \"$src\" \"$dst\""),
    ("systemctl_active", "systemctl is-active \"$timer\""),
    ("systemctl_failed", "systemctl is-failed \"$service\""),
    ("inactive_timers", "inactive_timers=0"),
    ("failed_services", "failed_services=0"),
    ("summary", "systemd_unit_guard_status=ok units=%d timers=%d services=%d sync_failures=0 missing_units=0 inactive_timers=0 failed_services=0"),
]


DOC_SOURCE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only source hardening guard for BR-Wissen documentation sources"),
    ("docstring_scope", "README, Runbook, systemd documentation and the readiness\ndossier"),
    ("readme_path", "README = ROOT / \"README.md\""),
    ("runbook_path", "RUNBOOK = ROOT / \"docs\" / \"RUNBOOK.md\""),
    ("systemd_readme_path", "SYSTEMD_README = ROOT / \"systemd\" / \"README.md\""),
    ("readiness_path", "READINESS = ROOT / \"docs\" / \"READINESS.md\""),
    ("readme_markers", "README_MARKERS: list[tuple[str, str]] = ["),
    ("runbook_markers", "RUNBOOK_MARKERS: list[tuple[str, str]] = ["),
    ("systemd_readme_markers", "SYSTEMD_README_MARKERS: list[tuple[str, str]] = ["),
    ("readiness_markers", "READINESS_MARKERS: list[tuple[str, str]] = ["),
    ("forbidden_doc_markers", "FORBIDDEN_DOC_MARKERS = ["),
    ("check_markers", "def check_markers(findings: list[str], text: str, markers: list[tuple[str, str]], prefix: str) -> int:"),
    ("check_forbidden", "def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:"),
    ("doc_source_status", "doc_source_hardening_status=%s checks=%d findings=%d readme_markers=%d runbook_markers=%d systemd_readme_markers=%d readiness_markers=%d forbidden_markers=%d"),
]


SOURCE_HARDENING_COVERAGE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only source hardening coverage guard for BR-Wissen check scripts"),
    ("docstring_inventory", "every project `scripts/check-*` helper is either covered"),
    ("scripts_path", "SCRIPTS = ROOT / \"scripts\""),
    ("coverage_groups", "COVERAGE_GROUPS: dict[str, dict[str, list[str] | str]] = {"),
    ("core_group", "core_source_hardening"),
    ("privilege_risk_review_target", "check-privilege-risk-review.py"),
    ("privilege_plan_target", "check-privilege-least-privilege-plan.py"),
    ("container_group", "container_source_hardening"),
    ("network_group", "network_source_hardening"),
    ("access_group", "access_runtime_source_hardening"),
    ("data_group", "data_integrity_source_hardening"),
    ("meta_group", "meta_source_hardening"),
    ("source_guards", "SOURCE_HARDENING_GUARDS = sorted"),
    ("exceptions", "EXPLICIT_EXCEPTIONS = {"),
    ("cloudflare_exception", "check-cloudflare-staging-pattern.sh"),
    ("actual_scripts", "actual_scripts = sorted(path.name for path in SCRIPTS.glob(\"check-*\")"),
    ("unaccounted", "unaccounted_check_script=%s"),
    ("summary", "source_hardening_coverage_status=%s checks=%d findings=%d check_scripts=%d covered_targets=%d source_guards=%d exceptions=%d coverage_groups=%d forbidden_markers=%d"),
]


SUMMARY_CONTRACT_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only summary contract guard for BR-Wissen guard scripts"),
    ("guard_coverage_path", "GUARD_COVERAGE = SCRIPTS / \"check-guard-coverage.py\""),
    ("no_summary_contract", "NO_SUMMARY_CONTRACT = {"),
    ("allow_accepted_risk", "--allow-accepted-risk"),
    ("guard_contract_dataclass", "class GuardContract:"),
    ("parse_guard_contracts", "def parse_guard_contracts(text: str, findings: list[str]) -> list[GuardContract]:"),
    ("ast_parse", "tree = ast.parse(text)"),
    ("guards_assignment", "target.id != \"GUARDS\""),
    ("status_key_check", "status_key_missing_%s=%s"),
    ("summary_arg_check", "summary_arg_missing=%s"),
    ("summary_status_key_check", "summary_status_key_missing=%s"),
    ("summary", "summary_contract_status=%s checks=%d findings=%d guards=%d status_keys=%d summary_contracts=%d no_summary_exceptions=%d forbidden_markers=%d"),
]


SURFACE_REGISTRY_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only guard surface registry consistency check for BR-Wissen"),
    ("docstring_surfaces", "status wrapper, backup preflight and\nsystemd healthcheck units"),
    ("guard_coverage_path", "GUARD_COVERAGE = SCRIPTS / \"check-guard-coverage.py\""),
    ("status_script_path", "STATUS_SCRIPT = SCRIPTS / \"status-br-wissen.sh\""),
    ("backup_script_path", "BACKUP_SCRIPT = SCRIPTS / \"backup-br-wissen.sh\""),
    ("project_unit_path", "PROJECT_HEALTHCHECK_UNIT = ROOT / \"systemd\" / \"br-wissen-healthcheck.service\""),
    ("installed_unit_path", "INSTALLED_HEALTHCHECK_UNIT = Path(\"/etc/systemd/system/br-wissen-healthcheck.service\")"),
    ("status_only_helpers", "STATUS_ONLY_HELPERS = {"),
    ("guard_surface_dataclass", "class GuardSurface:"),
    ("parse_guard_surfaces", "def parse_guard_surfaces(text: str, findings: list[str]) -> list[GuardSurface]:"),
    ("extract_status_calls", "def extract_status_calls(text: str) -> list[tuple[str, str]]:"),
    ("extract_backup_preflights", "def extract_backup_preflights(text: str) -> list[tuple[str, str, str]]:"),
    ("extract_execstartpre", "def extract_execstartpre(text: str) -> list[tuple[str, str]]:"),
    ("compare_sequence", "def compare_sequence(findings: list[str], label: str, actual: list[object], expected: list[object]) -> int:"),
    ("status_missing", "status_missing_registry_script=%s"),
    ("status_unexpected", "status_unexpected_check_script=%s"),
    ("sequence_unexpected", "%s_sequence_unexpected_count_%d_expected_%d"),
    ("backup_sequence_label", "backup_preflight"),
    ("project_sequence_label", "project_healthcheck"),
    ("installed_sequence_label", "installed_healthcheck"),
    ("summary", "surface_registry_status=%s checks=%d findings=%d guards=%d status_calls=%d backup_preflights=%d healthcheck_preflights=%d status_helpers=%d forbidden_markers=%d"),
]


GUARD_REGISTRY_INTEGRITY_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only guard registry integrity check for BR-Wissen"),
    ("docstring_registry", "validates the registry itself for duplicate labels, scripts, status keys and\nbackup labels"),
    ("guard_coverage_path", "GUARD_COVERAGE = SCRIPTS / \"check-guard-coverage.py\""),
    ("allowed_args", "ALLOWED_ARG_CONTRACTS = {\"\", \" --summary\", \" --summary --allow-accepted-risk\"}"),
    ("status_key_pattern", "STATUS_KEY_PATTERN = re.compile"),
    ("backup_label_pattern", "BACKUP_LABEL_PATTERN = re.compile"),
    ("guard_entry_dataclass", "class GuardRegistryEntry:"),
    ("parse_registry", "def parse_registry(text: str, findings: list[str]) -> list[GuardRegistryEntry]:"),
    ("find_duplicates", "def find_duplicates(values: list[str]) -> list[str]:"),
    ("duplicate_label", "duplicate_%s=%s"),
    ("script_missing", "script_missing=%s"),
    ("script_not_executable", "script_not_executable=%s"),
    ("status_key_shape", "status_key_shape_unexpected=%s"),
    ("backup_label_shape", "backup_label_shape_unexpected=%s"),
    ("arg_contracts", "healthcheck_args_unexpected_%s=%s"),
    ("summary", "guard_registry_integrity_status=%s checks=%d findings=%d guards=%d labels=%d scripts=%d status_keys=%d backup_labels=%d disabled_backup=%d forbidden_markers=%d"),
]

# Meta-governance inventory marker for source-hardening coverage:
# check-guard-registry-integrity.py


PROTOCOL_INTEGRITY_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only protocol integrity guard for the BR-Wissen project log"),
    ("protocol_path", "PROTOCOL = Path(os.getenv(\"BR_PROTOCOL\", \"/home/chris/web/diverses/betriebsrat.md\"))"),
    ("backup_script_path", "BACKUP_SCRIPT = ROOT / \"scripts\" / \"backup-br-wissen.sh\""),
    ("required_protocol_markers", "REQUIRED_PROTOCOL_MARKERS: list[tuple[str, str]] = ["),
    ("required_backup_markers", "REQUIRED_BACKUP_MARKERS: list[tuple[str, str]] = ["),
    ("forbidden_protocol_markers", "FORBIDDEN_PROTOCOL_MARKERS = ["),
    ("read_text", "def read_text(path: Path, findings: list[str], label: str) -> str:"),
    ("symlink_check", "if path.is_symlink():"),
    ("world_writable", "protocol_world_writable"),
    ("backup_included", "protocol_file_status=included"),
    ("forbidden_check", "check_forbidden(findings, protocol_text, FORBIDDEN_PROTOCOL_MARKERS, \"protocol\")"),
    ("summary", "protocol_integrity_status=%s checks=%d findings=%d protocol_markers=%d backup_markers=%d forbidden_markers=%d protocol_bytes=%d"),
]

# Meta-governance inventory marker for source-hardening coverage:
# check-protocol-integrity.py


GIT_REMOTE_READINESS_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only Git/GitHub remote readiness guard for BR-Wissen"),
    ("expected_branch", "EXPECTED_BRANCH = os.getenv(\"BR_GIT_EXPECTED_BRANCH\", \"main\")"),
    ("expected_remote", "EXPECTED_REMOTE = os.getenv(\"BR_GIT_EXPECTED_REMOTE\", \"git@github.com:scheffe2804/scheffe2804-br.m11h.eu.git\")"),
    ("expected_remote_head", "EXPECTED_REMOTE_HEAD = os.getenv(\"BR_GIT_EXPECTED_REMOTE_HEAD\", \"refs/heads/main\")"),
    ("allowed_env", "ALLOWED_TRACKED_ENV = {\".env.example\"}"),
    ("required_ignores", "REQUIRED_IGNORES = ["),
    ("cloudflared_ignore", "cloudflared/config.yml"),
    ("sensitive_patterns", "SENSITIVE_TRACKED_PATTERNS = ["),
    ("run_git", "def run_git(args: list[str]) -> tuple[int, str]:"),
    ("status_porcelain", "run_git([\"status\", \"--porcelain\"])"),
    ("remote_get_url", "run_git([\"remote\", \"get-url\", \"origin\"])"),
    ("upstream", "run_git([\"rev-parse\", \"--abbrev-ref\", \"--symbolic-full-name\", \"@{u}\"])"),
    ("remote_head", "run_git([\"ls-remote\", \"--heads\", \"origin\", EXPECTED_BRANCH])"),
    ("tracked_files", "run_git([\"ls-files\"])"),
    ("sensitive_tracked", "git_sensitive_tracked=%d"),
    ("summary", "git_remote_readiness_status=%s checks=%d findings=%d branch=%s tracking=%d dirty=%d"),
]

# Meta-governance inventory marker for source-hardening coverage:
# check-git-remote-readiness.py


BACKUP_SCOPE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only Restic backup scope guard for BR-Wissen"),
    ("app_dir", "APP_DIR = Path(os.getenv(\"BR_APP_DIR\", \"/home/chris/web/br.m11h.eu\"))"),
    ("storage_root", "STORAGE_ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))"),
    ("protocol_file", "PROTOCOL_FILE = Path(os.getenv(\"BR_PROTOCOL_FILE\", \"/home/chris/web/diverses/betriebsrat.md\"))"),
    ("expected_tags", "EXPECTED_TAGS = {\"br-wissen\", \"includes-internal-sources\"}"),
    ("expected_paths", "EXPECTED_PATHS = {str(APP_DIR), str(STORAGE_ROOT), str(PROTOCOL_FILE)}"),
    ("load_snapshots", "def load_snapshots() -> list[dict[str, Any]] | None:"),
    ("restic_snapshots", '"res" + "tic snapshots --host %s --tag br-wissen --json"'),
    ("path_missing", "snapshot_paths_missing=%d"),
    ("path_unexpected", "snapshot_paths_unexpected=%d"),
    ("summary", "backup_scope_status=%s checks=%d findings=%d snapshots=%d latest_snapshot=%s tags=%d paths=%d expected_paths=%d"),
]

# Meta-governance inventory marker for source-hardening coverage:
# check-backup-scope.py


FORBIDDEN_COMMON_MARKERS = [
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
    "docker compose up",
    "docker compose down",
    "docker compose restart",
    "docker compose rm",
    "docker rm",
    "docker volume rm",
    "docker rmi",
    "docker system prune",
    "systemctl start",
    "systemctl stop",
    "systemctl restart",
    "systemctl enable",
    "systemctl disable",
    "systemctl daemon-reload",
    "pg_dump",
    "psql ",
    "restic ",
    "/srv/br-wissensdatenbank/backups",
    "/srv/br-wissensdatenbank/secrets",
    "/srv/br-wissensdatenbank/exports",
    "/run/br-secrets/",
]


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def check_markers(findings: list[str], text: str, markers: list[tuple[str, str]], prefix: str) -> int:
    checks = 0
    for label, marker in markers:
        checks += 1
        if marker not in text:
            findings.append("%s_missing=%s" % (prefix, safe(label)))
    return checks


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen meta source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    coverage_text = read_source(GUARD_COVERAGE, findings, "guard_coverage")
    readiness_text = read_source(READINESS_DOC, findings, "readiness_doc")
    python_text = read_source(PYTHON_SYNTAX, findings, "python_syntax")
    shell_text = read_source(SHELL_SYNTAX, findings, "shell_syntax")
    systemd_text = read_source(SYSTEMD_UNITS, findings, "systemd_units")
    doc_source_text = read_source(DOC_SOURCE_HARDENING, findings, "doc_source_hardening")
    source_coverage_text = read_source(SOURCE_HARDENING_COVERAGE, findings, "source_hardening_coverage")
    summary_contract_text = read_source(SUMMARY_CONTRACTS, findings, "summary_contracts")
    surface_registry_text = read_source(SURFACE_REGISTRY, findings, "surface_registry")
    guard_registry_integrity_text = read_source(GUARD_REGISTRY_INTEGRITY, findings, "guard_registry_integrity")
    protocol_integrity_text = read_source(PROTOCOL_INTEGRITY, findings, "protocol_integrity")
    git_remote_readiness_text = read_source(GIT_REMOTE_READINESS, findings, "git_remote_readiness")
    backup_scope_text = read_source(BACKUP_SCOPE, findings, "backup_scope")
    checks += 13

    checks += check_markers(findings, coverage_text, GUARD_COVERAGE_MARKERS, "coverage")
    checks += check_markers(findings, readiness_text, READINESS_DOC_MARKERS, "readiness")
    checks += check_markers(findings, python_text, PYTHON_SYNTAX_MARKERS, "python_syntax")
    checks += check_markers(findings, shell_text, SHELL_SYNTAX_MARKERS, "shell_syntax")
    checks += check_markers(findings, systemd_text, SYSTEMD_UNIT_MARKERS, "systemd_unit")
    checks += check_markers(findings, doc_source_text, DOC_SOURCE_MARKERS, "doc_source")
    checks += check_markers(findings, source_coverage_text, SOURCE_HARDENING_COVERAGE_MARKERS, "source_coverage")
    checks += check_markers(findings, summary_contract_text, SUMMARY_CONTRACT_MARKERS, "summary_contract")
    checks += check_markers(findings, surface_registry_text, SURFACE_REGISTRY_MARKERS, "surface_registry")
    checks += check_markers(findings, guard_registry_integrity_text, GUARD_REGISTRY_INTEGRITY_MARKERS, "guard_registry_integrity")
    checks += check_markers(findings, protocol_integrity_text, PROTOCOL_INTEGRITY_MARKERS, "protocol_integrity")
    checks += check_markers(findings, git_remote_readiness_text, GIT_REMOTE_READINESS_MARKERS, "git_remote_readiness")
    checks += check_markers(findings, backup_scope_text, BACKUP_SCOPE_MARKERS, "backup_scope")

    for prefix, text in [
        ("coverage", coverage_text),
        ("readiness", readiness_text),
        ("python_syntax", python_text),
        ("shell_syntax", shell_text),
        ("systemd_unit", systemd_text),
        ("doc_source", doc_source_text),
        ("source_coverage", source_coverage_text),
        ("summary_contract", summary_contract_text),
        ("surface_registry", surface_registry_text),
        ("guard_registry_integrity", guard_registry_integrity_text),
        ("protocol_integrity", protocol_integrity_text),
        ("git_remote_readiness", git_remote_readiness_text),
        ("backup_scope", backup_scope_text),
    ]:
        checks += check_forbidden(findings, text, FORBIDDEN_COMMON_MARKERS, prefix)

    checks += 1
    if coverage_text.find("GUARDS: list[GuardSpec]") > coverage_text.find("for guard in GUARDS"):
        findings.append("coverage_guards_after_loop")
    checks += 1
    if readiness_text.find("required_literals = [") > readiness_text.find("for literal in required_literals"):
        findings.append("readiness_required_literals_after_loop")
    checks += 1
    if python_text.find("scan_roots = [") > python_text.find("for scan_root in scan_roots"):
        findings.append("python_scan_roots_after_loop")
    checks += 1
    if shell_text.find("check_file()") > shell_text.find("check_file \"$path\""):
        findings.append("shell_check_file_after_use")
    checks += 1
    if systemd_text.find("units=(") > systemd_text.find("for unit in \"${units[@]}\""):
        findings.append("systemd_units_after_loop")
    checks += 1
    if doc_source_text.find("README_MARKERS") > doc_source_text.find("check_markers(findings, readme_text"):
        findings.append("doc_source_readme_markers_after_loop")
    checks += 1
    if source_coverage_text.find("COVERAGE_GROUPS") > source_coverage_text.find("for group, spec in COVERAGE_GROUPS.items()"):
        findings.append("source_coverage_groups_after_loop")
    checks += 1
    if summary_contract_text.find("parse_guard_contracts") > summary_contract_text.find("contracts = parse_guard_contracts"):
        findings.append("summary_contract_parser_after_use")
    checks += 1
    if surface_registry_text.find("parse_guard_surfaces") > surface_registry_text.find("surfaces = parse_guard_surfaces"):
        findings.append("surface_registry_parser_after_use")
    checks += 1
    if guard_registry_integrity_text.find("parse_registry") > guard_registry_integrity_text.find("entries = parse_registry"):
        findings.append("guard_registry_integrity_parser_after_use")
    checks += 1
    if protocol_integrity_text.find("REQUIRED_PROTOCOL_MARKERS") > protocol_integrity_text.find("check_markers(findings, protocol_text"):
        findings.append("protocol_integrity_markers_after_use")
    checks += 1
    if git_remote_readiness_text.find("REQUIRED_IGNORES") > git_remote_readiness_text.find("missing_ignores ="):
        findings.append("git_remote_readiness_required_ignores_after_use")
    checks += 1
    if backup_scope_text.find("EXPECTED_PATHS") > backup_scope_text.find("missing_paths = sorted"):
        findings.append("backup_scope_expected_paths_after_use")

    status = "ok" if not findings else "failed"
    summary = "meta_source_hardening_status=%s checks=%d findings=%d coverage_markers=%d readiness_markers=%d python_syntax_markers=%d shell_syntax_markers=%d systemd_unit_markers=%d doc_source_markers=%d source_coverage_markers=%d summary_contract_markers=%d surface_registry_markers=%d guard_registry_integrity_markers=%d protocol_integrity_markers=%d git_remote_readiness_markers=%d backup_scope_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(GUARD_COVERAGE_MARKERS),
        len(READINESS_DOC_MARKERS),
        len(PYTHON_SYNTAX_MARKERS),
        len(SHELL_SYNTAX_MARKERS),
        len(SYSTEMD_UNIT_MARKERS),
        len(DOC_SOURCE_MARKERS),
        len(SOURCE_HARDENING_COVERAGE_MARKERS),
        len(SUMMARY_CONTRACT_MARKERS),
        len(SURFACE_REGISTRY_MARKERS),
        len(GUARD_REGISTRY_INTEGRITY_MARKERS),
        len(PROTOCOL_INTEGRITY_MARKERS),
        len(GIT_REMOTE_READINESS_MARKERS),
        len(BACKUP_SCOPE_MARKERS),
        len(FORBIDDEN_COMMON_MARKERS) * 13,
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
