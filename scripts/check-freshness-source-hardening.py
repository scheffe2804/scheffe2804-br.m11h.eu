#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen freshness guards.

The guard validates backup- and restore-freshness guard sources for expected
metadata-only collection, sudo JSON helper modes, retention, age, permission,
Restic, dump, restore-smoke and summary markers. It only reads project source
files; it does not run freshness checks, sudo, Restic, Docker, backups, restores,
imports or database queries and never reads secrets, dumps, logs, answers or
source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
BACKUP_FRESHNESS = ROOT / "scripts" / "check-backup-freshness.py"
BACKUP_SCOPE = ROOT / "scripts" / "check-backup-scope.py"
BACKUP_RUNTIME_POLICY = ROOT / "scripts" / "check-backup-runtime-policy.py"
RESTIC_REPOSITORY_CHECK = ROOT / "scripts" / "check-restic-repository-check.py"
RESTORE_RUNTIME_POLICY = ROOT / "scripts" / "check-restore-runtime-policy.py"
RESTORE_FRESHNESS = ROOT / "scripts" / "check-restore-freshness.py"


BACKUP_MARKERS: list[tuple[str, str]] = [
    ("docstring_no_secrets", "It never prints\nbackup secret values, dump contents, log bodies or credential file contents."),
    ("storage_root", "ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))"),
    ("backup_env", "BACKUP_ENV = Path(os.getenv(\"BR_BACKUP_ENV\", \"/etc/web-backup/repos.d/m11h-br-wissen.env\"))"),
    ("protocol_file", "PROTOCOL_FILE = Path(os.getenv(\"BR_PROTOCOL_FILE\", \"/home/chris/web/diverses/betriebsrat.md\"))"),
    ("log_dir", "LOG_DIR = ROOT / \"logs\""),
    ("backup_dir", "BACKUP_DIR = ROOT / \"backups\""),
    ("local_dump_keep", "BR_LOCAL_DUMP_KEEP"),
    ("backup_log_keep", "BR_BACKUP_LOG_KEEP"),
    ("min_dump_bytes", "BR_MIN_DUMP_BYTES"),
    ("protocol_snapshot_skew", "BR_PROTOCOL_SNAPSHOT_SKEW_SECONDS"),
    ("collect_local_info", "def collect_local_info()"),
    ("backup_logs", "backup-*.log"),
    ("postgres_dumps", "postgres-*.sql"),
    ("snapshot_regex", r"^snapshot\s+([0-9a-f]+)\s+saved$"),
    ("creating_dump_regex", r"^creating_db_dump=(.+)$"),
    ("required_preflights", "required_preflights = ["),
    ("host_context_marker", "host_context_status=ok"),
    ("core_source_marker", "core_source_hardening_status=ok"),
    ("container_source_marker", "container_source_hardening_status=ok"),
    ("network_source_marker", "network_source_hardening_status=ok"),
    ("status_source_marker", "status_source_hardening_status=ok"),
    ("healthcheck_source_marker", "healthcheck_source_hardening_status=ok"),
    ("access_runtime_source_marker", "access_runtime_source_hardening_status=ok"),
    ("data_integrity_source_marker", "data_integrity_source_hardening_status=ok"),
    ("meta_source_marker", "meta_source_hardening_status=ok"),
    ("doc_source_marker", "doc_source_hardening_status=ok"),
    ("source_hardening_coverage_marker", "source_hardening_coverage_status=ok"),
    ("summary_contract_marker", "summary_contract_status=ok"),
    ("surface_registry_marker", "surface_registry_status=ok"),
    ("guard_registry_integrity_marker", "guard_registry_integrity_status=ok"),
    ("protocol_integrity_marker", "protocol_integrity_status=ok"),
    ("git_remote_readiness_marker", "git_remote_readiness_status=ok"),
    ("regression_source_marker", "regression_source_hardening_status=ok"),
    ("protocol_marker", "protocol_file_status=included"),
    ("script", "SCRIPT = Path(__file__).resolve()"),
    ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
    ("test_path", "TEST = Path(\"/usr/bin/test\")"),
    ("bash_path", "BASH = Path(\"/usr/bin/bash\")"),
    ("allowed_python_paths", "ALLOWED_PYTHON_PATHS = ("),
    ("python_path_313", "Path(\"/usr/bin/python3.13\")"),
    ("allowed_restic_paths", "ALLOWED_RESTIC_PATHS = (Path(\"/usr/bin/restic\"), Path(\"/usr/local/bin/restic\"))"),
    ("stat_info", "def stat_info(path: Path) -> dict[str, Any]:"),
    ("helper_binary_policy", "def check_helper_binary_policy(findings: list[str], label: str, path: Path, require_setuid: bool = False) -> int:"),
    ("helper_binary_is_usable", "def helper_binary_is_usable(path: Path) -> bool:"),
    ("python_binary", "def python_binary() -> Path | None:"),
    ("restic_binary", "def restic_binary() -> Path | None:"),
    ("sudo_local_info", "def sudo_local_info(python_path: Path | None)"),
    ("absolute_sudo_scan", "run([str(SUDO), \"-n\", str(python_path), str(SCRIPT), \"--scan-json\"])"),
    ("scan_json", "--scan-json"),
    ("backup_env_json", "--backup-env-json"),
    ("backup_env_info", "def collect_backup_env_info()"),
    ("sudo_backup_env_info", "def sudo_backup_env_info(python_path: Path | None)"),
    ("backup_env_mode", "stat.S_IMODE(st.st_mode)"),
    ("backup_env_owner", "backup_env_bad_owner"),
    ("backup_env_mode_check", "backup_env_bad_mode=%03o"),
    ("restic_latest", "def restic_latest(restic_path: Path | None)"),
    ("restic_snapshots", "%s snapshots --host m11h --tag br-wissen --json"),
    ("restic_paths", "\"paths\": [str(path) for path in (latest.get(\"paths\") or []) if isinstance(path, str)]"),
    ("restic_locks", "def restic_lock_info(restic_path: Path | None)"),
    ("restic_list_locks", "LC_ALL=C %s list locks"),
    ("absolute_sudo_test", "run([str(SUDO), \"-n\", str(TEST), \"-f\", str(BACKUP_ENV)])"),
    ("absolute_sudo_bash", "run([str(SUDO), \"-n\", str(BASH), \"-lc\", command])"),
    ("helper_python_unavailable", "helper_python_unavailable"),
    ("helper_restic_unavailable", "helper_restic_unavailable"),
    ("helper_binaries_summary", "helper_binaries=%d"),
    ("python_binary_summary", "python_binary=%s"),
    ("restic_binary_summary", "restic_binary=%s"),
    ("max_age_env", "BR_BACKUP_MAX_AGE_HOURS"),
    ("geteuid_root_gate", "if os.geteuid() != 0:"),
    ("retention_log", "backup_log_retention_exceeded"),
    ("retention_dump", "dump_retention_exceeded"),
    ("log_too_old", "latest_log_too_old_h"),
    ("dump_too_old", "latest_dump_too_old_h"),
    ("backup_done", "latest_log_missing_backup_done"),
    ("snapshot_missing", "latest_log_missing_snapshot"),
    ("dump_too_small", "latest_dump_too_small"),
    ("preflight_incomplete", "latest_log_preflight_markers_incomplete"),
    ("dump_reference", "latest_dump_not_referenced_by_latest_log"),
    ("restic_mismatch", "latest_log_snapshot_mismatch"),
    ("protocol_path_missing", "restic_protocol_path_missing"),
    ("protocol_newer_than_snapshot", "protocol_newer_than_restic_snapshot_h"),
    ("protocol_snapshot_current", "protocol_snapshot_current"),
    ("stale_locks", "restic_stale_locks_present"),
    ("summary", "backup_freshness_status=%s checks=%d findings=%d latest_snapshot=%s restic_latest=%s restic_locks=%d restic_stale_locks=%d backup_env_mode=%03o helper_binaries=%d python_binary=%s restic_binary=%s latest_log_age_h=%.1f latest_dump_age_h=%.1f restic_age_h=%.1f log_count=%d dump_count=%d protocol_snapshot_current=%d"),
]


BACKUP_SCOPE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only Restic backup scope guard for BR-Wissen"),
    ("app_dir", "APP_DIR = Path(os.getenv(\"BR_APP_DIR\", \"/home/chris/web/br.m11h.eu\"))"),
    ("storage_root", "STORAGE_ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))"),
    ("protocol_file", "PROTOCOL_FILE = Path(os.getenv(\"BR_PROTOCOL_FILE\", \"/home/chris/web/diverses/betriebsrat.md\"))"),
    ("backup_env", "BACKUP_ENV = Path(os.getenv(\"BR_BACKUP_ENV\", \"/etc/web-backup/repos.d/m11h-br-wissen.env\"))"),
    ("expected_tags", "EXPECTED_TAGS = {\"br-wissen\", \"includes-internal-sources\"}"),
    ("expected_paths", "EXPECTED_PATHS = {str(APP_DIR), str(STORAGE_ROOT), str(PROTOCOL_FILE)}"),
    ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
    ("test_path", "TEST = Path(\"/usr/bin/test\")"),
    ("bash_path", "BASH = Path(\"/usr/bin/bash\")"),
    ("allowed_restic_paths", "ALLOWED_RESTIC_PATHS = (Path(\"/usr/bin/restic\"), Path(\"/usr/local/bin/restic\"))"),
    ("stat_info", "def stat_info(path: Path) -> dict[str, Any]:"),
    ("helper_binary_policy", "def check_helper_binary_policy(findings: list[str], label: str, path: Path, require_setuid: bool = False) -> int:"),
    ("helper_binary_is_usable", "def helper_binary_is_usable(path: Path) -> bool:"),
    ("restic_binary", "def restic_binary() -> Path | None:"),
    ("load_snapshots", "def load_snapshots(restic_path: Path | None) -> list[dict[str, Any]] | None:"),
    ("absolute_sudo_test", "run([str(SUDO), \"-n\", str(TEST), \"-f\", str(BACKUP_ENV)])"),
    ("absolute_sudo_bash", "run([str(SUDO), \"-n\", str(BASH), \"-lc\", command])"),
    ("restic_snapshots", "%s snapshots --host %s --tag br-wissen --json"),
    ("helper_restic_unavailable", "helper_restic_unavailable"),
    ("helper_binaries_summary", "helper_binaries=%d"),
    ("restic_binary_summary", "restic_binary=%s"),
    ("missing_paths", "snapshot_paths_missing=%d"),
    ("unexpected_paths", "snapshot_paths_unexpected=%d"),
    ("summary", "backup_scope_status=%s checks=%d findings=%d snapshots=%d latest_snapshot=%s tags=%d paths=%d expected_paths=%d helper_binaries=%d restic_binary=%s"),
]


BACKUP_RUNTIME_POLICY_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only backup runtime policy guard for BR-Wissen"),
    ("backup_env", "BACKUP_ENV = Path(os.getenv(\"BR_BACKUP_ENV\", \"/etc/web-backup/repos.d/m11h-br-wissen.env\"))"),
    ("backup_service", "BACKUP_SERVICE = Path(os.getenv(\"BR_BACKUP_SERVICE\", \"/etc/systemd/system/br-wissen-backup.service\"))"),
    ("allowed_restic_paths", "ALLOWED_RESTIC_PATHS = {\"/usr/bin/restic\", \"/usr/local/bin/restic\"}"),
    ("stat_info", "def stat_info(path: Path) -> dict[str, Any]:"),
    ("collect_root_info", "def collect_root_info() -> dict[str, Any]:"),
    ("root_json", "--root-json"),
    ("sudo_root_info", "def sudo_root_info() -> dict[str, Any] | None:"),
    ("geteuid_root_gate", "if os.geteuid() != 0:"),
    ("backup_env_mode", "backup_env_mode=%03o"),
    ("parent_mode", "backup_env_parent_mode=%03o"),
    ("restic_mode", "restic_mode=%03o"),
    ("restic_path_allowed", "restic_path_not_allowed"),
    ("service_user_root", "service_user_root=%d"),
    ("summary", "backup_runtime_policy_status=%s checks=%d findings=%d backup_env_mode=%03o backup_env_parent_mode=%03o restic_mode=%03o service_mode=%03o service_user_root=%d"),
]


RESTIC_REPOSITORY_CHECK_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only Restic repository check freshness guard for BR-Wissen"),
    ("docstring_no_lock", "does not run `restic check`, does\nnot take a repository lock"),
    ("readiness_path", "READINESS = ROOT / \"docs\" / \"READINESS.md\""),
    ("max_age_env", "BR_RESTIC_CHECK_MAX_AGE_HOURS"),
    ("parse_timestamp", "def parse_timestamp(text: str) -> datetime | None:"),
    ("age_hours", "def age_hours(stamp: datetime | None) -> float:"),
    ("required_markers", "required_markers = ["),
    ("restic_check_marker", "restic check"),
    ("success_marker", "no errors were found"),
    ("lock_marker", "exklusiven Repository-Lock"),
    ("snapshot_regex", r"([0-9]+) Snapshots geprueft"),
    ("lock_preflight", "lock_preflight = 0"),
    ("too_old", "restic_check_too_old_h=%.1f"),
    ("summary", "restic_repository_check_status=%s checks=%d findings=%d last_check=%s age_h=%.1f snapshots=%d documented_success=%d max_age_h=%.1f lock_preflight=%d"),
]


RESTORE_RUNTIME_POLICY_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only restore runtime policy guard for BR-Wissen"),
    ("root", "ROOT = Path(os.getenv(\"BR_APP_DIR\", \"/home/chris/web/br.m11h.eu\"))"),
    ("backup_env", "BACKUP_ENV = Path(os.getenv(\"BR_BACKUP_ENV\", \"/etc/web-backup/repos.d/m11h-br-wissen.env\"))"),
    ("restore_wrapper", "RESTORE_WRAPPER = ROOT / \"scripts\" / \"run-restore-smoke-drill.sh\""),
    ("restore_script", "RESTORE_SCRIPT = ROOT / \"scripts\" / \"restore-smoke-br-wissen.sh\""),
    ("restore_service", "RESTORE_SERVICE = Path(os.getenv(\"BR_RESTORE_SERVICE\", \"/etc/systemd/system/br-wissen-restore-smoke.service\"))"),
    ("restore_timer", "RESTORE_TIMER = Path(os.getenv(\"BR_RESTORE_TIMER\", \"/etc/systemd/system/br-wissen-restore-smoke.timer\"))"),
    ("allowed_restic_paths", "ALLOWED_RESTIC_PATHS = {\"/usr/bin/restic\", \"/usr/local/bin/restic\"}"),
    ("allowed_docker_paths", "ALLOWED_DOCKER_PATHS = {\"/usr/bin/docker\", \"/usr/local/bin/docker\"}"),
    ("stat_info", "def stat_info(path: Path) -> dict[str, Any]:"),
    ("collect_root_info", "def collect_root_info() -> dict[str, Any]:"),
    ("root_json", "--root-json"),
    ("sudo_root_info", "def sudo_root_info() -> dict[str, Any] | None:"),
    ("tmp_mode", "tmp_mode=%04o"),
    ("service_user_root", "service_user_root=%d"),
    ("timer_persistent", "timer_persistent=%d"),
    ("summary", "restore_runtime_policy_status=%s checks=%d findings=%d backup_env_mode=%03o tmp_mode=%04o restic_mode=%03o docker_mode=%03o service_mode=%03o timer_mode=%03o service_user_root=%d timer_persistent=%d"),
]


RESTORE_MARKERS: list[tuple[str, str]] = [
    ("docstring_no_secrets", "It never prints\nrestore log bodies, dump contents, secret values or credential file contents."),
    ("storage_root", "ROOT = Path(os.getenv(\"BR_STORAGE_ROOT\", \"/srv/br-wissensdatenbank\"))"),
    ("app_dir", "APP_DIR = Path(os.getenv(\"BR_APP_DIR\", \"/home/chris/web/br.m11h.eu\"))"),
    ("backup_env", "BACKUP_ENV = Path(os.getenv(\"BR_BACKUP_ENV\", \"/etc/web-backup/repos.d/m11h-br-wissen.env\"))"),
    ("protocol_file", "PROTOCOL_FILE = Path(os.getenv(\"BR_PROTOCOL_FILE\", \"/home/chris/web/diverses/betriebsrat.md\"))"),
    ("log_dir", "LOG_DIR = ROOT / \"logs\""),
    ("restore_log_keep", "BR_RESTORE_LOG_KEEP"),
    ("min_dump_bytes", "BR_MIN_DUMP_BYTES"),
    ("expected_tags", "EXPECTED_TAGS = {\"br-wissen\", \"includes-internal-sources\"}"),
    ("expected_paths", "EXPECTED_PATHS = {str(APP_DIR), str(ROOT), str(PROTOCOL_FILE)}"),
    ("script", "SCRIPT = Path(__file__).resolve()"),
    ("self_parent_dirs", "SELF_PARENT_DIRS = (APP_DIR, SCRIPT.parent)"),
    ("self_script_min_bytes", "SELF_SCRIPT_MIN_BYTES = 10_000"),
    ("sudo_path", "SUDO = Path(\"/usr/bin/sudo\")"),
    ("test_path", "TEST = Path(\"/usr/bin/test\")"),
    ("bash_path", "BASH = Path(\"/usr/bin/bash\")"),
    ("allowed_python_paths", "ALLOWED_PYTHON_PATHS = ("),
    ("python_path_313", "Path(\"/usr/bin/python3.13\")"),
    ("allowed_restic_paths", "ALLOWED_RESTIC_PATHS = (Path(\"/usr/bin/restic\"), Path(\"/usr/local/bin/restic\"))"),
    ("stat_info", "def stat_info(path: Path) -> dict[str, Any]:"),
    ("stat_info_is_dir", '"is_dir": False'),
    ("int_value", "def int_value(info: dict[str, Any], key: str, default: int = -1) -> int:"),
    ("helper_binary_policy", "def check_helper_binary_policy(findings: list[str], label: str, path: Path, require_setuid: bool = False) -> int:"),
    ("helper_missing", "helper_%s_missing"),
    ("helper_not_root_owned", "helper_%s_not_root_owned"),
    ("helper_group_or_other_writable", "helper_%s_group_or_other_writable"),
    ("helper_special_bits", "helper_%s_special_bits_unexpected"),
    ("helper_restic_unavailable", "helper_restic_unavailable"),
    ("self_script_policy", "def check_self_script_policy(findings: list[str]) -> int:"),
    ("self_script_group_or_other_writable", "self_script_group_or_other_writable"),
    ("self_script_not_executable", "self_script_not_executable"),
    ("self_script_too_small", "self_script_too_small"),
    ("self_parent_policy", "def check_self_parent_directory_policy(findings: list[str]) -> int:"),
    ("self_parent_not_directory", "self_parent_%s_not_directory"),
    ("self_parent_owner_mismatch", "self_parent_%s_owner_mismatch"),
    ("self_parent_group_or_other_writable", "self_parent_%s_group_or_other_writable"),
    ("self_parent_not_searchable", "self_parent_%s_not_searchable"),
    ("collect_restore_info", "def collect_restore_info()"),
    ("restore_logs", "restore-smoke-*.log"),
    ("restore_drill_done", "restore_drill_status=ok"),
    ("restore_status_ok", "restore_status=ok"),
    ("db_restore_status_ok", "db_restore_status=ok"),
    ("storage_capacity_ok", "storage_capacity_status=ok"),
    ("snapshot_regex", r"^snapshot=(.+)$"),
    ("resolved_snapshot_regex", r"^restore_resolved_snapshot=([0-9a-f]+)$"),
    ("sql_ready_wait_regex", r"^restore_sql_ready_wait=([0-9]+)$"),
    ("latest_dump_regex", r"^restore_latest_dump=(.+)$"),
    ("dump_size_regex", r"^restore_latest_dump_size=([0-9]+)$"),
    ("required_missing", "restore_required_missing"),
    ("artifact_findings", "restore_artifact_findings"),
    ("protocol_exists", "restore_protocol_exists=yes"),
    ("protocol_markers", "restore_protocol_markers=yes"),
    ("manifest_json", "restore_manifest_json"),
    ("answers_without_statements", "restore_answers_without_statements"),
    ("statements_without_citation", "restore_statements_without_citation"),
    ("vector_extension", "restore_vector_extension"),
    ("operational_indexes", "restore_operational_indexes"),
    ("network_isolated", "restore_network_mode=none"),
    ("ports_empty", "restore_ports={}"),
    ("dump_marker_count", "dump_marker_.+=yes"),
    ("helper_binary_is_usable", "def helper_binary_is_usable(path: Path) -> bool:"),
    ("python_binary", "def python_binary() -> Path | None:"),
    ("helper_python_unavailable", "helper_python_unavailable"),
    ("sudo_restore_info", "def sudo_restore_info(python_path: Path | None)"),
    ("absolute_sudo_scan", "run([str(SUDO), \"-n\", str(python_path), str(SCRIPT), \"--scan-json\"])"),
    ("scan_json", "--scan-json"),
    ("geteuid_root_gate", "if os.geteuid() != 0:"),
    ("restic_binary", "def restic_binary() -> Path | None:"),
    ("absolute_sudo_test", "run([str(SUDO), \"-n\", str(TEST), \"-x\", str(path)])"),
    ("restic_resolved_snapshot_info", "def restic_resolved_snapshot_info(snapshot_id: str, restic_path: Path | None) -> dict[str, Any] | None:"),
    ("absolute_backup_env_test", "run([str(SUDO), \"-n\", str(TEST), \"-f\", str(BACKUP_ENV)])"),
    ("restic_metadata_command", "%s snapshots %s --host m11h --tag br-wissen --json"),
    ("absolute_sudo_bash", "run([str(SUDO), \"-n\", str(BASH), \"-lc\", command])"),
    ("resolved_snapshot_unavailable", "restore_resolved_snapshot_unavailable"),
    ("resolved_snapshot_tags_missing", "restore_resolved_snapshot_tags_missing=%s"),
    ("resolved_snapshot_paths_missing", "restore_resolved_snapshot_paths_missing=%d"),
    ("resolved_snapshot_present_summary", "restore_resolved_snapshot_present=%d"),
    ("resolved_snapshot_paths_summary", "restore_resolved_snapshot_paths=%d"),
    ("max_age_env", "BR_RESTORE_MAX_AGE_HOURS"),
    ("log_retention", "restore_log_retention_exceeded"),
    ("restore_too_old", "latest_restore_too_old_h"),
    ("log_bad_mode", "latest_restore_log_bad_mode"),
    ("missing_drill_done", "latest_restore_missing_drill_done"),
    ("status_not_ok", "latest_restore_status_not_ok"),
    ("db_not_ok", "latest_db_restore_status_not_ok"),
    ("missing_storage_capacity", "latest_restore_missing_storage_capacity_ok"),
    ("missing_snapshot", "latest_restore_missing_snapshot"),
    ("missing_resolved_snapshot", "latest_restore_missing_resolved_snapshot"),
    ("missing_dump_name", "latest_restore_missing_dump_name"),
    ("dump_too_small", "latest_restore_dump_too_small"),
    ("protocol_missing", "restore_protocol_missing"),
    ("manifest_missing", "restore_manifest_json_missing"),
    ("db_isolation", "restore_db_isolation_missing"),
    ("dump_markers", "restore_dump_markers_incomplete"),
    ("helper_binaries_summary", "helper_binaries=%d"),
    ("python_binary_summary", "python_binary=%s"),
    ("self_script_policy_summary", "self_script_policy=%d"),
    ("self_parent_policy_summary", "self_parent_policy=%d"),
    ("summary", "restore_freshness_status=%s checks=%d findings=%d latest_restore_age_h=%.1f log_count=%d restore_snapshot=%s restore_resolved_snapshot=%s restore_resolved_snapshot_present=%d restore_resolved_snapshot_paths=%d helper_binaries=%d python_binary=%s self_script_policy=%d self_parent_policy=%d restore_dump=%s db_restore=%s sql_ready_wait=%d manifests=%d"),
]


FORBIDDEN_MUTATING_MARKERS = [
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
    "docker compose exec",
    "pg_dump",
    "psql ",
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
    parser = argparse.ArgumentParser(description="Check BR-Wissen freshness source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    backup_scope_text = read_source(BACKUP_SCOPE, findings, "backup_scope")
    backup_runtime_policy_text = read_source(BACKUP_RUNTIME_POLICY, findings, "backup_runtime_policy")
    restic_repository_check_text = read_source(RESTIC_REPOSITORY_CHECK, findings, "restic_repository_check")
    restore_runtime_policy_text = read_source(RESTORE_RUNTIME_POLICY, findings, "restore_runtime_policy")
    backup_text = read_source(BACKUP_FRESHNESS, findings, "backup_freshness")
    restore_text = read_source(RESTORE_FRESHNESS, findings, "restore_freshness")
    checks += 6

    checks += check_markers(findings, backup_scope_text, BACKUP_SCOPE_MARKERS, "backup_scope")
    checks += check_markers(findings, backup_runtime_policy_text, BACKUP_RUNTIME_POLICY_MARKERS, "backup_runtime_policy")
    checks += check_markers(findings, restic_repository_check_text, RESTIC_REPOSITORY_CHECK_MARKERS, "restic_repository_check")
    checks += check_markers(findings, restore_runtime_policy_text, RESTORE_RUNTIME_POLICY_MARKERS, "restore_runtime_policy")
    checks += check_markers(findings, backup_text, BACKUP_MARKERS, "backup")
    checks += check_markers(findings, restore_text, RESTORE_MARKERS, "restore")
    checks += check_forbidden(findings, backup_scope_text, FORBIDDEN_MUTATING_MARKERS, "backup_scope")
    checks += check_forbidden(findings, backup_runtime_policy_text, FORBIDDEN_MUTATING_MARKERS, "backup_runtime_policy")
    checks += check_forbidden(findings, restic_repository_check_text, FORBIDDEN_MUTATING_MARKERS, "restic_repository_check")
    checks += check_forbidden(findings, restore_runtime_policy_text, FORBIDDEN_MUTATING_MARKERS, "restore_runtime_policy")
    checks += check_forbidden(findings, backup_text, FORBIDDEN_MUTATING_MARKERS, "backup")
    checks += check_forbidden(findings, restore_text, FORBIDDEN_MUTATING_MARKERS, "restore")

    checks += 1
    if backup_text.find("def collect_local_info") > backup_text.find("def sudo_local_info"):
        findings.append("backup_collect_local_after_sudo_wrapper")
    checks += 1
    if restore_text.find("def collect_restore_info") > restore_text.find("def sudo_restore_info"):
        findings.append("restore_collect_after_sudo_wrapper")
    checks += 1
    if restore_text.find("checks += 23") > restore_text.find("restore_dump_markers_incomplete"):
        findings.append("restore_checks_increment_after_findings")

    status = "ok" if not findings else "failed"
    summary = "freshness_source_hardening_status=%s checks=%d findings=%d backup_scope_markers=%d backup_runtime_policy_markers=%d restic_repository_check_markers=%d restore_runtime_policy_markers=%d backup_markers=%d restore_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(BACKUP_SCOPE_MARKERS),
        len(BACKUP_RUNTIME_POLICY_MARKERS),
        len(RESTIC_REPOSITORY_CHECK_MARKERS),
        len(RESTORE_RUNTIME_POLICY_MARKERS),
        len(BACKUP_MARKERS),
        len(RESTORE_MARKERS),
        len(FORBIDDEN_MUTATING_MARKERS) * 6,
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
