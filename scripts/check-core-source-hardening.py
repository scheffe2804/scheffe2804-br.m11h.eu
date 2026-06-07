#!/usr/bin/env python3
"""Read-only source hardening guard for BR-Wissen core operational guards.

The guard validates host-context, time-sync, compose-service, privilege-policy,
privilege-risk-review, least-privilege-plan, remediation-gate, no-sudoers-change, project-artifact and runtime-log-marker guard sources for expected metadata-only checks, compact
summaries and non-mutating behaviour. It only reads project source files; it does
not run Docker, Compose, timedatectl, chronyc, hostname, Tailscale, backups,
restores, imports, regressions or database queries and never reads secrets,
dumps, logs, answers or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
HOST_CONTEXT = ROOT / "scripts" / "check-host-context.py"
TIME_SYNC = ROOT / "scripts" / "check-time-sync.py"
COMPOSE_SERVICES = ROOT / "scripts" / "check-compose-services.py"
PRIVILEGE_POLICY = ROOT / "scripts" / "check-privilege-policy.py"
PRIVILEGE_RISK_REVIEW = ROOT / "scripts" / "check-privilege-risk-review.py"
PRIVILEGE_LEAST_PRIVILEGE_PLAN = ROOT / "scripts" / "check-privilege-least-privilege-plan.py"
PRIVILEGE_REMEDIATION_GATE = ROOT / "scripts" / "check-privilege-remediation-gate.py"
PRIVILEGE_NO_SUDOERS_CHANGE = ROOT / "scripts" / "check-privilege-no-sudoers-change.py"
PROJECT_ARTIFACTS = ROOT / "scripts" / "check-project-artifacts.sh"
RUNTIME_LOG_MARKERS_SCRIPT = ROOT / "scripts" / "check-runtime-log-markers.sh"


HOST_CONTEXT_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only host context guard for BR-Wissen"),
    ("docstring_no_secrets", "never reads application\nsecrets, backup environment contents, logs or dumps"),
    ("host_context_path", "HOST_CONTEXT = Path(os.getenv(\"BR_HOST_CONTEXT\", \"/etc/opencode-host-context\"))"),
    ("expected_hostname", "EXPECTED_HOSTNAME = os.getenv(\"BR_EXPECTED_HOSTNAME\", \"m11h.eu\")"),
    ("expected_role", "EXPECTED_HOST_ROLE = os.getenv(\"BR_EXPECTED_HOST_ROLE\", \"m11h\")"),
    ("expected_server", "EXPECTED_THIS_SERVER = os.getenv(\"BR_EXPECTED_THIS_SERVER\", \"m11h\")"),
    ("expected_public_ip", "EXPECTED_PUBLIC_IPV4 = os.getenv(\"BR_EXPECTED_PUBLIC_IPV4\", \"31.70.74.139\")"),
    ("expected_tailscale_ip", "EXPECTED_TAILSCALE_IPV4 = os.getenv(\"BR_EXPECTED_TAILSCALE_IPV4\", \"100.102.205.121\")"),
    ("parse_context", "def parse_context(path: Path)"),
    ("read_text_context", "path.read_text(encoding=\"utf-8\", errors=\"replace\")"),
    ("hostname_command", "subprocess.run([\"hostname\"]"),
    ("tailscale_command", "subprocess.run([\"tailscale\", \"ip\", \"-4\"]"),
    ("expect_value", "def expect_value(findings: list[str], label: str, actual: str, expected: str)"),
    ("expected_values", "expected_values = ["),
    ("m00h_different", "M00H_IS_DIFFERENT_SERVER"),
    ("summary", "host_context_status=%s checks=%d findings=%d hostname=%s host_role=%s this_server=%s public_ipv4=%s tailscale_ipv4=%s"),
]


TIME_SYNC_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only host time synchronisation guard for BR-Wissen"),
    ("docstring_no_mutation", "never\nchanges time settings and never reads application secrets, dumps, logs, answers\nor source documents"),
    ("max_system_offset", "MAX_SYSTEM_OFFSET_SECONDS = 1.0"),
    ("max_rms_offset", "MAX_RMS_OFFSET_SECONDS = 1.0"),
    ("max_stratum", "MAX_STRATUM = 8"),
    ("timedatectl", "timedatectl_values()"),
    ("timedatectl_show", "timedatectl",),
    ("ntp_synchronized", "NTPSynchronized"),
    ("system_clock", "SystemClockSynchronized"),
    ("timezone", "Timezone"),
    ("parse_seconds", "def parse_seconds(line: str)"),
    ("chrony_tracking", "chronyc",),
    ("stratum", "Stratum"),
    ("system_time", "System time"),
    ("rms_offset", "RMS offset"),
    ("leap_status", "Leap status"),
    ("summary", "time_sync_status=%s checks=%d findings=%d ntp=%d system_clock=%d timezone=%s chrony_stratum=%d system_offset_s=%.6f rms_offset_s=%.6f leap_normal=%d"),
]


COMPOSE_SERVICE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only Docker Compose service guard for BR-Wissen"),
    ("docstring_metadata_only", "using Docker\nmetadata only"),
    ("expected_services", "EXPECTED_SERVICES = [\"app\", \"db\", \"worker\", \"proxy\", \"cloudflared\"]"),
    ("health_required", "HEALTH_REQUIRED = {\"app\", \"db\"}"),
    ("compose_ps", "docker",),
    ("compose_ps_format", "compose",),
    ("format_json", "--format",),
    ("json_parse", "json.loads"),
    ("array_output", "stdout.startswith(\"[\")"),
    ("line_output", "for raw_line in proc.stdout.splitlines()"),
    ("service_name", "def service_name(row: dict[str, Any])"),
    ("state_value", "def state_value(row: dict[str, Any])"),
    ("health_value", "def health_value(row: dict[str, Any])"),
    ("normalize_state", "def normalize_state(value: str)"),
    ("running", "state != \"running\""),
    ("healthy", "health != \"healthy\""),
    ("unexpected_services", "unexpected_services = sorted(set(by_service) - set(EXPECTED_SERVICES))"),
    ("summary", "compose_service_status=%s checks=%d findings=%d expected=%d running=%d health_required=%d healthy=%d unexpected=%d"),
]


PRIVILEGE_POLICY_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only sudo privilege policy visibility guard for BR-Wissen"),
    ("docstring_policy_shape", "prints only counters and policy-class flags"),
    ("target_user", "TARGET_USER = os.getenv(\"BR_PRIVILEGE_POLICY_USER\", \"chris\")"),
    ("sudo_list", "subprocess.run([\"sudo\", \"-n\", \"-l\", \"-U\", TARGET_USER]"),
    ("parse_policy", "def parse_policy(text: str) -> dict[str, int | str]:"),
    ("command_entries", "command_entries"),
    ("nopasswd_all", "nopasswd_all"),
    ("unrestricted_all", "unrestricted_all"),
    ("broad_sudo", "broad_sudo"),
    ("non_failing_risk_metadata", "Broad sudo rights are reported as risk metadata, not as a\nfailing finding"),
    ("summary", "privilege_policy_status=%s checks=%d findings=%d target_user=%s sudo_list_lines=%d command_entries=%d nopasswd_entries=%d password_entries=%d nopasswd_all=%d unrestricted_all=%d broad_sudo=%d"),
]


PRIVILEGE_RISK_REVIEW_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only privilege risk review guard for BR-Wissen"),
    ("docstring_no_sudoers", "never prints sudoers contents"),
    ("review_doc", "REVIEW_DOC = ROOT / \"docs\" / \"PRIVILEGE-RISK-REVIEW.md\""),
    ("policy_script", "POLICY_SCRIPT = ROOT / \"scripts\" / \"check-privilege-policy.py\""),
    ("required_markers", "REQUIRED_REVIEW_MARKERS = ["),
    ("risk_acceptance", "risk_acceptance_status=accepted"),
    ("last_review", "last_review_date="),
    ("next_review", "next_review_due="),
    ("least_privilege", "least_privilege_followup=required"),
    ("no_auto_change", "sudoers_auto_change_allowed=0"),
    ("parse_date", "def parse_iso_date(value: str) -> date | None:"),
    ("review_overdue", "review_overdue"),
    ("policy_summary", "def run_policy_summary() -> dict[str, str]:"),
    ("broad_sudo", "broad_sudo"),
    ("accepted_risk", "accepted_risk"),
    ("critical_privilege_risk", "critical_privilege_risk"),
    ("summary", "privilege_risk_review_status=%s checks=%d findings=%d target_user=%s critical_privilege_risk=%d broad_sudo=%d nopasswd_all=%d unrestricted_all=%d acceptance=%d least_privilege_followup=%d review_doc=%d review_cadence=monthly review_overdue=%d days_until_review=%d"),
    ("allow_accepted_risk", "--allow-accepted-risk"),
    ("accepted_risk_exit", "return 2"),
]


PRIVILEGE_LEAST_PRIVILEGE_PLAN_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only least-privilege follow-up plan guard for BR-Wissen"),
    ("docstring_no_sudoers", "never reads or prints sudoers contents"),
    ("plan_doc", "PLAN_DOC = ROOT / \"docs\" / \"PRIVILEGE-LEAST-PRIVILEGE-PLAN.md\""),
    ("required_markers", "REQUIRED_PLAN_MARKERS = ["),
    ("plan_status", "plan_status=planned"),
    ("target_due", "target_due="),
    ("lockout", "requires_lockout_protection=1"),
    ("rollback", "requires_rollback_plan=1"),
    ("visudo", "requires_visudo_validation=1"),
    ("backup_before_change", "requires_backup_before_change=1"),
    ("command_inventory", "requires_command_inventory=1"),
    ("staged_rollout", "requires_staged_rollout=1"),
    ("no_auto_change", "sudoers_auto_change_allowed=0"),
    ("parse_date", "def parse_iso_date(value: str) -> date | None:"),
    ("due_overdue", "due_overdue"),
    ("summary", "privilege_least_privilege_plan_status=%s checks=%d findings=%d target_user=%s plan_ready=%d remediation_complete=%d due_overdue=%d days_until_due=%d lockout_protection=1 rollback_plan=1 command_inventory=1 staged_rollout=1"),
]


PRIVILEGE_REMEDIATION_GATE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only privilege remediation gate guard for BR-Wissen"),
    ("docstring_no_sudoers", "never reads or\nprints sudoers contents"),
    ("gate_doc", "GATE_DOC = ROOT / \"docs\" / \"PRIVILEGE-REMEDIATION-GATE.md\""),
    ("risk_script", "RISK_SCRIPT = ROOT / \"scripts\" / \"check-privilege-risk-review.py\""),
    ("plan_script", "PLAN_SCRIPT = ROOT / \"scripts\" / \"check-privilege-least-privilege-plan.py\""),
    ("required_markers", "REQUIRED_GATE_MARKERS = ["),
    ("gate_status", "gate_status=closed"),
    ("remediation_allowed", "remediation_allowed=0"),
    ("actual_sudoers_change_allowed", "actual_sudoers_change_allowed=0"),
    ("remediation_complete_required", "remediation_complete_required_before_claim=1"),
    ("accepted_risk_visible", "accepted_risk_must_remain_visible=1"),
    ("no_auto_change", "sudoers_auto_change_allowed=0"),
    ("run_summary", "def run_summary(script: Path, *extra_args: str) -> tuple[int, dict[str, str]]:"),
    ("allow_accepted_risk", "--allow-accepted-risk"),
    ("critical_privilege_risk", "critical_privilege_risk"),
    ("summary", "privilege_remediation_gate_status=%s checks=%d findings=%d target_user=%s remediation_allowed=%d actual_sudoers_change_allowed=%d remediation_complete=%d accepted_risk_visible=%d critical_privilege_risk=%d broad_sudo=%d plan_status=%s gate_doc=%d"),
]


PRIVILEGE_NO_SUDOERS_CHANGE_MARKERS: list[tuple[str, str]] = [
    ("docstring_read_only", "Read-only no-sudoers-change policy guard for BR-Wissen"),
    ("docstring_no_sudoers", "never reads or prints sudoers contents"),
    ("policy_doc", "POLICY_DOC = ROOT / \"docs\" / \"PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md\""),
    ("risk_script", "RISK_SCRIPT = ROOT / \"scripts\" / \"check-privilege-risk-review.py\""),
    ("gate_script", "GATE_SCRIPT = ROOT / \"scripts\" / \"check-privilege-remediation-gate.py\""),
    ("required_markers", "REQUIRED_POLICY_MARKERS = ["),
    ("policy_status", "policy_status=active"),
    ("sudoers_forbidden", "sudoers_change_policy=forbidden"),
    ("changes_allowed_zero", "sudoers_changes_allowed=0"),
    ("remediation_requested_zero", "sudoers_remediation_requested=0"),
    ("actual_change_zero", "actual_sudoers_change_allowed=0"),
    ("accepted_risk_continues", "accepted_risk_continues=1"),
    ("planning_only", "least_privilege_planning_only=1"),
    ("new_explicit_request", "requires_new_explicit_user_request_before_sudoers_change=1"),
    ("run_summary", "def run_summary(script: Path, *extra_args: str) -> tuple[int, dict[str, str]]:"),
    ("summary", "privilege_no_sudoers_change_status=%s checks=%d findings=%d target_user=%s sudoers_changes_allowed=%d sudoers_remediation_requested=%d actual_sudoers_change_allowed=%d remediation_complete=%d accepted_risk_continues=%d critical_privilege_risk=%d broad_sudo=%d gate_status=%s policy_doc=%d"),
]


PROJECT_ARTIFACT_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("root", "ROOT=\"/home/chris/web/br.m11h.eu\""),
    ("summary_arg", "--summary"),
    ("check_glob", "check_glob()"),
    ("check_find", "check_find()"),
    ("compgen", "compgen -G"),
    ("find", "find ."),
    ("python_bytecode", "python_bytecode"),
    ("python_cache_dirs", "python_cache_dirs"),
    ("project_logs", "project_logs"),
    ("env_files", "env_files"),
    ("root_env", "root_env"),
    ("cloudflared_credentials_json", "cloudflared_credentials_json"),
    ("generic_credentials", "generic_credentials"),
    ("generic_tokens", "generic_tokens"),
    ("summary", "artifact_status=%s checks=%d findings=%d"),
]


RUNTIME_LOG_SOURCE_MARKERS: list[tuple[str, str]] = [
    ("strict_mode", "set -euo pipefail"),
    ("app_dir", "APP_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")/..\" && pwd)\""),
    ("proxy_container", "br-wissen-proxy"),
    ("cloudflared_container", "br-wissen-cloudflared"),
    ("app_container", "br-wissen-app"),
    ("worker_container", "br-wissen-worker"),
    ("db_container", "br-wissen-db"),
    ("cf_access_marker", "Cf-Access-Jwt-Assertion"),
    ("authorization_marker", "Authorization"),
    ("proxy_authorization_marker", "Proxy-Authorization"),
    ("auth_token_marker", "X-Auth-Token"),
    ("api_key_marker", "X-Api-Key"),
    ("docker_inspect", "docker inspect"),
    ("docker_logs", "docker logs"),
    ("grep_fixed", "grep -Fq --"),
    ("summary", "runtime_log_marker_status=${status} checks=${#containers[@]} markers=${#markers[@]} findings=${findings}"),
]


FORBIDDEN_COMMON_MARKERS = [
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "DROP ",
    "TRUNCATE ",
    "ALTER ",
    "CREATE TABLE",
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
    "timedatectl set-",
    "chronyc makestep",
    "pg_dump",
    "psql ",
    "restic ",
    "/srv/br-wissensdatenbank/backups",
    "/srv/br-wissensdatenbank/sources",
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
    parser = argparse.ArgumentParser(description="Check BR-Wissen core source hardening markers")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    host_text = read_source(HOST_CONTEXT, findings, "host_context")
    time_text = read_source(TIME_SYNC, findings, "time_sync")
    compose_text = read_source(COMPOSE_SERVICES, findings, "compose_services")
    privilege_text = read_source(PRIVILEGE_POLICY, findings, "privilege_policy")
    privilege_risk_text = read_source(PRIVILEGE_RISK_REVIEW, findings, "privilege_risk_review")
    privilege_plan_text = read_source(PRIVILEGE_LEAST_PRIVILEGE_PLAN, findings, "privilege_least_privilege_plan")
    privilege_gate_text = read_source(PRIVILEGE_REMEDIATION_GATE, findings, "privilege_remediation_gate")
    privilege_no_change_text = read_source(PRIVILEGE_NO_SUDOERS_CHANGE, findings, "privilege_no_sudoers_change")
    artifact_text = read_source(PROJECT_ARTIFACTS, findings, "project_artifacts")
    log_text = read_source(RUNTIME_LOG_MARKERS_SCRIPT, findings, "runtime_log_markers")
    checks += 10

    checks += check_markers(findings, host_text, HOST_CONTEXT_MARKERS, "host")
    checks += check_markers(findings, time_text, TIME_SYNC_MARKERS, "time")
    checks += check_markers(findings, compose_text, COMPOSE_SERVICE_MARKERS, "compose")
    checks += check_markers(findings, privilege_text, PRIVILEGE_POLICY_MARKERS, "privilege")
    checks += check_markers(findings, privilege_risk_text, PRIVILEGE_RISK_REVIEW_MARKERS, "privilege_risk")
    checks += check_markers(findings, privilege_plan_text, PRIVILEGE_LEAST_PRIVILEGE_PLAN_MARKERS, "privilege_plan")
    checks += check_markers(findings, privilege_gate_text, PRIVILEGE_REMEDIATION_GATE_MARKERS, "privilege_gate")
    checks += check_markers(findings, privilege_no_change_text, PRIVILEGE_NO_SUDOERS_CHANGE_MARKERS, "privilege_no_change")
    checks += check_markers(findings, artifact_text, PROJECT_ARTIFACT_MARKERS, "artifact")
    checks += check_markers(findings, log_text, RUNTIME_LOG_SOURCE_MARKERS, "runtime_log")

    for prefix, text in [
        ("host", host_text),
        ("time", time_text),
        ("compose", compose_text),
        ("privilege", privilege_text),
        ("privilege_risk", privilege_risk_text),
        ("privilege_plan", privilege_plan_text),
        ("privilege_gate", privilege_gate_text),
        ("privilege_no_change", privilege_no_change_text),
        ("artifact", artifact_text),
        ("runtime_log", log_text),
    ]:
        checks += check_forbidden(findings, text, FORBIDDEN_COMMON_MARKERS, prefix)

    checks += 1
    if host_text.find("EXPECTED_HOSTNAME") > host_text.find("expected_values = ["):
        findings.append("host_expected_values_before_policy")
    checks += 1
    if time_text.find("MAX_SYSTEM_OFFSET_SECONDS") > time_text.find("if system_offset > MAX_SYSTEM_OFFSET_SECONDS"):
        findings.append("time_threshold_after_check")
    checks += 1
    if compose_text.find("EXPECTED_SERVICES") > compose_text.find("for expected in EXPECTED_SERVICES"):
        findings.append("compose_expected_services_after_loop")
    checks += 1
    if privilege_text.find("def parse_policy") > privilege_text.find("policy = parse_policy"):
        findings.append("privilege_parser_after_use")
    checks += 1
    if privilege_risk_text.find("REQUIRED_REVIEW_MARKERS") > privilege_risk_text.find("for marker in REQUIRED_REVIEW_MARKERS"):
        findings.append("privilege_risk_markers_after_use")
    checks += 1
    if privilege_plan_text.find("REQUIRED_PLAN_MARKERS") > privilege_plan_text.find("for marker in REQUIRED_PLAN_MARKERS"):
        findings.append("privilege_plan_markers_after_use")
    checks += 1
    if privilege_gate_text.find("REQUIRED_GATE_MARKERS") > privilege_gate_text.find("for marker in REQUIRED_GATE_MARKERS"):
        findings.append("privilege_gate_markers_after_use")
    checks += 1
    if privilege_no_change_text.find("REQUIRED_POLICY_MARKERS") > privilege_no_change_text.find("for marker in REQUIRED_POLICY_MARKERS"):
        findings.append("privilege_no_change_markers_after_use")
    checks += 1
    if artifact_text.find("check_glob()") > artifact_text.find("check_glob \"python_bytecode\""):
        findings.append("artifact_helper_after_use")
    checks += 1
    if log_text.find("markers=(") > log_text.find("for marker in"):
        findings.append("runtime_log_markers_after_loop")

    status = "ok" if not findings else "failed"
    summary = "core_source_hardening_status=%s checks=%d findings=%d host_markers=%d time_markers=%d compose_markers=%d privilege_markers=%d privilege_risk_markers=%d privilege_plan_markers=%d privilege_gate_markers=%d privilege_no_change_markers=%d artifact_markers=%d runtime_log_markers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(HOST_CONTEXT_MARKERS),
        len(TIME_SYNC_MARKERS),
        len(COMPOSE_SERVICE_MARKERS),
        len(PRIVILEGE_POLICY_MARKERS),
        len(PRIVILEGE_RISK_REVIEW_MARKERS),
        len(PRIVILEGE_LEAST_PRIVILEGE_PLAN_MARKERS),
        len(PRIVILEGE_REMEDIATION_GATE_MARKERS),
        len(PRIVILEGE_NO_SUDOERS_CHANGE_MARKERS),
        len(PROJECT_ARTIFACT_MARKERS),
        len(RUNTIME_LOG_SOURCE_MARKERS),
        len(FORBIDDEN_COMMON_MARKERS) * 10,
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
