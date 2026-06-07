#!/usr/bin/env python3
"""Read-only guard surface registry consistency check for BR-Wissen.

The guard parses the central GuardSpec list from `check-guard-coverage.py` and
validates that the operational surfaces (status wrapper, backup preflight and
systemd healthcheck units) stay aligned with the registry. It only reads project
source files and installed unit text; it does not run guards, Docker, systemctl,
backups, restores, imports, regressions or database queries and never reads
secrets, dumps, logs, answers, exports or source documents.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SCRIPTS = ROOT / "scripts"
GUARD_COVERAGE = SCRIPTS / "check-guard-coverage.py"
STATUS_SCRIPT = SCRIPTS / "status-br-wissen.sh"
BACKUP_SCRIPT = SCRIPTS / "backup-br-wissen.sh"
PROJECT_HEALTHCHECK_UNIT = ROOT / "systemd" / "br-wissen-healthcheck.service"
INSTALLED_HEALTHCHECK_UNIT = Path("/etc/systemd/system/br-wissen-healthcheck.service")


STATUS_ONLY_HELPERS = {
    "check-container-images.sh": "status_image_inventory_detail",
    "check-image-pinning-readiness.sh": "status_optional_readiness_detail",
}


FORBIDDEN_MARKERS = [
    "INS" + "ERT ",
    "UPD" + "ATE ",
    "DEL" + "ETE ",
    "DR" + "OP ",
    "TRUN" + "CATE ",
    "AL" + "TER ",
    "CREATE" + " TABLE",
    "COM" + "MIT",
    "conn" + ".commit",
    "os" + ".remove(",
    "Path" + ".unlink(",
    "shutil" + ".rmtree",
    "docker compose" + " up",
    "docker compose" + " down",
    "docker compose" + " restart",
    "docker compose" + " rm",
    "docker" + " rm",
    "docker volume" + " rm",
    "docker" + " rmi",
    "docker system" + " prune",
    "systemctl" + " start",
    "systemctl" + " stop",
    "systemctl" + " restart",
    "systemctl" + " enable",
    "systemctl" + " disable",
    "systemctl" + " daemon-reload",
    "pg" + "_dump",
    "ps" + "ql ",
    "res" + "tic ",
    "/srv/br-wissensdatenbank/" + "backups",
    "/srv/br-wissensdatenbank/" + "secrets",
    "/srv/br-wissensdatenbank/" + "exports",
    "/run/br-" + "secrets/",
]


@dataclass(frozen=True)
class GuardSurface:
    label: str
    script: str
    status_key: str
    status_section: str | None
    backup_label: str | None
    in_status: bool
    in_backup: bool
    in_healthcheck: bool
    healthcheck_args: str
    backup_args: str


def safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_")


def read_source(path: Path, findings: list[str], label: str) -> str:
    if not path.exists():
        findings.append("missing_file=%s" % label)
        return ""
    if path.is_symlink():
        findings.append("symlink_file=%s" % label)
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def literal_value(node: ast.AST) -> object:
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return None


def bool_value(value: object, default: bool) -> bool:
    if value is None:
        return default
    return bool(value)


def parse_guard_surfaces(text: str, findings: list[str]) -> list[GuardSurface]:
    tree = ast.parse(text)
    surfaces: list[GuardSurface] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        target = node.target if isinstance(node, ast.AnnAssign) else node.targets[0]
        if not isinstance(target, ast.Name) or target.id != "GUARDS":
            continue
        value = node.value
        if not isinstance(value, ast.List):
            findings.append("guards_not_list_literal")
            return []
        for item in value.elts:
            if not isinstance(item, ast.Call):
                findings.append("guard_spec_not_call")
                continue
            positional = [literal_value(arg) for arg in item.args]
            keywords = {kw.arg: literal_value(kw.value) for kw in item.keywords if kw.arg}
            if len(positional) < 3:
                findings.append("guard_spec_too_short")
                continue
            status_section = keywords.get("status_section", positional[3] if len(positional) > 3 else None)
            backup_label = keywords.get("backup_label", positional[4] if len(positional) > 4 else None)
            surfaces.append(
                GuardSurface(
                    label=str(positional[0]),
                    script=str(positional[1]),
                    status_key=str(positional[2]),
                    status_section=str(status_section) if status_section is not None else None,
                    backup_label=str(backup_label) if backup_label is not None else None,
                    in_status=bool_value(keywords.get("in_status"), True),
                    in_backup=bool_value(keywords.get("in_backup"), True),
                    in_healthcheck=bool_value(keywords.get("in_healthcheck"), True),
                    healthcheck_args=str(keywords.get("healthcheck_args", " --summary")),
                    backup_args=str(keywords.get("backup_args", " --summary")),
                )
            )
        return surfaces
    findings.append("guards_assignment_missing")
    return []


def normalize_args(value: str) -> str:
    return " ".join(value.split())


def extract_status_calls(text: str) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    pattern = re.compile(r"^\s*scripts/(check-[A-Za-z0-9_.-]+)(?P<args>[^#\n]*)$", re.MULTILINE)
    for match in pattern.finditer(text):
        calls.append((match.group(1), normalize_args(match.group("args") or "")))
    return calls


def extract_backup_preflights(text: str) -> list[tuple[str, str, str]]:
    pattern = re.compile(
        r'^\s*run_preflight\s+([A-Za-z0-9_]+)\s+"\$\{APP_DIR\}/scripts/([^" ]+)"(?P<args>[^#\n]*)$',
        re.MULTILINE,
    )
    return [(m.group(1), m.group(2), normalize_args(m.group("args") or "")) for m in pattern.finditer(text)]


def extract_execstartpre(text: str) -> list[tuple[str, str]]:
    pattern = re.compile(
        r"^ExecStartPre=/home/chris/web/br\.m11h\.eu/scripts/(check-[A-Za-z0-9_.-]+)(?P<args>[^\n]*)$",
        re.MULTILINE,
    )
    return [(m.group(1), normalize_args(m.group("args") or "")) for m in pattern.finditer(text)]


def move_before(items: list[tuple[str, str]], item: tuple[str, str], before: tuple[str, str]) -> list[tuple[str, str]]:
    if item not in items or before not in items:
        return items
    new_items = [entry for entry in items if entry != item]
    index = new_items.index(before)
    new_items.insert(index, item)
    return new_items


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def compare_sequence(findings: list[str], label: str, actual: list[object], expected: list[object]) -> int:
    checks = 1
    if actual != expected:
        findings.append("%s_sequence_unexpected_count_%d_expected_%d" % (label, len(actual), len(expected)))
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            checks += 1
            if actual_item != expected_item:
                findings.append("%s_first_mismatch_%d" % (label, index))
                break
        if len(actual) != len(expected):
            checks += 1
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen guard surface registry consistency")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    coverage_text = read_source(GUARD_COVERAGE, findings, "guard_coverage")
    status_text = read_source(STATUS_SCRIPT, findings, "status_script")
    backup_text = read_source(BACKUP_SCRIPT, findings, "backup_script")
    project_unit_text = read_source(PROJECT_HEALTHCHECK_UNIT, findings, "project_healthcheck_unit")
    installed_unit_text = read_source(INSTALLED_HEALTHCHECK_UNIT, findings, "installed_healthcheck_unit")
    checks += 5

    surfaces = parse_guard_surfaces(coverage_text, findings) if coverage_text else []
    checks += 1

    expected_status = [(guard.script, normalize_args(guard.healthcheck_args)) for guard in surfaces if guard.in_status]
    expected_status_scripts = {script for script, _args in expected_status}
    actual_status = extract_status_calls(status_text)
    actual_status_scripts = [script for script, _args in actual_status]
    allowed_status_scripts = expected_status_scripts | set(STATUS_ONLY_HELPERS)

    for script, _args in expected_status:
        checks += 1
        if script not in actual_status_scripts:
            findings.append("status_missing_registry_script=%s" % script)
    for script, _args in actual_status:
        checks += 1
        if script not in allowed_status_scripts:
            findings.append("status_unexpected_check_script=%s" % script)
    for script in sorted(expected_status_scripts):
        checks += 1
        if actual_status_scripts.count(script) != 1:
            findings.append("status_registry_script_count_%s=%d" % (safe(script), actual_status_scripts.count(script)))

    expected_backup = [
        (str(guard.backup_label), guard.script, normalize_args(guard.backup_args))
        for guard in surfaces
        if guard.in_backup and guard.backup_label
    ]
    actual_backup = extract_backup_preflights(backup_text)
    checks += compare_sequence(findings, "backup_preflight", actual_backup, expected_backup)

    expected_healthcheck = [(guard.script, normalize_args(guard.healthcheck_args)) for guard in surfaces if guard.in_healthcheck]
    expected_healthcheck = move_before(
        expected_healthcheck,
        ("check-backup-freshness.py", "--summary"),
        ("check-backup-source-hardening.py", "--summary"),
    )
    actual_project_healthcheck = extract_execstartpre(project_unit_text)
    actual_installed_healthcheck = extract_execstartpre(installed_unit_text)
    checks += compare_sequence(findings, "project_healthcheck", actual_project_healthcheck, expected_healthcheck)
    checks += compare_sequence(findings, "installed_healthcheck", actual_installed_healthcheck, expected_healthcheck)

    for prefix, text in [
        ("self", read_source(SCRIPTS / "check-surface-registry.py", findings, "self")),
        ("guard_coverage", coverage_text),
    ]:
        checks += check_forbidden(findings, text, FORBIDDEN_MARKERS, prefix)

    status = "ok" if not findings else "failed"
    summary = "surface_registry_status=%s checks=%d findings=%d guards=%d status_calls=%d backup_preflights=%d healthcheck_preflights=%d status_helpers=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(surfaces),
        len(actual_status),
        len(actual_backup),
        len(actual_project_healthcheck),
        len(STATUS_ONLY_HELPERS),
        len(FORBIDDEN_MARKERS),
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
