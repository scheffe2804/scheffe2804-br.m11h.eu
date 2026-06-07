#!/usr/bin/env python3
"""Read-only guard registry integrity check for BR-Wissen.

The guard parses the central GuardSpec list from `check-guard-coverage.py` and
validates the registry itself for duplicate labels, scripts, status keys and
backup labels, missing or non-executable guard scripts and basic contract shape.
It only reads project source files; it does not run guards, Docker, systemctl,
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


ALLOWED_ARG_CONTRACTS = {"", " --summary", " --summary --allow-accepted-risk"}
STATUS_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*_status$")
BACKUP_LABEL_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


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
class GuardRegistryEntry:
    label: str
    script: str
    status_key: str
    status_section: str | None
    backup_label: str | None
    in_status: bool
    in_backup: bool
    in_healthcheck: bool
    in_readiness: bool
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


def parse_registry(text: str, findings: list[str]) -> list[GuardRegistryEntry]:
    tree = ast.parse(text)
    entries: list[GuardRegistryEntry] = []
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
            entries.append(
                GuardRegistryEntry(
                    label=str(positional[0]),
                    script=str(positional[1]),
                    status_key=str(positional[2]),
                    status_section=str(status_section) if status_section is not None else None,
                    backup_label=str(backup_label) if backup_label is not None else None,
                    in_status=bool_value(keywords.get("in_status"), True),
                    in_backup=bool_value(keywords.get("in_backup"), True),
                    in_healthcheck=bool_value(keywords.get("in_healthcheck"), True),
                    in_readiness=bool_value(keywords.get("in_readiness"), True),
                    healthcheck_args=str(keywords.get("healthcheck_args", " --summary")),
                    backup_args=str(keywords.get("backup_args", " --summary")),
                )
            )
        return entries
    findings.append("guards_assignment_missing")
    return []


def find_duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen guard registry integrity")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    coverage_text = read_source(GUARD_COVERAGE, findings, "guard_coverage")
    checks += 1
    entries = parse_registry(coverage_text, findings) if coverage_text else []
    checks += 1

    labels = [entry.label for entry in entries]
    scripts = [entry.script for entry in entries]
    status_keys = [entry.status_key for entry in entries]
    backup_labels = [entry.backup_label for entry in entries if entry.backup_label]

    for name, values in [
        ("label", labels),
        ("script", scripts),
        ("status_key", status_keys),
        ("backup_label", backup_labels),
    ]:
        checks += 1
        duplicates = find_duplicates(values)
        if duplicates:
            findings.append("duplicate_%s=%s" % (name, ",".join(duplicates)))

    for index, entry in enumerate(entries):
        checks += 10
        if not entry.label or entry.label == "None":
            findings.append("empty_label_%d" % index)
        if not entry.script.startswith("check-"):
            findings.append("script_name_unexpected=%s" % entry.script)
        if "/" in entry.script or ".." in entry.script:
            findings.append("script_path_unexpected=%s" % safe(entry.script))
        script_path = SCRIPTS / entry.script
        if not script_path.exists():
            findings.append("script_missing=%s" % entry.script)
        elif not os.access(script_path, os.X_OK):
            findings.append("script_not_executable=%s" % entry.script)
        if not STATUS_KEY_PATTERN.match(entry.status_key):
            findings.append("status_key_shape_unexpected=%s" % entry.status_key)
        if entry.in_status and not entry.status_section:
            findings.append("status_section_missing=%s" % entry.script)
        if entry.in_backup and not entry.backup_label:
            findings.append("backup_label_missing=%s" % entry.script)
        if entry.backup_label and not BACKUP_LABEL_PATTERN.match(entry.backup_label):
            findings.append("backup_label_shape_unexpected=%s" % entry.backup_label)
        if entry.healthcheck_args not in ALLOWED_ARG_CONTRACTS:
            findings.append("healthcheck_args_unexpected_%s=%s" % (safe(entry.script), safe(entry.healthcheck_args)))
        if entry.backup_args not in ALLOWED_ARG_CONTRACTS:
            findings.append("backup_args_unexpected_%s=%s" % (safe(entry.script), safe(entry.backup_args)))
        if not entry.in_backup and entry.backup_label:
            findings.append("backup_label_present_when_disabled=%s" % entry.script)

    checks += 1
    if "GUARDS: list[GuardSpec] = [" not in coverage_text:
        findings.append("typed_guards_assignment_missing")
    checks += 1
    if coverage_text.count("GuardSpec(") != len(entries):
        findings.append("guard_spec_call_count_mismatch=%d" % coverage_text.count("GuardSpec("))
    checks += 1
    if coverage_text.find("GUARDS: list[GuardSpec]") > coverage_text.find("for guard in GUARDS:"):
        findings.append("guards_assignment_after_runtime_loop")

    self_text = read_source(SCRIPTS / "check-guard-registry-integrity.py", findings, "self")
    checks += 1
    checks += check_forbidden(findings, self_text, FORBIDDEN_MARKERS, "self")

    disabled_backup = sum(1 for entry in entries if not entry.in_backup)
    status = "ok" if not findings else "failed"
    summary = "guard_registry_integrity_status=%s checks=%d findings=%d guards=%d labels=%d scripts=%d status_keys=%d backup_labels=%d disabled_backup=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(entries),
        len(labels),
        len(scripts),
        len(status_keys),
        len(backup_labels),
        disabled_backup,
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
