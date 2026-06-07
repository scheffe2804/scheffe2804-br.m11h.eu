#!/usr/bin/env python3
"""Read-only summary contract guard for BR-Wissen guard scripts.

The guard parses the central GuardSpec list from `check-guard-coverage.py` and
validates that each declared guard script source contains its declared status key
and, for summary-capable integrations, an explicit `--summary` contract marker.
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


NO_SUMMARY_CONTRACT = {
    "check-runtime-log-markers.sh": "shell_guard_without_summary_flag_in_healthcheck",
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
class GuardContract:
    label: str
    script: str
    status_key: str
    healthcheck_args: str
    backup_args: str
    in_healthcheck: bool
    in_backup: bool


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


def parse_guard_contracts(text: str, findings: list[str]) -> list[GuardContract]:
    tree = ast.parse(text)
    contracts: list[GuardContract] = []
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
            label = str(positional[0])
            script = str(positional[1])
            status_key = str(positional[2])
            contracts.append(
                GuardContract(
                    label=label,
                    script=script,
                    status_key=status_key,
                    healthcheck_args=str(keywords.get("healthcheck_args", " --summary")),
                    backup_args=str(keywords.get("backup_args", " --summary")),
                    in_healthcheck=bool(keywords.get("in_healthcheck", True)),
                    in_backup=bool(keywords.get("in_backup", True)),
                )
            )
        return contracts
    findings.append("guards_assignment_missing")
    return []


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen guard summary/status contracts")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []
    coverage_text = read_source(GUARD_COVERAGE, findings, "guard_coverage")
    checks += 1
    contracts = parse_guard_contracts(coverage_text, findings) if coverage_text else []
    checks += 1

    summary_expected = 0
    status_key_expected = 0
    no_summary_exceptions = 0

    for contract in contracts:
        script_path = SCRIPTS / contract.script
        script_text = read_source(script_path, findings, contract.script)
        checks += 1
        status_key_expected += 1
        checks += 1
        if contract.status_key not in script_text:
            findings.append("status_key_missing_%s=%s" % (safe(contract.script), contract.status_key))

        expects_summary = "--summary" in contract.healthcheck_args or "--summary" in contract.backup_args
        expects_allow_accepted_risk = "--allow-accepted-risk" in contract.healthcheck_args or "--allow-accepted-risk" in contract.backup_args
        if contract.script in NO_SUMMARY_CONTRACT:
            no_summary_exceptions += 1
            expects_summary = False
        if expects_summary:
            summary_expected += 1
            checks += 2
            if "--summary" not in script_text:
                findings.append("summary_arg_missing=%s" % contract.script)
            if "%s" % contract.status_key not in script_text:
                findings.append("summary_status_key_missing=%s" % contract.script)
        if expects_allow_accepted_risk:
            checks += 1
            if "--allow-accepted-risk" not in script_text:
                findings.append("allow_accepted_risk_arg_missing=%s" % contract.script)
        checks += 1
        if contract.in_healthcheck and contract.healthcheck_args == " --summary" and "--summary" not in script_text and contract.script not in NO_SUMMARY_CONTRACT:
            findings.append("healthcheck_summary_contract_missing=%s" % contract.script)
        checks += 1
        if contract.in_backup and contract.backup_args == " --summary" and "--summary" not in script_text and contract.script not in NO_SUMMARY_CONTRACT:
            findings.append("backup_summary_contract_missing=%s" % contract.script)

    self_text = read_source(SCRIPTS / "check-summary-contracts.py", findings, "self")
    checks += 1
    checks += check_forbidden(findings, self_text, FORBIDDEN_MARKERS, "self")
    checks += 1
    if coverage_text.find("GUARDS: list[GuardSpec]") > coverage_text.find("for guard in GUARDS"):
        findings.append("guard_specs_after_runtime_loop")
    checks += 1
    if self_text.find("parse_guard_contracts") > self_text.find("contracts = parse_guard_contracts"):
        findings.append("parser_defined_after_use")

    status = "ok" if not findings else "failed"
    summary = "summary_contract_status=%s checks=%d findings=%d guards=%d status_keys=%d summary_contracts=%d no_summary_exceptions=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(contracts),
        status_key_expected,
        summary_expected,
        no_summary_exceptions,
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
