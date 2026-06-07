#!/usr/bin/env python3
"""Read-only source hardening coverage guard for BR-Wissen check scripts.

The guard validates that every project `scripts/check-*` helper is either covered
by a documented source-hardening guard, is itself a source-hardening/governance
guard, or is explicitly documented as a non-integrated legacy/helper exception.
It only reads project source files; it does not run guards, Docker, systemctl,
backups, restores, imports, regressions or database queries and never reads
secrets, dumps, logs, answers, exports or source documents.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


ROOT = Path(os.getenv("BR_APP_DIR", "/home/chris/web/br.m11h.eu"))
SCRIPTS = ROOT / "scripts"


COVERAGE_GROUPS: dict[str, dict[str, list[str] | str]] = {
    "core_source_hardening": {
        "guard": "check-core-source-hardening.py",
        "targets": [
            "check-host-context.py",
            "check-time-sync.py",
            "check-compose-services.py",
            "check-privilege-policy.py",
            "check-privilege-risk-review.py",
            "check-privilege-least-privilege-plan.py",
            "check-privilege-remediation-gate.py",
            "check-privilege-no-sudoers-change.py",
            "check-project-artifacts.sh",
            "check-runtime-log-markers.sh",
        ],
    },
    "container_source_hardening": {
        "guard": "check-container-source-hardening.py",
        "targets": [
            "check-container-hardening.py",
            "check-container-images.sh",
            "check-image-pinning-guard.sh",
            "check-image-pinning-readiness.sh",
        ],
    },
    "network_source_hardening": {
        "guard": "check-network-source-hardening.py",
        "targets": [
            "check-network-exposure.py",
            "check-public-dns-exposure.py",
            "check-public-dns-multiresolver.py",
            "check-public-dns-authoritative.py",
            "check-public-dns-caa.py",
            "check-direct-origin-bypass.py",
            "check-direct-origin-port-exposure.py",
            "check-host-udp-exposure.py",
            "check-host-firewall-br-ports.py",
            "check-host-nft-br-ports.py",
            "check-network-policy-consistency.py",
            "check-network-policy-runtime-env.py",
            "check-network-policy-runtime-summary.py",
        ],
    },
    "access_runtime_source_hardening": {
        "guard": "check-access-runtime-source-hardening.py",
        "targets": [
            "check-runtime-http-security.py",
            "check-external-access-surface.py",
            "check-external-cookie-security.py",
            "check-tls-certificate.py",
            "check-app-auth-surface.py",
        ],
    },
    "import_source_hardening": {
        "guard": "check-import-source-hardening.py",
        "targets": ["check-import-pipeline.py"],
    },
    "data_integrity_source_hardening": {
        "guard": "check-data-integrity-source-hardening.py",
        "targets": [
            "check-answer-export-safety.py",
            "check-audit-trail.py",
            "check-db-schema.py",
        ],
    },
    "freshness_source_hardening": {
        "guard": "check-freshness-source-hardening.py",
        "targets": ["check-backup-scope.py", "check-backup-runtime-policy.py", "check-restic-repository-check.py", "check-restore-runtime-policy.py", "check-backup-freshness.py", "check-restore-freshness.py"],
    },
    "storage_source_hardening": {
        "guard": "check-storage-source-hardening.py",
        "targets": ["check-storage-permissions.py", "check-storage-capacity.py"],
    },
    "regression_source_hardening": {
        "guard": "check-regression-source-hardening.py",
        "targets": ["check-regression-freshness.py"],
    },
    "meta_source_hardening": {
        "guard": "check-meta-source-hardening.py",
        "targets": [
            "check-guard-coverage.py",
            "check-readiness-doc.py",
            "check-python-syntax.sh",
            "check-shell-syntax.sh",
            "check-systemd-units.sh",
            "check-systemd-loaded-units.py",
            "check-script-permission-policy.py",
            "check-doc-source-hardening.py",
            "check-source-hardening-coverage.py",
            "check-summary-contracts.py",
            "check-surface-registry.py",
            "check-guard-registry-integrity.py",
            "check-protocol-integrity.py",
            "check-git-remote-readiness.py",
        ],
    },
}


SOURCE_HARDENING_GUARDS = sorted(
    {
        "check-access-runtime-source-hardening.py",
        "check-backup-source-hardening.py",
        "check-compose-source-hardening.py",
        "check-container-source-hardening.py",
        "check-core-source-hardening.py",
        "check-data-integrity-source-hardening.py",
        "check-doc-source-hardening.py",
        "check-freshness-source-hardening.py",
        "check-healthcheck-source-hardening.py",
        "check-import-source-hardening.py",
        "check-meta-source-hardening.py",
        "check-network-source-hardening.py",
        "check-operational-wrapper-source-hardening.py",
        "check-regression-source-hardening.py",
        "check-restore-source-hardening.py",
        "check-source-hardening-coverage.py",
        "check-summary-contracts.py",
        "check-surface-registry.py",
        "check-guard-registry-integrity.py",
        "check-protocol-integrity.py",
        "check-git-remote-readiness.py",
        "check-status-source-hardening.py",
        "check-storage-source-hardening.py",
        "check-systemd-source-hardening.py",
    }
)


EXPLICIT_EXCEPTIONS = {
    "check-cloudflare-staging-pattern.sh": "legacy_manual_helper_not_in_status_backup_or_healthcheck",
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


def check_forbidden(findings: list[str], text: str, markers: list[str], prefix: str) -> int:
    checks = 0
    for marker in markers:
        checks += 1
        if marker in text:
            findings.append("%s_forbidden=%s" % (prefix, safe(marker)))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen source-hardening coverage inventory")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    checks = 0
    findings: list[str] = []

    actual_scripts = sorted(path.name for path in SCRIPTS.glob("check-*") if path.is_file() or path.is_symlink())
    covered_targets: set[str] = set()
    referenced_guards: set[str] = set()

    for group, spec in COVERAGE_GROUPS.items():
        guard = str(spec["guard"])
        targets = list(spec["targets"])  # type: ignore[arg-type]
        guard_path = SCRIPTS / guard
        guard_text = read_source(guard_path, findings, group)
        checks += 1
        referenced_guards.add(guard)
        if guard not in SOURCE_HARDENING_GUARDS:
            findings.append("coverage_group_guard_not_declared=%s" % guard)
        for target in targets:
            checks += 3
            covered_targets.add(target)
            if target not in actual_scripts:
                findings.append("covered_target_missing=%s" % target)
            if target not in guard_text:
                findings.append("guard_missing_target_reference_%s=%s" % (group, target))
            if target.endswith("-source-hardening.py") and target != "check-doc-source-hardening.py" and target != "check-source-hardening-coverage.py":
                findings.append("source_guard_listed_as_target=%s" % target)

    grouped_source_guards = referenced_guards | (covered_targets & set(SOURCE_HARDENING_GUARDS))

    for guard in SOURCE_HARDENING_GUARDS:
        checks += 2
        if guard not in actual_scripts:
            findings.append("source_guard_missing=%s" % guard)
        if guard not in grouped_source_guards and guard not in {"check-backup-source-hardening.py", "check-compose-source-hardening.py", "check-healthcheck-source-hardening.py", "check-operational-wrapper-source-hardening.py", "check-restore-source-hardening.py", "check-status-source-hardening.py", "check-storage-source-hardening.py", "check-systemd-source-hardening.py"}:
            findings.append("source_guard_not_in_coverage_groups=%s" % guard)

    accounted = covered_targets | set(SOURCE_HARDENING_GUARDS) | set(EXPLICIT_EXCEPTIONS)
    for script in actual_scripts:
        checks += 1
        if script not in accounted:
            findings.append("unaccounted_check_script=%s" % script)

    for script in sorted(accounted):
        checks += 1
        if script not in actual_scripts:
            findings.append("accounted_script_missing=%s" % script)

    checks += 1
    duplicate_targets = sorted(target for target in covered_targets if sum(target in list(spec["targets"]) for spec in COVERAGE_GROUPS.values()) > 1)  # type: ignore[arg-type]
    if duplicate_targets:
        findings.append("duplicate_covered_targets=%s" % ",".join(duplicate_targets))

    checks += 1
    if "check-cloudflare-staging-pattern.sh" not in EXPLICIT_EXCEPTIONS:
        findings.append("cloudflare_staging_exception_missing")

    self_text = read_source(SCRIPTS / "check-source-hardening-coverage.py", findings, "self")
    checks += 1
    checks += check_forbidden(findings, self_text, FORBIDDEN_MARKERS, "self")
    checks += 1
    if self_text.find("COVERAGE_GROUPS") > self_text.find("for group, spec in COVERAGE_GROUPS.items()"):
        findings.append("coverage_groups_after_loop")

    status = "ok" if not findings else "failed"
    summary = "source_hardening_coverage_status=%s checks=%d findings=%d check_scripts=%d covered_targets=%d source_guards=%d exceptions=%d coverage_groups=%d forbidden_markers=%d" % (
        status,
        checks,
        len(findings),
        len(actual_scripts),
        len(covered_targets),
        len(SOURCE_HARDENING_GUARDS),
        len(EXPLICIT_EXCEPTIONS),
        len(COVERAGE_GROUPS),
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
