#!/usr/bin/env python3
"""Read-only audit-trail guard for BR-Wissen.

The guard checks audit coverage and consistency using counters only. It never
prints answer text, source content, secret values or audit detail JSON.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


ROOT = Path("/home/chris/web/br.m11h.eu")

# Historical tolerated gaps from early bootstrap/manual test exports before the
# audit guard existed. Keep this list explicit so new gaps still fail.
LEGACY_EXPORT_AUDIT_GAPS = {
    "a-src-test-0784dcd7",
    "a-tariff-20260529082203-7ec7dbbf",
    "a-tariff-20260529091650-aac06058",
    "a-tariff-20260529092158-6be85203",
    "a-tariff-20260529093429-27636d11",
    "a-struct-20260529093429-d12bc7bb",
    "a-struct-20260529093730-8d61cc62",
    "a-tariff-20260529093731-e5341f50",
}

LEGACY_ANSWER_CREATE_AUDIT_GAPS = {"a-src-test-0784dcd7"}


def run_sql(sql: str) -> tuple[int, list[str]]:
    proc = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-U", "br_app", "-d", "br_wissen", "-Atc", sql],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode, proc.stdout.splitlines()


def scalar_metrics() -> dict[str, int]:
    sql = """
SELECT 'audit_rows=' || count(*) FROM audit_log;
SELECT 'audit_actor_empty=' || count(*) FROM audit_log WHERE coalesce(actor,'')='';
SELECT 'audit_action_empty=' || count(*) FROM audit_log WHERE coalesce(action,'')='';
SELECT 'audit_object_uid_empty=' || count(*) FROM audit_log WHERE coalesce(object_uid,'')='';
SELECT 'audit_future_rows=' || count(*) FROM audit_log WHERE created_at > now() + interval '5 minutes';
SELECT 'audit_unknown_actions=' || count(*) FROM audit_log WHERE action NOT IN (
  'source_technical_approve','source_block','source_unblock','source_unblock_and_approve','source_approve_all_evg','source_approve_all_evg_cli',
  'draft_export_create','source_snippet_answer_create','structured_source_answer_create','structured_tariff_answer_create','validated_answer_export','validated_answer_export_cli','export_manifest_backfill'
);
SELECT 'answer_create_audit_rows=' || count(*) FROM audit_log WHERE object_type='answer' AND action IN ('source_snippet_answer_create','structured_source_answer_create','structured_tariff_answer_create');
SELECT 'validated_export_audit_rows=' || count(*) FROM audit_log WHERE object_type='answer' AND action IN ('validated_answer_export','validated_answer_export_cli');
SELECT 'manifest_backfill_audit_rows=' || count(*) FROM audit_log WHERE action='export_manifest_backfill';
"""
    code, lines = run_sql(sql)
    metrics: dict[str, int] = {}
    if code != 0:
        metrics["audit_db_query_failed"] = 1
        return metrics
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            metrics[key] = int(value)
        except ValueError:
            metrics[key] = -1
    return metrics


def uid_list(sql: str) -> list[str]:
    code, lines = run_sql(sql)
    if code != 0:
        return ["__query_failed__"]
    return [line.strip() for line in lines if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen audit trail")
    parser.add_argument("--summary", action="store_true", help="print one compact status line")
    args = parser.parse_args()

    metrics = scalar_metrics()
    findings: list[str] = []
    checks = len(metrics)
    for key in ["audit_db_query_failed", "audit_actor_empty", "audit_action_empty", "audit_object_uid_empty", "audit_future_rows", "audit_unknown_actions"]:
        if metrics.get(key, 0) != 0:
            findings.append("%s=%s" % (key, metrics.get(key)))

    missing_create = set(uid_list(
        """
        SELECT a.answer_uid
        FROM answers a
        WHERE NOT EXISTS (
          SELECT 1 FROM audit_log l
          WHERE l.object_type='answer' AND l.object_uid=a.answer_uid
            AND l.action IN ('source_snippet_answer_create','structured_source_answer_create','structured_tariff_answer_create')
        )
        ORDER BY a.created_at
        """
    ))
    checks += 1
    unexpected_missing_create = sorted(missing_create - LEGACY_ANSWER_CREATE_AUDIT_GAPS)
    if unexpected_missing_create:
        findings.append("unexpected answer create audit gaps=%d" % len(unexpected_missing_create))

    missing_exports = set(uid_list(
        """
        SELECT a.answer_uid
        FROM answers a
        WHERE coalesce(a.html_path,'')<>'' AND coalesce(a.pdf_path,'')<>''
          AND NOT EXISTS (
            SELECT 1 FROM audit_log l
            WHERE l.object_type='answer' AND l.object_uid=a.answer_uid
              AND l.action IN ('validated_answer_export','validated_answer_export_cli')
          )
        ORDER BY a.created_at
        """
    ))
    checks += 1
    unexpected_missing_exports = sorted(missing_exports - LEGACY_EXPORT_AUDIT_GAPS)
    if unexpected_missing_exports:
        findings.append("unexpected export audit gaps=%d" % len(unexpected_missing_exports))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "audit_trail_status=%s checks=%d findings=%d audit_rows=%s answer_create_audit_rows=%s export_audit_rows=%s legacy_export_gaps=%d"
            % (
                status,
                checks,
                len(findings),
                metrics.get("audit_rows", 0),
                metrics.get("answer_create_audit_rows", 0),
                metrics.get("validated_export_audit_rows", 0),
                len(missing_exports & LEGACY_EXPORT_AUDIT_GAPS),
            )
        )
    else:
        print("audit_trail_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        for key in sorted(metrics):
            print("%s=%s" % (key, metrics[key]))
        print("legacy_answer_create_gaps=%d" % len(missing_create & LEGACY_ANSWER_CREATE_AUDIT_GAPS))
        print("unexpected_answer_create_gaps=%d" % len(unexpected_missing_create))
        print("legacy_export_gaps=%d" % len(missing_exports & LEGACY_EXPORT_AUDIT_GAPS))
        print("unexpected_export_gaps=%d" % len(unexpected_missing_exports))
        for finding in findings:
            print("finding=%s" % finding)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
