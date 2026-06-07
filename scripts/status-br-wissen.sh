#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"
HOST_CONTEXT="/etc/opencode-host-context"
DATE_BIN="/usr/bin/date"
HOSTNAME_BIN="/usr/bin/hostname"
GREP_BIN="/usr/bin/grep"
TAILSCALE_BIN="/usr/bin/tailscale"
DOCKER_BIN="/usr/bin/docker"
SYSTEMCTL_BIN="/usr/bin/systemctl"
PYTHON_BIN="/usr/bin/python3.13"

run_regressions=0
verbose_health=0
show_duplicates=0
show_image_pinning=0
for arg in "$@"; do
  case "$arg" in
    --with-regressions)
      run_regressions=1
      ;;
    --verbose-health)
      verbose_health=1
      ;;
    --duplicates)
      show_duplicates=1
      ;;
    --image-pinning)
      show_image_pinning=1
      ;;
    *)
      echo "Usage: status-br-wissen.sh [--with-regressions] [--verbose-health] [--duplicates] [--image-pinning]" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

echo "# BR Wissensdatenbank Status"
echo "timestamp_utc=$($DATE_BIN -u +%Y-%m-%dT%H:%M:%SZ)"
echo

echo "## Host"
echo "hostname=$($HOSTNAME_BIN)"
if [[ -f "$HOST_CONTEXT" ]]; then
  "$GREP_BIN" -E '^(HOST_ROLE|HOST_FQDN|THIS_SERVER|PUBLIC_IPV4|TAILSCALE_IPV4|M00H_IS_DIFFERENT_SERVER)=' "$HOST_CONTEXT" || true
fi
if [[ -x "$TAILSCALE_BIN" ]]; then
  echo "tailscale_ipv4=$($TAILSCALE_BIN ip -4 2>/dev/null || true)"
fi
echo

echo "## Host-Kontext-Guard"
scripts/check-host-context.py --summary
echo

echo "## Time-Sync-Guard"
scripts/check-time-sync.py --summary
echo

echo "## Docker Compose"
"$DOCKER_BIN" compose ps
echo

echo "## Compose-Service-Guard"
scripts/check-compose-services.py --summary
echo

echo "## Privilege-Policy-Guard"
scripts/check-privilege-policy.py --summary
echo

echo "## Privilege-Risk-Review-Guard"
scripts/check-privilege-risk-review.py --summary --allow-accepted-risk
echo

echo "## Privilege-Least-Privilege-Plan-Guard"
scripts/check-privilege-least-privilege-plan.py --summary
echo

echo "## Privilege-Remediation-Gate-Guard"
scripts/check-privilege-remediation-gate.py --summary
echo

echo "## Privilege-No-Sudoers-Change-Guard"
scripts/check-privilege-no-sudoers-change.py --summary
echo

echo "## Core-Source-Hardening"
scripts/check-core-source-hardening.py --summary
echo

echo "## Container-Hardening"
scripts/check-container-hardening.py --summary
echo

echo "## Container-Source-Hardening"
scripts/check-container-source-hardening.py --summary
echo

echo "## Compose-Source-Hardening"
scripts/check-compose-source-hardening.py --summary
echo

echo "## Network-Source-Hardening"
scripts/check-network-source-hardening.py --summary
echo

echo "## Network-Exposure-Guard"
scripts/check-network-exposure.py --summary
echo

echo "## Public-DNS-Exposure-Guard"
scripts/check-public-dns-exposure.py --summary
echo

echo "## Public-DNS-Multiresolver-Guard"
scripts/check-public-dns-multiresolver.py --summary
echo

echo "## Public-DNS-Authoritative-Guard"
scripts/check-public-dns-authoritative.py --summary
echo

echo "## Public-DNS-CAA-Guard"
scripts/check-public-dns-caa.py --summary
echo

echo "## Direct-Origin-Bypass-Guard"
scripts/check-direct-origin-bypass.py --summary
echo

echo "## Direct-Origin-Port-Exposure-Guard"
scripts/check-direct-origin-port-exposure.py --summary
echo

echo "## Host-UDP-Exposure-Guard"
scripts/check-host-udp-exposure.py --summary
echo

echo "## Host-Firewall-BR-Ports-Guard"
scripts/check-host-firewall-br-ports.py --summary
echo

echo "## Host-NFT-BR-Ports-Guard"
scripts/check-host-nft-br-ports.py --summary
echo

echo "## Network-Policy-Consistency-Guard"
scripts/check-network-policy-consistency.py --summary
echo

echo "## Network-Policy-Runtime-Env-Guard"
scripts/check-network-policy-runtime-env.py --summary
echo

echo "## Network-Policy-Runtime-Summary-Guard"
scripts/check-network-policy-runtime-summary.py --summary
echo

echo "## Systemd Timer"
"$SYSTEMCTL_BIN" is-active br-wissen-healthcheck.timer br-wissen-backup.timer br-wissen-import-bag.timer br-wissen-import-m00h.timer br-wissen-restore-smoke.timer
"$SYSTEMCTL_BIN" list-timers br-wissen-healthcheck.timer br-wissen-backup.timer br-wissen-import-bag.timer br-wissen-import-m00h.timer br-wissen-restore-smoke.timer --no-pager
scripts/check-systemd-units.sh --summary
echo

echo "## Systemd-Source-Hardening"
scripts/check-systemd-source-hardening.py --summary
echo

echo "## Status-Source-Hardening"
scripts/check-status-source-hardening.py --summary
echo

echo "## Healthcheck-Source-Hardening"
scripts/check-healthcheck-source-hardening.py --summary
echo

echo "## Operational-Wrapper-Source-Hardening"
scripts/check-operational-wrapper-source-hardening.py --summary
echo

echo "## Guard-Coverage-Guard"
scripts/check-guard-coverage.py --summary
echo

echo "## Meta-Source-Hardening"
scripts/check-meta-source-hardening.py --summary
echo

echo "## Doku-Source-Hardening"
scripts/check-doc-source-hardening.py --summary
echo

echo "## Source-Hardening-Coverage"
scripts/check-source-hardening-coverage.py --summary
echo

echo "## Summary-Contract-Guard"
scripts/check-summary-contracts.py --summary
echo

echo "## Surface-Registry-Guard"
scripts/check-surface-registry.py --summary
echo

echo "## Guard-Registry-Integrity"
scripts/check-guard-registry-integrity.py --summary
echo

echo "## Protocol-Integrity-Guard"
scripts/check-protocol-integrity.py --summary
echo

echo "## Git-Remote-Readiness"
scripts/check-git-remote-readiness.py --summary
echo

echo "## Python-Syntax-Guard"
scripts/check-python-syntax.sh --summary
echo

echo "## Shell-Syntax-Guard"
scripts/check-shell-syntax.sh --summary
echo

echo "## App Healthcheck"
if [[ "$verbose_health" -eq 1 ]]; then
  scripts/healthcheck-br-wissen-docker.sh
else
  health_json="$(scripts/healthcheck-br-wissen-docker.sh --summary)"
  HEALTH_JSON="$health_json" "$PYTHON_BIN" - <<'PY'
import json
import os

data = json.loads(os.environ["HEALTH_JSON"])
print("health_status=%s" % data.get("status"))
print("failures=%d" % len(data.get("failures") or []))
counts = data.get("counts") or {}
for key in ["sources", "documents", "chunks", "queries", "answers"]:
    print("%s=%s" % (key, counts.get(key)))
print("approved_chunkless_sources=%d" % int(data.get("approved_chunkless_sources") or 0))
repaired = data.get("repaired_ocr_integrity") or {}
print("repaired_ocr_documents=%s" % repaired.get("repaired_documents"))
print("repaired_ocr_without_chunks=%s" % repaired.get("repaired_without_chunks"))
print("repaired_ocr_missing_text_paths=%s" % repaired.get("missing_text_paths"))
exports = data.get("exports") or {}
print("exports_html=%s" % exports.get("html_exports"))
print("exports_pdf=%s" % exports.get("pdf_exports"))
print("duplicate_document_sha_groups=%d" % int(data.get("duplicate_document_sha_groups") or 0))
integrity = data.get("source_integrity") or {}
integrity_counts = integrity.get("counts") or {}
print("source_integrity_invalid_status=%d" % int(integrity.get("invalid_status") or 0))
print("source_integrity_invalid_class=%d" % int(integrity.get("invalid_class") or 0))
print("source_missing_paths=%d" % int(integrity.get("missing_path_count") or 0))
print("source_paths_outside_storage=%d" % int(integrity.get("outside_storage_path_count") or 0))
for key in ["source_sha_missing", "document_sha_missing", "sources_without_documents", "chunk_class_mismatches", "recent_gelb_answer_citations"]:
    print("%s=%s" % (key, integrity_counts.get(key)))
PY
fi
echo

echo "## Projektartefakte"
scripts/check-project-artifacts.sh
echo

echo "## Runtime-Log-Marker"
scripts/check-runtime-log-markers.sh
echo

echo "## Access-Runtime-Source-Hardening"
scripts/check-access-runtime-source-hardening.py --summary
echo

echo "## Runtime-HTTP-Security"
scripts/check-runtime-http-security.py --summary
echo

echo "## External-Access-Surface"
scripts/check-external-access-surface.py --summary
echo

echo "## External-Cookie-Security"
scripts/check-external-cookie-security.py --summary
echo

echo "## TLS-Certificate-Guard"
scripts/check-tls-certificate.py --summary
echo

echo "## App-Auth-Surface"
scripts/check-app-auth-surface.py --summary
echo

echo "## Import-Pipeline-Guard"
scripts/check-import-pipeline.py --summary
echo

echo "## Import-Source-Hardening"
scripts/check-import-source-hardening.py --summary
echo

echo "## Answer-Export-Safety"
scripts/check-answer-export-safety.py --summary
echo

echo "## Data-Integrity-Source-Hardening"
scripts/check-data-integrity-source-hardening.py --summary
echo

echo "## Audit-Trail"
scripts/check-audit-trail.py --summary
echo

echo "## DB-Schema"
scripts/check-db-schema.py --summary
echo

echo "## Backup-Scope-Guard"
scripts/check-backup-scope.py --summary
echo

echo "## Backup-Runtime-Policy-Guard"
scripts/check-backup-runtime-policy.py --summary
echo

echo "## Restic-Repository-Check-Freshness"
scripts/check-restic-repository-check.py --summary
echo

echo "## Backup-Freshness"
scripts/check-backup-freshness.py --summary
echo

echo "## Backup-Source-Hardening"
scripts/check-backup-source-hardening.py --summary
echo

echo "## Restore-Source-Hardening"
scripts/check-restore-source-hardening.py --summary
echo

echo "## Restore-Runtime-Policy-Guard"
scripts/check-restore-runtime-policy.py --summary
echo

echo "## Storage-Permissions"
scripts/check-storage-permissions.py --summary
echo

echo "## Storage-Capacity"
scripts/check-storage-capacity.py --summary
echo

echo "## Restore-Freshness"
scripts/check-restore-freshness.py --summary
echo

echo "## Freshness-Source-Hardening"
scripts/check-freshness-source-hardening.py --summary
echo

echo "## Storage-Source-Hardening"
scripts/check-storage-source-hardening.py --summary
echo

echo "## Readiness-Doku"
scripts/check-readiness-doc.py --summary
echo

echo "## Regression-Freshness"
scripts/check-regression-freshness.py --summary
echo

echo "## Regression-Source-Hardening"
scripts/check-regression-source-hardening.py --summary
echo

echo "## Container-Images"
scripts/check-container-images.sh --summary
echo

echo "## Image-Pinning-Guard"
scripts/check-image-pinning-guard.sh --summary
echo

echo "## Image-Pinning-Readiness"
scripts/check-image-pinning-readiness.sh --summary --no-remote
echo

if [[ "$show_image_pinning" -eq 1 ]]; then
  echo "## Image-Pinning-Readiness-Remote"
  scripts/check-image-pinning-readiness.sh --summary
  echo
fi

if [[ "$show_duplicates" -eq 1 ]]; then
  echo "## Duplicate Document SHA Report"
  scripts/report-duplicate-documents-docker.sh
  echo
fi

if [[ "$run_regressions" -eq 1 ]]; then
  echo "## Regressionen"
  scripts/run-regressions-docker.sh
  echo
else
  echo "## Regressionen"
  echo "skipped=true"
  echo "hint=Run with --with-regressions to create fresh regression answers and exports."
  echo
fi

echo "status=ok"
