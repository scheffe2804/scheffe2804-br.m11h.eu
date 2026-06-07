#!/usr/bin/env bash
set -euo pipefail

# Safe restore-smoke drill for BR-Wissen backups.
# Restores only into /tmp/br-wissen-restore-* and prints only structural
# counters/markers. It never prints dump contents, secret values or restored
# credential file contents.

APP_DIR="${BR_APP_DIR:-/home/chris/web/br.m11h.eu}"
BACKUP_ENV="${BR_BACKUP_ENV:-/etc/web-backup/repos.d/m11h-br-wissen.env}"
SNAPSHOT="latest"
RUN_DB_RESTORE=0
KEEP_TARGET=0
TARGET=""
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PGVECTOR_IMAGE="pgvector/pgvector:pg16@sha256:00ba258a66dac104fd5171074a0084462a64a1369d8513f3d0a634e2f24d15bc"
DB_CONTAINER="br-wissen-restore-smoke-db-${STAMP}"
DB_VOLUME="br_wissen_restore_smoke_pgdata_${STAMP}"
DB_LOG="/tmp/br-wissen-restore-smoke-db-${STAMP}.log"
SQL_READY_WAIT="${BR_RESTORE_SQL_READY_WAIT:-15}"

usage() {
  cat <<'EOF'
Usage: restore-smoke-br-wissen.sh [--snapshot SNAPSHOT|latest] [--target /tmp/br-wissen-restore-*] [--db] [--keep-target]

Safely restores a BR-Wissen restic snapshot into an isolated /tmp path and
checks only structure, counts and markers. With --db, also restores the newest
dump into an isolated Docker container with --network none.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot)
      SNAPSHOT="${2:-}"
      shift 2
      ;;
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --db)
      RUN_DB_RESTORE=1
      shift
      ;;
    --keep-target)
      KEEP_TARGET=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$SNAPSHOT" ]]; then
  echo "restore_status=invalid_snapshot"
  exit 2
fi

if [[ -z "$TARGET" ]]; then
  TARGET="/tmp/br-wissen-restore-smoke-${STAMP}"
fi

case "$TARGET" in
  /tmp/br-wissen-restore-*) ;;
  *)
    echo "restore_status=unsafe_target"
    echo "restore_target=$TARGET"
    exit 2
    ;;
esac

cleanup() {
  if docker ps -a --format '{{.Names}}' | grep -qx "$DB_CONTAINER"; then
    docker rm -f "$DB_CONTAINER" >/dev/null 2>&1 || true
  fi
  if docker volume inspect "$DB_VOLUME" >/dev/null 2>&1; then
    docker volume rm "$DB_VOLUME" >/dev/null 2>&1 || true
  fi
  rm -f -- "$DB_LOG"
  if [[ "$KEEP_TARGET" -eq 0 ]]; then
    case "$TARGET" in
      /tmp/br-wissen-restore-*) sudo rm -rf -- "$TARGET" ;;
    esac
  fi
}
trap cleanup EXIT

if ! sudo test -f "$BACKUP_ENV"; then
  echo "restore_status=missing_backup_env"
  echo "backup_env=$BACKUP_ENV"
  exit 1
fi

if ! command -v restic >/dev/null 2>&1; then
  echo "restore_status=missing_restic"
  exit 1
fi

if [[ -e "$TARGET" ]]; then
  echo "restore_status=target_exists"
  echo "restore_target=$TARGET"
  exit 1
fi

if ! [[ "$SQL_READY_WAIT" =~ ^[0-9]+$ ]] || [[ "$SQL_READY_WAIT" -lt 1 ]]; then
  echo "restore_status=invalid_sql_ready_wait"
  echo "restore_sql_ready_wait=${SQL_READY_WAIT}"
  exit 2
fi

echo "# BR-Wissen Restore Smoke"
echo "timestamp=$STAMP"
echo "snapshot=$SNAPSHOT"
echo "restore_target=$TARGET"
echo "db_restore_requested=$RUN_DB_RESTORE"
echo "restore_sql_ready_wait=$SQL_READY_WAIT"

snapshot_json="$(sudo bash -c 'set -euo pipefail; set -a; source "$1"; set +a; restic snapshots "$2" --host m11h --tag br-wissen --json' _ "$BACKUP_ENV" "$SNAPSHOT")"
resolved_snapshot="$(RESTORE_SNAPSHOT_JSON="$snapshot_json" python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

def parse_time(value):
    if not value:
        return datetime.fromtimestamp(0, timezone.utc)
    normalized = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.fromtimestamp(0, timezone.utc)
    return parsed.astimezone(timezone.utc)

data = json.loads(os.environ["RESTORE_SNAPSHOT_JSON"])
if not isinstance(data, list) or not data:
    raise SystemExit(1)
latest = max((item for item in data if isinstance(item, dict)), key=lambda item: parse_time(item.get("time")))
snapshot_id = str(latest.get("short_id") or latest.get("id") or "")[:8]
if not snapshot_id:
    raise SystemExit(1)
print(snapshot_id)
PY
)"
echo "restore_resolved_snapshot=$resolved_snapshot"

sudo bash -c 'set -euo pipefail; set -a; source "$1"; set +a; restic restore "$2" --host m11h --tag br-wissen --target "$3"' _ "$BACKUP_ENV" "$SNAPSHOT" "$TARGET" >/dev/null

APP_RESTORE="$TARGET/home/chris/web/br.m11h.eu"
PROTOCOL_RESTORE="$TARGET/home/chris/web/diverses/betriebsrat.md"
DATA_RESTORE="$TARGET/srv/br-wissensdatenbank"
EXPORT_RESTORE="$DATA_RESTORE/exports"
BACKUP_RESTORE="$DATA_RESTORE/backups"

echo "restore_app_exists=$(sudo test -d "$APP_RESTORE" && echo yes || echo no)"
echo "restore_data_exists=$(sudo test -d "$DATA_RESTORE" && echo yes || echo no)"
restore_file_count="$(sudo find "$TARGET" -type f | wc -l | tr -d ' ')"
echo "restore_file_count=$restore_file_count"

required_files=(
  "$APP_RESTORE/docker-compose.yml"
  "$APP_RESTORE/app/main.py"
  "$APP_RESTORE/scripts/restore-smoke-br-wissen.sh"
  "$APP_RESTORE/scripts/check-answer-export-safety.py"
  "$APP_RESTORE/scripts/check-db-schema.py"
  "$APP_RESTORE/scripts/backup-br-wissen.sh"
  "$APP_RESTORE/scripts/status-br-wissen.sh"
  "$APP_RESTORE/systemd/br-wissen-healthcheck.service"
  "$APP_RESTORE/docs/READINESS.md"
  "$PROTOCOL_RESTORE"
)
missing_required=0
for path in "${required_files[@]}"; do
  if ! sudo test -f "$path"; then
    missing_required=$((missing_required + 1))
  fi
done

artifact_findings="$(sudo find "$APP_RESTORE" \( -name '*.pyc' -o -name '*.log' -o -name '.env' -o -name '*.env' -o -name '__pycache__' -o -iname '*credential*' -o -iname '*token*' -o -path '*/cloudflared/*.json' \) -print 2>/dev/null | wc -l | tr -d ' ')"
echo "restore_artifact_findings=$artifact_findings"

marker_failures=0
if sudo test -f "$PROTOCOL_RESTORE"; then
  echo "restore_protocol_exists=yes"
  echo "restore_protocol_size=$(sudo stat -c '%s' "$PROTOCOL_RESTORE")"
  if sudo grep -aFq '# betriebsrat' "$PROTOCOL_RESTORE" && sudo grep -aFq 'BR-Wissen' "$PROTOCOL_RESTORE"; then
    echo "restore_protocol_markers=yes"
  else
    echo "restore_protocol_markers=no"
    marker_failures=$((marker_failures + 1))
  fi
else
  echo "restore_protocol_exists=no"
  echo "restore_protocol_size=0"
  echo "restore_protocol_markers=no"
  missing_required=$((missing_required + 1))
fi
echo "restore_required_missing=$missing_required"

if sudo test -d "$EXPORT_RESTORE"; then
  export_dirs="$(sudo find "$EXPORT_RESTORE" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
  manifest_count="$(sudo find "$EXPORT_RESTORE" -mindepth 2 -maxdepth 2 -type f -name manifest.json | wc -l | tr -d ' ')"
else
  export_dirs=0
  manifest_count=0
fi
echo "restore_export_dirs=$export_dirs"
echo "restore_manifest_json=$manifest_count"

latest_dump=""
if sudo test -d "$BACKUP_RESTORE"; then
  latest_dump="$(sudo find "$BACKUP_RESTORE" -maxdepth 1 -type f -name 'postgres-*.sql' -printf '%T@ %p\n' | sort -rn | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')"
fi

if [[ -z "$latest_dump" ]]; then
  echo "restore_status=missing_dump"
  exit 1
fi

dump_name="$(basename "$latest_dump")"
dump_size="$(sudo stat -c '%s' "$latest_dump")"
echo "restore_latest_dump=$dump_name"
echo "restore_latest_dump_size=$dump_size"

for marker in \
  "PostgreSQL database dump" \
  "CREATE TABLE" \
  "COPY" \
  "public.audit_log" \
  "public.answers" \
  "public.answer_statements" \
  "public.answer_citations"; do
  label="$(printf '%s' "$marker" | tr ' .' '__')"
  if sudo grep -aFq "$marker" "$latest_dump"; then
    echo "dump_marker_${label}=yes"
  else
    echo "dump_marker_${label}=no"
    marker_failures=$((marker_failures + 1))
  fi
done

atomic_refs="$(sudo grep -aF 'create_cited_answer_record' "$APP_RESTORE/app/main.py" | wc -l | tr -d ' ')"
guard_refs="$(sudo grep -aF 'NOT EXISTS' "$APP_RESTORE/scripts/check-answer-export-safety.py" | wc -l | tr -d ' ')"
db_schema_refs="$(sudo grep -aF 'check-db-schema.py' "$APP_RESTORE/scripts/status-br-wissen.sh" "$APP_RESTORE/scripts/backup-br-wissen.sh" "$APP_RESTORE/systemd/br-wissen-healthcheck.service" | wc -l | tr -d ' ')"
echo "restore_atomic_helper_refs=$atomic_refs"
echo "restore_guard_not_exists_refs=$guard_refs"
echo "restore_db_schema_refs=$db_schema_refs"

if [[ "$RUN_DB_RESTORE" -eq 1 ]]; then
  docker volume create "$DB_VOLUME" >/dev/null
  docker run -d --name "$DB_CONTAINER" --network none \
    -e POSTGRES_USER=br_app \
    -e POSTGRES_PASSWORD=restore_test_password \
    -e POSTGRES_DB=br_wissen_restore \
    -v "$DB_VOLUME:/var/lib/postgresql/data" \
    "$PGVECTOR_IMAGE" >/dev/null
  ready=0
  for _ in $(seq 1 30); do
    if docker exec "$DB_CONTAINER" pg_isready -U br_app -d br_wissen_restore >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "db_restore_status=db_not_ready"
    exit 1
  fi
  sql_ready=0
  for _ in $(seq 1 "$SQL_READY_WAIT"); do
    if docker exec "$DB_CONTAINER" psql -U br_app -d br_wissen_restore -Atqc 'SELECT 1' >/dev/null 2>&1; then
      sql_ready=1
      break
    fi
    sleep 1
  done
  if [[ "$sql_ready" -ne 1 ]]; then
    echo "db_restore_status=db_sql_not_ready"
    exit 1
  fi
  sudo bash -c 'docker exec -i "$1" psql -v ON_ERROR_STOP=1 -U br_app -d br_wissen_restore < "$2"' _ "$DB_CONTAINER" "$latest_dump" >"$DB_LOG" 2>&1
  docker exec "$DB_CONTAINER" psql -U br_app -d br_wissen_restore -Atc \
    "SELECT 'restore_sources=' || count(*) FROM sources; \
     SELECT 'restore_documents=' || count(*) FROM documents; \
     SELECT 'restore_chunks=' || count(*) FROM chunks; \
     SELECT 'restore_queries=' || count(*) FROM queries; \
     SELECT 'restore_answers=' || count(*) FROM answers; \
     SELECT 'restore_answer_statements=' || count(*) FROM answer_statements; \
     SELECT 'restore_answer_citations=' || count(*) FROM answer_citations; \
     SELECT 'restore_exports=' || count(*) FROM answers WHERE html_path IS NOT NULL OR pdf_path IS NOT NULL; \
     SELECT 'restore_audit_rows=' || count(*) FROM audit_log; \
     SELECT 'restore_answers_without_statements=' || count(*) FROM answers a WHERE NOT EXISTS (SELECT 1 FROM answer_statements st WHERE st.answer_id=a.id); \
     SELECT 'restore_statements_without_citation=' || count(*) FROM answer_statements st WHERE NOT EXISTS (SELECT 1 FROM answer_citations cit WHERE cit.statement_id=st.id); \
     SELECT 'restore_vector_extension=' || count(*) FROM pg_extension WHERE extname='vector'; \
     SELECT 'restore_operational_indexes=' || count(*) FROM pg_indexes WHERE schemaname='public' AND indexname IN ('idx_sources_citation_status','idx_sources_last_checked','idx_documents_sha256','idx_chunks_document','idx_chunks_source_class','idx_answers_query','idx_answers_created_at','idx_answers_export_paths','idx_answer_statements_answer','idx_answer_citations_statement','idx_answer_citations_chunk','idx_answer_citations_source_class','idx_audit_log_action_created','idx_audit_log_object');"
  docker inspect "$DB_CONTAINER" --format 'restore_network_mode={{.HostConfig.NetworkMode}} restore_ports={{json .NetworkSettings.Ports}}'
  echo "db_restore_status=ok"
fi

if [[ "$missing_required" -ne 0 || "$artifact_findings" -ne 0 || "$marker_failures" -ne 0 || "$atomic_refs" -lt 1 || "$guard_refs" -lt 1 || "$db_schema_refs" -lt 3 ]]; then
  echo "restore_status=failed"
  exit 1
fi

if [[ "$KEEP_TARGET" -eq 1 ]]; then
  echo "restore_cleanup=kept"
else
  echo "restore_cleanup=scheduled"
fi
echo "restore_status=ok"
