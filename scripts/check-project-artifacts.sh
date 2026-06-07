#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"
summary=0

for arg in "$@"; do
  case "$arg" in
    --summary)
      summary=1
      ;;
    *)
      echo "Usage: check-project-artifacts.sh [--summary]" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

status=0
failed_total=0
checked_total=0

check_glob() {
  local label="$1"
  local pattern="$2"
  mapfile -t matches < <(compgen -G "$pattern" || true)
  checked_total=$((checked_total + 1))
  if [[ "${#matches[@]}" -gt 0 ]]; then
    failed_total=$((failed_total + ${#matches[@]}))
    if [[ "$summary" -eq 0 ]]; then
      printf 'artifact_check=%s status=failed count=%d\n' "$label" "${#matches[@]}"
      printf '  %s\n' "${matches[@]}"
    fi
    status=1
  else
    if [[ "$summary" -eq 0 ]]; then
      printf 'artifact_check=%s status=ok count=0\n' "$label"
    fi
  fi
}

check_find() {
  local label="$1"
  shift
  mapfile -t matches < <(find . "$@" -print | sed 's#^./##' | sort)
  checked_total=$((checked_total + 1))
  if [[ "${#matches[@]}" -gt 0 ]]; then
    failed_total=$((failed_total + ${#matches[@]}))
    if [[ "$summary" -eq 0 ]]; then
      printf 'artifact_check=%s status=failed count=%d\n' "$label" "${#matches[@]}"
      printf '  %s\n' "${matches[@]}"
    fi
    status=1
  else
    if [[ "$summary" -eq 0 ]]; then
      printf 'artifact_check=%s status=ok count=0\n' "$label"
    fi
  fi
}

check_glob "python_bytecode" "**/*.pyc"
check_find "python_cache_dirs" -type d -name __pycache__
check_glob "project_logs" "**/*.log"
check_glob "env_files" "**/*.env"
check_glob "root_env" ".env"
check_glob "cloudflared_credentials_json" "cloudflared/*.json"
check_glob "generic_credentials" "**/*credential*"
check_glob "generic_tokens" "**/*token*"

if [[ "$summary" -eq 1 ]]; then
  printf 'artifact_status=%s checks=%d findings=%d\n' "$([[ "$status" -eq 0 ]] && echo ok || echo failed)" "$checked_total" "$failed_total"
elif [[ "$status" -eq 0 ]]; then
  echo "status=ok"
else
  echo "status=failed"
fi

exit "$status"
