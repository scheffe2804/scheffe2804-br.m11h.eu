#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/chris/web/br.m11h.eu"
summary=0
BASH_BIN="/usr/bin/bash"
FIND_BIN="/usr/bin/find"
SORT_BIN="/usr/bin/sort"

for arg in "$@"; do
  case "$arg" in
    --summary)
      summary=1
      ;;
    *)
      echo "Usage: check-shell-syntax.sh [--summary]" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

status=0
checked=0
findings=0

check_file() {
  local path="$1"
  checked=$((checked + 1))
  if "$BASH_BIN" -n "$path" >/dev/null 2>&1; then
    if [[ "$summary" -eq 0 ]]; then
      printf 'shell_syntax_ok=%s\n' "$path"
    fi
  else
    findings=$((findings + 1))
    status=1
    if [[ "$summary" -eq 0 ]]; then
      printf 'finding=shell_syntax_error:%s\n' "$path"
    fi
  fi
}

is_shell_script() {
  local path="$1"
  local first_line=""
  IFS= read -r first_line < "$path" || true
  case "$path" in
    *.sh)
      return 0
      ;;
  esac
  case "$first_line" in
    '#!'*'/sh'|'#!'*'/bash'|'#!'*'env sh'|'#!'*'env bash')
      return 0
      ;;
  esac
  return 1
}

while IFS= read -r path; do
  if ! is_shell_script "$path"; then
    continue
  fi
  check_file "$path"
done < <("$FIND_BIN" scripts -maxdepth 1 -type f \( -name '*.sh' -o -perm -u=x \) -print | "$SORT_BIN")

if [[ "$summary" -eq 1 ]]; then
  printf 'shell_syntax_status=%s checks=%d findings=%d checked_shell_files=%d\n' "$([[ "$status" -eq 0 ]] && echo ok || echo failed)" "$checked" "$findings" "$checked"
else
  printf 'shell_syntax_status=%s\n' "$([[ "$status" -eq 0 ]] && echo ok || echo failed)"
  printf 'checks=%d\n' "$checked"
  printf 'findings=%d\n' "$findings"
  printf 'checked_shell_files=%d\n' "$checked"
fi

exit "$status"
