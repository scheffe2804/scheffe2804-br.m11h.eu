#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
summary=0
DOCKER_BIN="/usr/bin/docker"
PYTHON_BIN="/usr/bin/python3.13"
SORT_BIN="/usr/bin/sort"

for arg in "$@"; do
  case "$arg" in
    --summary)
      summary=1
      ;;
    *)
      echo "Usage: check-image-pinning-guard.sh [--summary]" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

declare -A refs
declare -A origins

add_ref() {
  local ref="$1"
  local origin="$2"
  [[ -n "$ref" ]] || return 0
  refs["$ref"]=1
  if [[ -n "${origins[$ref]:-}" ]]; then
    origins["$ref"]="${origins[$ref]},$origin"
  else
    origins["$ref"]="$origin"
  fi
}

while IFS= read -r image; do
  add_ref "$image" "compose_config"
done < <("$DOCKER_BIN" compose config --images 2>/dev/null || true)

while IFS= read -r image; do
  add_ref "$image" "running_container"
done < <("$DOCKER_BIN" compose ps --format json 2>/dev/null | "$PYTHON_BIN" -c 'import json,sys
for line in sys.stdin:
    line=line.strip()
    if not line:
        continue
    try:
        obj=json.loads(line)
    except json.JSONDecodeError:
        continue
    image=obj.get("Image")
    if image:
        print(image)
')

while IFS= read -r from_ref; do
  add_ref "$from_ref" "dockerfile_from"
done < <("$PYTHON_BIN" - "$ROOT/app/Dockerfile" "$ROOT/worker/Dockerfile" <<'PY'
import pathlib
import sys

for file_name in sys.argv[1:]:
    path = pathlib.Path(file_name)
    if not path.exists():
        continue
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts or parts[0].upper() != "FROM":
            continue
        idx = 1
        while idx < len(parts) and parts[idx].startswith("--"):
            idx += 1
        if idx < len(parts):
            print(parts[idx])
PY
)

mapfile -t sorted_refs < <(printf '%s\n' "${!refs[@]}" | "$SORT_BIN")

local_build=0
digest_pinned=0
violations=0

if [[ "$summary" -eq 0 ]]; then
  echo "# Image Pinning Guard"
fi

for ref in "${sorted_refs[@]}"; do
  status="violation"
  if [[ "$ref" == brm11heu-* ]]; then
    status="local_build"
    local_build=$((local_build + 1))
  elif [[ "$ref" == scratch ]]; then
    status="local_build"
    local_build=$((local_build + 1))
  elif [[ "$ref" == *@sha256:* ]]; then
    status="digest_pinned"
    digest_pinned=$((digest_pinned + 1))
  else
    violations=$((violations + 1))
  fi

  if [[ "$summary" -eq 0 ]]; then
    printf 'image_pinning_guard_ref=%s origins=%s status=%s\n' "$ref" "${origins[$ref]}" "$status"
  fi
done

if [[ "$violations" -eq 0 ]]; then
  printf 'image_pinning_guard_status=ok refs=%d local_build=%d digest_pinned=%d violations=0\n' \
    "${#sorted_refs[@]}" "$local_build" "$digest_pinned"
  exit 0
fi

printf 'image_pinning_guard_status=fail refs=%d local_build=%d digest_pinned=%d violations=%d\n' \
  "${#sorted_refs[@]}" "$local_build" "$digest_pinned" "$violations"
exit 1
