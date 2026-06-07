#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_BIN="/usr/bin/docker"
PYTHON_BIN="/usr/bin/python3.13"
SORT_BIN="/usr/bin/sort"
TIMEOUT_BIN="/usr/bin/timeout"
summary=0
remote=1

for arg in "$@"; do
  case "$arg" in
    --summary)
      summary=1
      ;;
    --no-remote)
      remote=0
      ;;
    *)
      echo "Usage: check-image-pinning-readiness.sh [--summary] [--no-remote]" >&2
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

local_build=0
digest_pinned=0
tag_candidates=0
latest_candidates=0
unversioned_candidates=0
remote_ok=0
remote_missing=0
remote_expected=0
unavailable_refs=()

display_ref() {
  local ref="$1"
  ref="${ref%@sha256:*}"
  printf '%s' "$ref"
}

if [[ "$summary" -eq 0 ]]; then
  echo "# Image Pinning Readiness"
  echo "mode=read_only"
  if [[ "$remote" -eq 1 ]]; then
    echo "remote_registry_lookup=enabled"
  else
    echo "remote_registry_lookup=disabled"
  fi
fi

mapfile -t sorted_refs < <(printf '%s\n' "${!refs[@]}" | "$SORT_BIN")

for ref in "${sorted_refs[@]}"; do
  classification="tag_pin_candidate"
  if [[ "$ref" == brm11heu-* ]]; then
    classification="local_build"
    local_build=$((local_build + 1))
  elif [[ "$ref" == *@sha256:* ]]; then
    classification="digest_pinned"
    digest_pinned=$((digest_pinned + 1))
  elif [[ "$ref" == *:latest ]]; then
    classification="latest_pin_candidate"
    latest_candidates=$((latest_candidates + 1))
    tag_candidates=$((tag_candidates + 1))
  elif [[ "$ref" != *:* ]]; then
    classification="unversioned_pin_candidate"
    unversioned_candidates=$((unversioned_candidates + 1))
    tag_candidates=$((tag_candidates + 1))
  else
    tag_candidates=$((tag_candidates + 1))
  fi

  if [[ "$summary" -eq 0 ]]; then
    printf 'ref=%s origins=%s classification=%s\n' "$ref" "${origins[$ref]}" "$classification"
  fi

  if [[ "$remote" -eq 1 && "$classification" != "local_build" ]]; then
    remote_expected=$((remote_expected + 1))
    inspect_json="$($TIMEOUT_BIN 45 "$DOCKER_BIN" buildx imagetools inspect "$ref" --format '{{json .}}' 2>/dev/null || true)"
    if [[ -n "$inspect_json" ]]; then
      remote_ok=$((remote_ok + 1))
      if [[ "$summary" -eq 0 ]]; then
        printf '%s' "$inspect_json" | "$PYTHON_BIN" -c 'import json,sys
ref=sys.argv[1]
data=json.load(sys.stdin)
manifest=data.get("manifest") or {}
index_digest=manifest.get("digest") or "unknown"
amd64_digest="unknown"
arm64_digest="unknown"
for item in manifest.get("manifests") or []:
    platform=item.get("platform") or {}
    os_name=platform.get("os")
    arch=platform.get("architecture")
    digest=item.get("digest") or "unknown"
    if os_name == "linux" and arch == "amd64":
        amd64_digest=digest
    if os_name == "linux" and arch == "arm64":
        arm64_digest=digest
image=(data.get("image") or {}).get("linux/amd64") or {}
config=image.get("config") or {}
labels=config.get("Labels") or {}
version=(labels.get("org.opencontainers.image.version") or labels.get("CI_GIT_COMMIT") or "unknown")
created=image.get("created") or "unknown"
print("remote_ref=%s remote_status=ok index_digest=%s linux_amd64_digest=%s linux_arm64_digest=%s version_or_revision=%s amd64_created=%s" % (ref, index_digest, amd64_digest, arm64_digest, version, created))
' "$ref"
      fi
    else
      remote_missing=$((remote_missing + 1))
      unavailable_refs+=("$(display_ref "$ref")")
      if [[ "$summary" -eq 0 ]]; then
        printf 'remote_ref=%s remote_status=unavailable\n' "$ref"
      fi
    fi
  fi
done

image_pinning_readiness_status="ok"
if [[ "${#sorted_refs[@]}" -eq 0 ]]; then
  image_pinning_readiness_status="failed"
elif [[ "$tag_candidates" -gt 0 || "$latest_candidates" -gt 0 || "$unversioned_candidates" -gt 0 || "$remote_missing" -gt 0 ]]; then
  image_pinning_readiness_status="warning"
fi

remote_coverage=0
if [[ "$remote_expected" -gt 0 ]]; then
  remote_coverage=$((remote_ok * 100 / remote_expected))
fi
remote_unavailable_refs="none"
if [[ "${#unavailable_refs[@]}" -gt 0 ]]; then
  remote_unavailable_refs="$(IFS=,; printf '%s' "${unavailable_refs[*]}")"
fi

printf 'image_pinning_readiness_status=%s refs=%d local_build=%d digest_pinned=%d tag_pin_candidates=%d latest_pin_candidates=%d unversioned_pin_candidates=%d remote_expected=%d remote_ok=%d remote_unavailable=%d remote_coverage_pct=%d remote_unavailable_refs=%s\n' \
  "$image_pinning_readiness_status" \
  "${#sorted_refs[@]}" "$local_build" "$digest_pinned" "$tag_candidates" "$latest_candidates" "$unversioned_candidates" "$remote_expected" "$remote_ok" "$remote_missing" "$remote_coverage" "$remote_unavailable_refs"

if [[ "$image_pinning_readiness_status" == "failed" ]]; then
  exit 1
fi
exit 0
