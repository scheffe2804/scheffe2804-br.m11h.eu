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
      echo "Usage: check-container-images.sh [--summary]" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

mapfile -t compose_images < <(
  {
    "$DOCKER_BIN" compose config --images
    "$DOCKER_BIN" compose ps --format json | "$PYTHON_BIN" -c 'import json,sys
for line in sys.stdin:
    line=line.strip()
    if not line:
        continue
    obj=json.loads(line)
    image=obj.get("Image")
    if image:
        print(image)
'
  } | "$SORT_BIN" -u
)
unversioned=0
latest=0
digest_pinned=0
tag_pinned=0
local_build=0

if [[ "$summary" -eq 0 ]]; then
  echo "# Container Image Inventory"
fi

for image in "${compose_images[@]}"; do
  status="tag_pinned"
  if [[ "$image" == brm11heu-* ]]; then
    status="local_build"
    local_build=$((local_build + 1))
  elif [[ "$image" == *@sha256:* ]]; then
    status="digest_pinned"
    digest_pinned=$((digest_pinned + 1))
  elif [[ "$image" == *:latest ]]; then
    status="latest_tag"
    latest=$((latest + 1))
  elif [[ "$image" != *:* ]]; then
    status="unversioned_tag"
    unversioned=$((unversioned + 1))
  else
    tag_pinned=$((tag_pinned + 1))
  fi

  if [[ "$summary" -eq 0 ]]; then
    image_id="unknown"
    created="unknown"
    if inspect=$("$DOCKER_BIN" image inspect "$image" --format '{{.Id}} {{.Created}}' 2>/dev/null); then
      image_id="${inspect%% *}"
      created="${inspect#* }"
    fi
    printf 'image=%s status=%s id=%s created=%s\n' "$image" "$status" "$image_id" "$created"
  fi
done

container_image_status="ok"
if [[ "${#compose_images[@]}" -eq 0 ]]; then
  container_image_status="failed"
elif [[ "$tag_pinned" -gt 0 || "$latest" -gt 0 || "$unversioned" -gt 0 ]]; then
  container_image_status="warning"
fi

printf 'container_image_status=%s images=%d local_build=%d tag_pinned=%d digest_pinned=%d latest=%d unversioned=%d\n' \
  "$container_image_status" \
  "${#compose_images[@]}" "$local_build" "$tag_pinned" "$digest_pinned" "$latest" "$unversioned"

if [[ "$container_image_status" == "failed" ]]; then
  exit 1
fi
exit 0
