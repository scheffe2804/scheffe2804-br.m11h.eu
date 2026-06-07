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
      echo "Usage: check-python-syntax.sh [--summary]" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

PYTHON_SYNTAX_SUMMARY="$summary" python3 - <<'PY'
import ast
import os
from pathlib import Path

root = Path(".").resolve()
scan_roots = [root / "app", root / "scripts", root / "worker"]
excluded_parts = {"__pycache__", ".pytest_cache", ".venv", "node_modules", "tmp"}
summary = os.environ.get("PYTHON_SYNTAX_SUMMARY") == "1"

checked = 0
findings = []
for scan_root in scan_roots:
    if not scan_root.exists():
        continue
    for path in sorted(scan_root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(part in excluded_parts for part in rel.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8")
            ast.parse(source, filename=str(rel))
        except SyntaxError as exc:
            findings.append("syntax_error=%s:%s" % (rel, exc.lineno or 0))
        except OSError:
            findings.append("read_error=%s" % rel)
        checked += 1
        if not summary and not findings:
            print("syntax_ok=%s" % rel)

status = "ok" if not findings else "failed"
if summary:
    print("python_syntax_status=%s checks=%d findings=%d checked_python_files=%d" % (status, checked, len(findings), checked))
else:
    print("python_syntax_status=%s" % status)
    print("checks=%d" % checked)
    print("findings=%d" % len(findings))
    print("checked_python_files=%d" % checked)
    for finding in findings:
        print("finding=%s" % finding)
raise SystemExit(0 if not findings else 1)
PY
