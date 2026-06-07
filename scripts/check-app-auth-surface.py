#!/usr/bin/env python3
"""Read-only app authentication/CSRF surface guard for BR-Wissen.

The guard runs HTTP metadata checks inside the app container against the internal
loopback app port. It does not send credentials, does not follow redirects, does
not read response bodies, and does not read secrets, dumps, logs, answers or
source documents.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from textwrap import dedent
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

CONTAINER_CHECK = r'''
import http.client
import json

HOST = "127.0.0.1"
PORT = 8000
TIMEOUT = 5

PROTECTED_GETS = [
    "/",
    "/sources",
    "/source-quality",
    "/queries",
    "/queries/new",
    "/answers",
    "/security-rules",
    "/search",
    "/validation",
]
PUBLIC_GETS = {
    "/healthz": 200,
    "/login": 200,
}
CSRF_POSTS = [
    "/logout",
    "/queries",
    "/sources/approve-evg-all",
    "/sources/nonexistent/block",
    "/queries/nonexistent/recommended-answer",
    "/answers/nonexistent/export",
]


def request(method, path):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)
    headers = {"User-Agent": "br-wissen-app-auth-surface-guard"}
    body = None
    if method == "POST":
        body = b""
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        status = int(resp.status)
        headers_out = {key.lower(): value for key, value in resp.getheaders()}
        resp.close()
        return {"path": path, "method": method, "status": status, "location": headers_out.get("location", "")}
    finally:
        conn.close()


result = {
    "protected_gets": [request("GET", path) for path in PROTECTED_GETS],
    "public_gets": [request("GET", path) for path in PUBLIC_GETS],
    "csrf_posts": [request("POST", path) for path in CSRF_POSTS],
}
print(json.dumps(result, sort_keys=True))
'''


def run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=str(ROOT), input=stdin, text=True, capture_output=True, check=False)


def collect() -> tuple[int, dict[str, Any]]:
    proc = run(["docker", "compose", "exec", "-T", "app", "python", "-"], CONTAINER_CHECK)
    if proc.returncode != 0:
        return proc.returncode, {}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return 1, {}
    return 0, data if isinstance(data, dict) else {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen app auth and CSRF surface")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    checks = 0
    code, data = collect()
    checks += 1
    if code != 0:
        findings.append("app_container_check_unavailable")
        data = {}

    protected_gets = data.get("protected_gets") if isinstance(data.get("protected_gets"), list) else []
    public_gets = data.get("public_gets") if isinstance(data.get("public_gets"), list) else []
    csrf_posts = data.get("csrf_posts") if isinstance(data.get("csrf_posts"), list) else []

    redirected = 0
    for item in protected_gets:
        checks += 1
        path = str(item.get("path") or "unknown")
        status = int(item.get("status") or 0)
        location = str(item.get("location") or "")
        if status == 303 and location == "/login":
            redirected += 1
        else:
            findings.append("protected_get_%s_status=%s_location=%s" % (path.strip("/") or "root", status, location or "none"))

    public_ok = 0
    expected_public = {"/healthz": 200, "/login": 200}
    for item in public_gets:
        checks += 1
        path = str(item.get("path") or "unknown")
        status = int(item.get("status") or 0)
        expected = expected_public.get(path)
        if expected is not None and status == expected:
            public_ok += 1
        else:
            findings.append("public_get_%s_status=%s" % (path.strip("/") or "root", status))

    csrf_blocked = 0
    post_successes = 0
    post_redirects = 0
    for item in csrf_posts:
        checks += 1
        path = str(item.get("path") or "unknown")
        status = int(item.get("status") or 0)
        if 200 <= status < 300:
            post_successes += 1
        if 300 <= status < 400:
            post_redirects += 1
        if status == 403:
            csrf_blocked += 1
        else:
            findings.append("csrf_post_%s_status=%s" % (path.strip("/").replace("/", "_") or "root", status))

    checks += 1
    if len(protected_gets) != 9:
        findings.append("protected_get_count=%d" % len(protected_gets))
    checks += 1
    if len(public_gets) != 2:
        findings.append("public_get_count=%d" % len(public_gets))
    checks += 1
    if len(csrf_posts) != 6:
        findings.append("csrf_post_count=%d" % len(csrf_posts))

    status = "ok" if not findings else "failed"
    if args.summary:
        print(
            "app_auth_surface_status=%s checks=%d findings=%d protected_gets=%d redirected=%d public_gets=%d public_ok=%d csrf_posts=%d csrf_blocked=%d post_successes=%d post_redirects=%d"
            % (
                status,
                checks,
                len(findings),
                len(protected_gets),
                redirected,
                len(public_gets),
                public_ok,
                len(csrf_posts),
                csrf_blocked,
                post_successes,
                post_redirects,
            )
        )
    else:
        print("app_auth_surface_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("protected_gets=%d" % len(protected_gets))
        print("redirected=%d" % redirected)
        print("public_gets=%d" % len(public_gets))
        print("public_ok=%d" % public_ok)
        print("csrf_posts=%d" % len(csrf_posts))
        print("csrf_blocked=%d" % csrf_blocked)
        print("post_successes=%d" % post_successes)
        print("post_redirects=%d" % post_redirects)
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
