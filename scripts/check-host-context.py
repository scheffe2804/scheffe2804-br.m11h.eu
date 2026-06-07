#!/usr/bin/env python3
"""Read-only host context guard for BR-Wissen.

The guard verifies that the BR-Wissen operational checks run on the expected
target host. It prints only non-secret host metadata and never reads application
secrets, backup environment contents, logs or dumps.
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
from pathlib import Path


HOST_CONTEXT = Path(os.getenv("BR_HOST_CONTEXT", "/etc/opencode-host-context"))
EXPECTED_HOSTNAME = os.getenv("BR_EXPECTED_HOSTNAME", "m11h.eu")
EXPECTED_HOST_ROLE = os.getenv("BR_EXPECTED_HOST_ROLE", "m11h")
EXPECTED_THIS_SERVER = os.getenv("BR_EXPECTED_THIS_SERVER", "m11h")
EXPECTED_PUBLIC_IPV4 = os.getenv("BR_EXPECTED_PUBLIC_IPV4", "31.70.74.139")
EXPECTED_TAILSCALE_IPV4 = os.getenv("BR_EXPECTED_TAILSCALE_IPV4", "100.102.205.121")
EXPECTED_M00H_DIFFERENT = os.getenv("BR_EXPECTED_M00H_DIFFERENT_SERVER", "true")
HOSTNAME = Path("/usr/bin/hostname")
TAILSCALE = Path("/usr/bin/tailscale")


def parse_context(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def current_hostname() -> str:
    proc = None
    if HOSTNAME.exists() and not HOSTNAME.is_symlink() and HOSTNAME.is_file():
        proc = subprocess.run([str(HOSTNAME)], text=True, capture_output=True, check=False)
    if proc and proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return socket.gethostname()


def current_tailscale_ipv4() -> str:
    if not TAILSCALE.exists() or TAILSCALE.is_symlink() or not TAILSCALE.is_file():
        return ""
    proc = subprocess.run([str(TAILSCALE), "ip", "-4"], text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip().splitlines()[0].strip() if proc.stdout.strip() else ""


def expect_value(findings: list[str], label: str, actual: str, expected: str) -> None:
    if actual != expected:
        safe_actual = actual if actual else "missing"
        findings.append("%s_unexpected=%s" % (label, safe_actual))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check BR-Wissen host context")
    parser.add_argument("--summary", action="store_true", help="print compact summary")
    args = parser.parse_args()

    findings: list[str] = []
    context = parse_context(HOST_CONTEXT)
    hostname = current_hostname()
    tailscale_ipv4 = current_tailscale_ipv4()

    checks = 0
    checks += 1
    if not HOST_CONTEXT.exists():
        findings.append("host_context_file_missing")

    expected_values = [
        ("hostname", hostname, EXPECTED_HOSTNAME),
        ("host_role", context.get("HOST_ROLE", ""), EXPECTED_HOST_ROLE),
        ("this_server", context.get("THIS_SERVER", ""), EXPECTED_THIS_SERVER),
        ("public_ipv4", context.get("PUBLIC_IPV4", ""), EXPECTED_PUBLIC_IPV4),
        ("context_tailscale_ipv4", context.get("TAILSCALE_IPV4", ""), EXPECTED_TAILSCALE_IPV4),
        ("runtime_tailscale_ipv4", tailscale_ipv4, EXPECTED_TAILSCALE_IPV4),
        ("m00h_is_different_server", context.get("M00H_IS_DIFFERENT_SERVER", ""), EXPECTED_M00H_DIFFERENT),
    ]
    for label, actual, expected in expected_values:
        checks += 1
        expect_value(findings, label, actual, expected)

    status = "ok" if not findings else "failed"
    public_ipv4 = context.get("PUBLIC_IPV4", "missing") or "missing"
    context_tailscale_ipv4 = context.get("TAILSCALE_IPV4", "missing") or "missing"
    host_role = context.get("HOST_ROLE", "missing") or "missing"
    this_server = context.get("THIS_SERVER", "missing") or "missing"

    if args.summary:
        print(
            "host_context_status=%s checks=%d findings=%d hostname=%s host_role=%s this_server=%s public_ipv4=%s tailscale_ipv4=%s"
            % (status, checks, len(findings), hostname, host_role, this_server, public_ipv4, context_tailscale_ipv4)
        )
    else:
        print("host_context_status=%s" % status)
        print("checks=%d" % checks)
        print("findings=%d" % len(findings))
        print("hostname=%s" % hostname)
        print("host_role=%s" % host_role)
        print("this_server=%s" % this_server)
        print("public_ipv4=%s" % public_ipv4)
        print("context_tailscale_ipv4=%s" % context_tailscale_ipv4)
        print("runtime_tailscale_ipv4=%s" % (tailscale_ipv4 or "missing"))
        for finding in findings:
            print("finding=%s" % finding)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
