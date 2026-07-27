#!/usr/bin/env python3
"""Deterministic tests for the external cookie/fallback security guard.

The tests use only synthetic status/header metadata. They perform no network
requests, read no response bodies and handle no credentials or cookie values
from the live service.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


GUARD_PATH = Path(__file__).with_name("check-external-cookie-security.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("external_cookie_security_guard", GUARD_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("guard_import_failed")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


COOKIE = "CF_Authorization=synthetic; Secure; HttpOnly; SameSite=None; Path=/; Max-Age=60; Domain=br.m11h.eu"
FALLBACK_HEADERS = {
    "server": "cloudflare",
    "www-authenticate": 'Basic realm="restricted"',
    "x-robots-tag": "noindex, nofollow, noarchive",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
}
COOKIE_HEADERS = {"server": "cloudflare"}


class ExternalCookieSecurityTests(unittest.TestCase):
    def run_guard(self, responses: list[tuple[int, list[str], dict[str, str]]]) -> tuple[int, str]:
        with (
            patch.object(GUARD, "fetch_cookie_headers", side_effect=responses),
            patch.object(sys, "argv", [str(GUARD_PATH), "--summary"]),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            result = GUARD.main()
        return result, output.getvalue().strip()

    def test_complete_cookie_mode_passes(self) -> None:
        result, output = self.run_guard([(200, [COOKIE], COOKIE_HEADERS)] * 3)
        self.assertEqual(result, 0)
        self.assertIn("external_cookie_security_status=ok", output)
        self.assertIn("mode=cloudflare_cookie", output)
        self.assertIn("cookies=3", output)

    def test_complete_server_bypass_fallback_passes(self) -> None:
        result, output = self.run_guard([(401, [], FALLBACK_HEADERS)] * 3)
        self.assertEqual(result, 0)
        self.assertIn("mode=server_bypass_fallback", output)
        self.assertIn("bypass_fallback=3", output)

    def test_mixed_cookie_visibility_fails(self) -> None:
        responses = [
            (200, [COOKIE], COOKIE_HEADERS),
            (401, [], FALLBACK_HEADERS),
            (200, [COOKIE], COOKIE_HEADERS),
        ]
        result, output = self.run_guard(responses)
        self.assertEqual(result, 1)
        self.assertIn("external_cookie_security_status=failed", output)

    def test_missing_fallback_header_fails(self) -> None:
        incomplete = dict(FALLBACK_HEADERS)
        incomplete.pop("content-security-policy")
        result, output = self.run_guard([(401, [], FALLBACK_HEADERS), (401, [], incomplete), (401, [], FALLBACK_HEADERS)])
        self.assertEqual(result, 1)
        self.assertIn("external_cookie_security_status=failed", output)

    def test_missing_cloudflare_server_marker_fails(self) -> None:
        no_cloudflare = dict(FALLBACK_HEADERS)
        no_cloudflare["server"] = "caddy"
        result, output = self.run_guard([(401, [], FALLBACK_HEADERS), (401, [], no_cloudflare), (401, [], FALLBACK_HEADERS)])
        self.assertEqual(result, 1)
        self.assertIn("external_cookie_security_status=failed", output)

    def test_unreachable_path_fails(self) -> None:
        result, output = self.run_guard([(401, [], FALLBACK_HEADERS), (0, [], {}), (401, [], FALLBACK_HEADERS)])
        self.assertEqual(result, 1)
        self.assertIn("external_cookie_security_status=failed", output)


if __name__ == "__main__":
    unittest.main()
