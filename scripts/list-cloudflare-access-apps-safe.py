#!/usr/bin/env python3
"""List Cloudflare Access apps in a secret-safe way."""

import json
import urllib.parse
import urllib.request
from pathlib import Path

SECRET_FILE = Path("/home/chris/.config/opencode-secrets/cloudflare.env")
ZONE_NAME = "m11h.eu"


def load_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def req(email: str, key: str, path: str) -> dict:
    r = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, headers={"X-Auth-Email": email, "X-Auth-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=30) as resp:
        payload = json.loads(resp.read().decode())
    if not payload.get("success"):
        raise SystemExit(payload.get("errors"))
    return payload


def q(params: dict[str, str]) -> str:
    return urllib.parse.urlencode(params)


env = load_env(SECRET_FILE)
zone = req(env["CLOUDFLARE_EMAIL"], env["CLOUDFLARE_GLOBAL_API_KEY"], "/zones?" + q({"name": ZONE_NAME, "status": "active", "per_page": "50"}))["result"][0]
account_id = zone["account"]["id"]
apps = req(env["CLOUDFLARE_EMAIL"], env["CLOUDFLARE_GLOBAL_API_KEY"], "/accounts/%s/access/apps?%s" % (account_id, q({"per_page": "100"})))["result"]
for app in sorted(apps, key=lambda a: a.get("domain", "")):
    print("domain=%r name=%r type=%r session=%r auto_redirect=%r binding=%r httponly=%r samesite=%r allowed_idps_count=%d launcher=%r" % (
        app.get("domain"), app.get("name"), app.get("type"), app.get("session_duration"), app.get("auto_redirect_to_identity"),
        app.get("enable_binding_cookie"), app.get("http_only_cookie_attribute"), app.get("same_site_cookie_attribute"),
        len(app.get("allowed_idps") or []), app.get("app_launcher_visible"),
    ))
