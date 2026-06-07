#!/usr/bin/env python3
"""Align br.m11h.eu Cloudflare Access cookie settings with working staging apps."""

import json
import urllib.parse
import urllib.request
from pathlib import Path

SECRET_FILE = Path("/home/chris/.config/opencode-secrets/cloudflare.env")
DOMAIN = "br.m11h.eu"
ZONE_NAME = "m11h.eu"


def load_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            values[k.strip()] = v.strip().strip('"').strip("'")
    return values


class CF:
    def __init__(self, email: str, key: str):
        self.email = email; self.key = key
    def request(self, method: str, path: str, body=None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, data=data, method=method, headers={"X-Auth-Email": self.email, "X-Auth-Key": self.key, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
        if not payload.get("success"):
            raise SystemExit(payload.get("errors"))
        return payload
    def get(self, path: str) -> dict: return self.request("GET", path)
    def put(self, path: str, body) -> dict: return self.request("PUT", path, body)


def q(params: dict[str, str]) -> str:
    return urllib.parse.urlencode(params)


env = load_env(SECRET_FILE)
cf = CF(env["CLOUDFLARE_EMAIL"], env["CLOUDFLARE_GLOBAL_API_KEY"])
zone = cf.get("/zones?" + q({"name": ZONE_NAME, "status": "active", "per_page": "50"}))["result"][0]
account_id = zone["account"]["id"]
apps = cf.get("/accounts/%s/access/apps?%s" % (account_id, q({"per_page": "100"})))["result"]
for app in apps:
    if app.get("domain") == DOMAIN or app.get("name") == DOMAIN:
        body = {
            "name": app.get("name", DOMAIN),
            "domain": app.get("domain", DOMAIN),
            "type": app.get("type", "self_hosted"),
            "session_duration": app.get("session_duration", "24h"),
            "auto_redirect_to_identity": False,
            "enable_binding_cookie": False,
            "http_only_cookie_attribute": False,
            "allowed_idps": app.get("allowed_idps", []),
            "app_launcher_visible": app.get("app_launcher_visible", True),
        }
        cf.put("/accounts/%s/access/apps/%s" % (account_id, app["id"]), body)
        print("updated app_id=%s cookie_settings=staging-like" % app["id"])
        raise SystemExit(0)
print("app_not_found")
raise SystemExit(1)
