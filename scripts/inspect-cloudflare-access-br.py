#!/usr/bin/env python3
"""Inspect Cloudflare Access app for br.m11h.eu without printing secrets."""

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
    def get(self, path: str) -> dict:
        req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, headers={"X-Auth-Email": self.email, "X-Auth-Key": self.key, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
        if not payload.get("success"):
            raise SystemExit(payload.get("errors"))
        return payload


def q(params: dict[str, str]) -> str:
    return urllib.parse.urlencode(params)


env = load_env(SECRET_FILE)
cf = CF(env["CLOUDFLARE_EMAIL"], env["CLOUDFLARE_GLOBAL_API_KEY"])
zone = cf.get("/zones?" + q({"name": ZONE_NAME, "status": "active", "per_page": "50"}))["result"][0]
account_id = zone["account"]["id"]
apps = cf.get("/accounts/%s/access/apps?%s" % (account_id, q({"per_page": "100"})))["result"]
for app in apps:
    if app.get("domain") == DOMAIN or app.get("name") == DOMAIN:
        print("app_id=%s" % app.get("id"))
        for key in ["name","domain","type","aud","session_duration","auto_redirect_to_identity","enable_binding_cookie","http_only_cookie_attribute","same_site_cookie_attribute","allowed_idps","app_launcher_visible"]:
            if key in app:
                print("%s=%r" % (key, app.get(key)))
        policies = cf.get("/accounts/%s/access/apps/%s/policies?%s" % (account_id, app["id"], q({"per_page": "100"})))["result"]
        print("policies=%d" % len(policies))
        for pol in policies:
            print("policy name=%r decision=%r precedence=%r include_keys=%r" % (pol.get("name"), pol.get("decision"), pol.get("precedence"), [list(i.keys()) for i in pol.get("include", [])]))
