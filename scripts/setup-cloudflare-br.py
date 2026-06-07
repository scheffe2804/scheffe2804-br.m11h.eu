#!/usr/bin/env python3
"""Create/ensure Cloudflare Tunnel, DNS and Access app for br.m11h.eu.

Secrets are loaded from /home/chris/.config/opencode-secrets/cloudflare.env.
This script never prints token/key values or tunnel secrets.

Default mode is dry-run. Use --apply to write Cloudflare changes and local
tunnel credential files.
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SECRET_FILE = Path("/home/chris/.config/opencode-secrets/cloudflare.env")
DOMAIN = "br.m11h.eu"
ZONE_NAME = "m11h.eu"
TUNNEL_NAME = "br-m11h-eu"
PROJECT_DIR = Path("/home/chris/web/br.m11h.eu")
CLOUDFLARED_DIR = PROJECT_DIR / "cloudflared"


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


class CF:
    def __init__(self, email: str, key: str):
        self.email = email
        self.key = key

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None
        headers = {
            "X-Auth-Email": self.email,
            "X-Auth-Key": self.key,
            "Content-Type": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError("Cloudflare API HTTP %s for %s %s: %s" % (exc.code, method, path, raw[:1000])) from exc
        if not payload.get("success"):
            raise RuntimeError("Cloudflare API reported failure for %s %s: %s" % (method, path, payload.get("errors")))
        return payload

    def get(self, path: str) -> dict:
        return self.request("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self.request("POST", path, body)

    def put(self, path: str, body: dict) -> dict:
        return self.request("PUT", path, body)


def q(params: dict[str, str]) -> str:
    return urllib.parse.urlencode(params)


def find_zone(cf: CF) -> dict:
    payload = cf.get("/zones?" + q({"name": ZONE_NAME, "status": "active", "per_page": "50"}))
    zones = payload["result"]
    if not zones:
        raise RuntimeError("Zone not found: %s" % ZONE_NAME)
    return zones[0]


def find_tunnel(cf: CF, account_id: str) -> dict | None:
    payload = cf.get("/accounts/%s/cfd_tunnel?%s" % (account_id, q({"name": TUNNEL_NAME, "per_page": "50"})))
    for tunnel in payload["result"]:
        if tunnel.get("name") == TUNNEL_NAME and not tunnel.get("deleted_at"):
            return tunnel
    return None


def create_tunnel(cf: CF, account_id: str) -> tuple[dict, str]:
    tunnel_secret = base64.b64encode(os.urandom(32)).decode("ascii")
    payload = cf.post("/accounts/%s/cfd_tunnel" % account_id, {"name": TUNNEL_NAME, "tunnel_secret": tunnel_secret})
    return payload["result"], tunnel_secret


def ensure_dns(cf: CF, zone_id: str, tunnel_id: str, apply: bool) -> str:
    target = "%s.cfargotunnel.com" % tunnel_id
    payload = cf.get("/zones/%s/dns_records?%s" % (zone_id, q({"type": "CNAME", "name": DOMAIN, "per_page": "50"})))
    records = payload["result"]
    body = {"type": "CNAME", "name": DOMAIN, "content": target, "proxied": True, "ttl": 1, "comment": "br.m11h.eu Cloudflare Tunnel"}
    if records:
        rec = records[0]
        if rec.get("content") == target and rec.get("proxied") is True:
            return "dns-ok-existing"
        if apply:
            cf.put("/zones/%s/dns_records/%s" % (zone_id, rec["id"]), body)
            return "dns-updated"
        return "dns-would-update"
    if apply:
        cf.post("/zones/%s/dns_records" % zone_id, body)
        return "dns-created"
    return "dns-would-create"


def find_access_app(cf: CF, account_id: str) -> dict | None:
    payload = cf.get("/accounts/%s/access/apps?%s" % (account_id, q({"per_page": "100"})))
    for app in payload["result"]:
        if app.get("domain") == DOMAIN or app.get("name") == DOMAIN:
            return app
    return None


def ensure_access_app(cf: CF, account_id: str, email: str, apply: bool) -> str:
    app = find_access_app(cf, account_id)
    app_body = {
        "name": DOMAIN,
        "domain": DOMAIN,
        "type": "self_hosted",
        "session_duration": "24h",
        "auto_redirect_to_identity": False,
        "enable_binding_cookie": True,
        "http_only_cookie_attribute": True,
        "same_site_cookie_attribute": "strict",
    }
    if app is None:
        if not apply:
            return "access-app-would-create"
        app = cf.post("/accounts/%s/access/apps" % account_id, app_body)["result"]
        app_status = "access-app-created"
    else:
        app_status = "access-app-existing"

    # Ensure a simple allow policy for the configured Cloudflare account email.
    # If existing policies are present, do not delete or modify them.
    policies = cf.get("/accounts/%s/access/apps/%s/policies?%s" % (account_id, app["id"], q({"per_page": "100"})))["result"]
    for pol in policies:
        if pol.get("name") == "Allow configured admin email":
            return app_status + "+policy-existing"
    if not apply:
        return app_status + "+policy-would-create"
    policy_body = {
        "name": "Allow configured admin email",
        "decision": "allow",
        "precedence": 1,
        "include": [{"email": {"email": email}}],
    }
    cf.post("/accounts/%s/access/apps/%s/policies" % (account_id, app["id"]), policy_body)
    return app_status + "+policy-created"


def write_tunnel_files(account_id: str, tunnel: dict, tunnel_secret: str | None, apply: bool) -> str:
    tunnel_id = tunnel["id"]
    cred_path = CLOUDFLARED_DIR / (tunnel_id + ".json")
    config_path = CLOUDFLARED_DIR / "config.yml"
    if not apply:
        return "files-would-write"
    CLOUDFLARED_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CLOUDFLARED_DIR, 0o700)
    if not cred_path.exists():
        if not tunnel_secret:
            raise RuntimeError("Existing tunnel has no local credential file and no new tunnel_secret is available. Recreate or provide credentials manually.")
        cred = {
            "AccountTag": account_id,
            "TunnelSecret": tunnel_secret,
            "TunnelID": tunnel_id,
            "TunnelName": TUNNEL_NAME,
        }
        cred_path.write_text(json.dumps(cred, indent=2) + "\n", encoding="utf-8")
        os.chmod(cred_path, 0o600)
        cred_status = "credentials-written"
    else:
        cred_status = "credentials-existing"
    config = """tunnel: %s
credentials-file: /etc/cloudflared/%s.json

ingress:
  - hostname: %s
    service: http://proxy:8080
  - service: http_status:404
""" % (tunnel_id, tunnel_id, DOMAIN)
    config_path.write_text(config, encoding="utf-8")
    os.chmod(config_path, 0o600)
    return cred_status + "+config-written"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="apply Cloudflare and local file changes")
    args = parser.parse_args()
    if not SECRET_FILE.exists():
        print("secret_file_missing")
        return 2
    env = load_env(SECRET_FILE)
    email = env.get("CLOUDFLARE_EMAIL")
    key = env.get("CLOUDFLARE_GLOBAL_API_KEY")
    if not email or not key:
        print("cloudflare_credentials_missing")
        return 2
    cf = CF(email, key)
    zone = find_zone(cf)
    zone_id = zone["id"]
    account_id = zone["account"]["id"]
    print("zone=found account=found mode=%s" % ("apply" if args.apply else "dry-run"))

    tunnel = find_tunnel(cf, account_id)
    tunnel_secret = None
    if tunnel is None:
        if args.apply:
            tunnel, tunnel_secret = create_tunnel(cf, account_id)
            print("tunnel=created id=%s" % tunnel["id"])
        else:
            print("tunnel=would-create name=%s" % TUNNEL_NAME)
            tunnel = {"id": "DRY-RUN-TUNNEL-ID", "name": TUNNEL_NAME}
    else:
        print("tunnel=existing id=%s" % tunnel["id"])

    if tunnel["id"] != "DRY-RUN-TUNNEL-ID":
        print(ensure_dns(cf, zone_id, tunnel["id"], args.apply))
        print(ensure_access_app(cf, account_id, email, args.apply))
    else:
        print("dns=would-create")
        print("access=would-create")
    print(write_tunnel_files(account_id, tunnel, tunnel_secret, args.apply))
    return 0


if __name__ == "__main__":
    sys.exit(main())
