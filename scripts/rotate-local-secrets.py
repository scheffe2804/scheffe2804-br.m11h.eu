#!/usr/bin/env python3
"""Rotate local development/production secrets for br.m11h.eu.

This script intentionally prints only file names, never secret values.
It requires Docker to create a Caddy-compatible bcrypt hash.
"""

import os
import secrets
import subprocess
from pathlib import Path


ROOT = Path("/srv/br-wissensdatenbank/secrets")


def write_secret(path: Path, content: str, mode: int = 0o600) -> None:
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    pg_password = secrets.token_urlsafe(36)
    admin_password = secrets.token_urlsafe(32)
    session_secret = secrets.token_urlsafe(64)
    basic_user = "bradmin"
    basic_password = secrets.token_urlsafe(28)
    hash_result = subprocess.run(
        ["docker", "run", "--rm", "caddy:2.8-alpine", "caddy", "hash-password", "--plaintext", basic_password],
        check=True,
        text=True,
        capture_output=True,
    )
    basic_hash = hash_result.stdout.strip()

    write_secret(ROOT / "postgres.env", "POSTGRES_DB=br_wissen\nPOSTGRES_USER=br_app\nPOSTGRES_PASSWORD=%s\n" % pg_password)
    write_secret(ROOT / "app-admin-password.txt", admin_password + "\n")
    write_secret(ROOT / "session-secret.txt", session_secret + "\n")
    write_secret(ROOT / "basic-auth-password.txt", "user=%s\npassword=%s\n" % (basic_user, basic_password))
    write_secret(
        ROOT / "app.env",
        "\n".join(
            [
                "BR_APP_ENV=production",
                "BR_APP_TITLE=Betriebsrats-Wissensdatenbank",
                "BR_PUBLIC_BASE_URL=https://br.m11h.eu",
                "BR_STORAGE_ROOT=/srv/br-wissensdatenbank",
                "BR_ADMIN_PASSWORD_FILE=/run/br-secrets/app-admin-password.txt",
                "BR_SESSION_SECRET_FILE=/run/br-secrets/session-secret.txt",
                "BR_DATABASE_URL=postgresql://br_app:%s@db:5432/br_wissen" % pg_password,
                "BR_REQUIRE_SOURCES=true",
                "BR_NEUTRALITY_MODE=strict",
                "",
            ]
        ),
    )
    # Compose interpolates `$` in env files unless values are single-quoted.
    write_secret(ROOT / "caddy-basic-auth.env", "BR_BASIC_AUTH_USER=%s\nBR_BASIC_AUTH_HASH='%s'\n" % (basic_user, basic_hash))
    write_secret(
        ROOT / "README-SECRETS.txt",
        "Secrets fuer br.m11h.eu. Werte nicht protokollieren, nicht committen, nicht in Markdown kopieren.\n"
        "App-Admin-Passwort: app-admin-password.txt\n"
        "Basic-Auth-Zugang: basic-auth-password.txt\n"
        "Nach Rotation muessen betroffene Container neu gestartet werden.\n",
    )
    print("rotated secret files:", ", ".join(sorted(p.name for p in ROOT.iterdir())))


if __name__ == "__main__":
    main()
