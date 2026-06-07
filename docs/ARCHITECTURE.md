# br.m11h.eu Architektur

## Verbindliche Betriebsbasis

- Primärsystem: `m11h`.
- Importquelle: `m00h` nur lesend/synchronisierend.
- App/Code: `/home/chris/web/br.m11h.eu`.
- Sensible Daten: `/srv/br-wissensdatenbank`.
- Öffentliche Auslieferung ausschließlich über `br.m11h.eu` und nur nach Cloudflare Access, Basic Auth und App-Login.

## Kernregeln

- Keine Angabe ohne Quelle.
- Quelle direkt bei jeder Aussage.
- Neutral, nicht EVG-freundlich, nicht arbeitgeberfreundlich, nicht parteiisch.
- Hinweisquellen und Gesetzesentwürfe strikt getrennt.
- Interne Quellen nie öffentlich, nie indexierbar, nie direkt downloadbar.

## Container

- `db`: PostgreSQL 16 mit pgvector.
- `app`: FastAPI + serverseitige Templates.
- `worker`: OCR-/Import-/Export-Jobs; in der ersten Stufe bewusst idle.
- `proxy`: Caddy mit Basic Auth, Security Headers und globalem Logfilter fuer
  sensible Request-Header.
- `cloudflared`: vorbereitet, aber erst mit Profil `tunnel` und echter Cloudflare-Konfiguration zu starten.

## Zugriffsschutz

1. Cloudflare Tunnel / Access.
2. Basic Auth im Caddy-Proxy.
3. App-Login.
4. App-Rechteprüfung für Dokumente/Exporte.

## Secrets

- Lokale Secrets liegen unter `/srv/br-wissensdatenbank/secrets` mit restriktiven Rechten.
- Werte nicht in Git, Markdown, Logs, Frontend oder Chat kopieren.
- Rotation über `scripts/rotate-local-secrets.py`.
- Cloudflared-Tunnel-Credentials liegen unter `/srv/br-wissensdatenbank/secrets/cloudflared/` und werden nur read-only in den `cloudflared`-Container gemountet.
- Caddy-Logs filtern sensible Header wie `Authorization`, `Cookie` und
  Cloudflare-Access-Header, damit Reverse-Proxy-Fehler keine vollstaendigen
  Authentifizierungsheader in Containerlogs schreiben.
