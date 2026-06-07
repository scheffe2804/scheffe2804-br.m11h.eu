# br.m11h.eu Runbook

Aktueller zusammengefasster Betriebs-, Sicherheits-, Backup-, Restore- und
Regressionstand: siehe `docs/READINESS.md`. Der letzte Doku-Abgleich erfolgte am
2026-06-03 mit read-only Status-/Summary-Guards sowie einem manuellen Marker-
Backup fuer den Network-Exposure-Preflight; produktive Container wurden dabei
nicht neu gestartet.

## Lokale Secrets rotieren

```bash
python3 /home/chris/web/br.m11h.eu/scripts/rotate-local-secrets.py
```

Bei produktiver Rotation nach einer moeglichen Secret-Offenlegung zusaetzlich
sicherstellen, dass auch die laufende Datenbankrolle rotiert wird. Danach
betroffene Container mit den neuen Env-/Secret-Dateien neu erstellen/starten und
mindestens pruefen:

```bash
cd /home/chris/web/br.m11h.eu
docker compose up -d --no-deps --force-recreate app worker proxy
scripts/check-compose-services.py --summary
scripts/check-runtime-http-security.py --summary
scripts/check-app-auth-surface.py --summary
scripts/healthcheck-br-wissen-docker.sh --summary
scripts/check-storage-permissions.py --summary
scripts/check-project-artifacts.sh --summary
```

Secretwerte niemals per `docker compose config`, Logs, Markdown, Chat oder
Shell-History ausgeben. Fuer Compose-Inspektionen nur gezielte, wertfreie Marker-
oder Key-Pruefungen nutzen.

## Admin-Zugangsdaten lokal einsehen

Nur auf `m11h`, nicht in Chat/Protokolle kopieren:

```bash
sudo -u chris sed -n '1,5p' /srv/br-wissensdatenbank/secrets/basic-auth-password.txt
sudo -u chris sed -n '1p' /srv/br-wissensdatenbank/secrets/app-admin-password.txt
```

## Lokal starten

```bash
cd /home/chris/web/br.m11h.eu
docker compose up -d --build
```

Lokaler Test nur über Loopback:

```text
http://127.0.0.1:18083
```

Produktiver Zugriff darf erst nach Cloudflare Access/Tunnel-Prüfung über `br.m11h.eu` erfolgen.

## Status und Healthcheck prüfen

Kompakter Betriebsstatus ohne neue Testantworten:

```bash
cd /home/chris/web/br.m11h.eu
scripts/status-br-wissen.sh
scripts/status-br-wissen.sh --image-pinning
```

Vollständiger read-only Healthcheck:

```bash
cd /home/chris/web/br.m11h.eu
scripts/healthcheck-br-wissen-docker.sh
```

Einzeilige Summary für Logs/Journald:

```bash
cd /home/chris/web/br.m11h.eu
scripts/healthcheck-br-wissen-docker.sh --summary
```

Lesbare Summary für manuelle Kontrolle:

```bash
cd /home/chris/web/br.m11h.eu
scripts/healthcheck-br-wissen-docker.sh --summary --pretty
```

## Python-Syntax-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-python-syntax.sh
scripts/check-python-syntax.sh --summary
```

Der Guard ist read-only und prueft alle Python-Dateien in `app/`, `scripts/` und
`worker/` per `ast.parse`, ohne Bytecode oder `__pycache__` zu erzeugen. Er liest
keine Secretwerte, Dump-Inhalte, Logs, Antworttexte oder Quelleninhalte. Der
Summary-Modus liefert `python_syntax_status`, `checks`, `findings` und
`checked_python_files`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Python-Syntax-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Shell-Syntax-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-shell-syntax.sh
scripts/check-shell-syntax.sh --summary
```

Der Guard ist read-only und prueft Shell-Skripte im `scripts/`-Verzeichnis per
`bash -n`, ohne die Skripte auszufuehren. Secretwerte, Dump-Inhalte, Logs,
Antworttexte oder Quelleninhalte werden nicht gelesen oder ausgegeben. Der
Summary-Modus liefert `shell_syntax_status`, `checks`, `findings` und
`checked_shell_files`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Shell-Syntax-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Systemd-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-systemd-source-hardening.py
scripts/check-systemd-source-hardening.py --summary
```

Der Guard ist read-only und validiert ausschliesslich die systemd-Quellen unter
`systemd/`. Geprueft werden erwartete Service- und Timer-Marker wie User,
WorkingDirectory, ExecStart-/ExecStartPre-Kette, OnCalendar, Persistent,
RandomizedDelaySec und WantedBy. Er ruft kein `systemctl` auf, schreibt keine
Units und liest keine Secretwerte, Dump-Inhalte, Logs, Antworttexte oder
Quelleninhalte.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Systemd-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Systemd-Unit-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-systemd-units.sh
scripts/check-systemd-units.sh --summary
```

Der Guard ist read-only und prueft die zehn BR-Wissen-Service-/Timer-Dateien auf
Synchronitaet zwischen Projektquelle und `/etc/systemd/system/`, die fuenf
erwarteten Timer auf `active`, die fuenf erwarteten Services auf nicht-`failed`
und metadata-only die Unit-Datei-Policy. Erwartet sind keine Symlinks, regulaere
Unit-Dateien, keine world-writable Projekt-/Installationsdateien und keine
group-writable installierten Units; der Summary-Marker dafuer ist
`unit_policy_failures=0`. Installierte Units muessen `root:root` gehoeren;
Projekt-Units muessen denselben Owner/dieselbe Group wie das Projekt-`systemd/`-
Verzeichnis haben. Zusaetzlich prueft der Guard die Parent-Verzeichnisse
`systemd/`, `/etc/systemd` und `/etc/systemd/system` auf Symlink-Freiheit,
Verzeichnistyp, keine world-writable Rechte und fuer installierte Parents
`root:root` ohne group-/world-writable Rechte; erwarteter Marker ist
`parent_policy_failures=0`. Zusaetzlich nutzt der Guard das vorhandene `lsattr`,
um Linux-Dateiattribute der direkten BR-Wissen-Unit-Dateien und Parent-
Verzeichnisse metadata-only zu pruefen; das normale Extents-Flag `e` ist erlaubt,
andere sichtbare Attribute gelten als Drift (`attr_policy_failures=0`,
`lsattr_available=1`). ACL-/xattr-Tools sind auf diesem Host nicht installiert und
werden nicht nachinstalliert; die Summary weist das als `acl_tool_available=0` und
`xattr_tool_available=0` aus. Die `root:root`-Anforderung gilt nur fuer installierte
`/etc/systemd*`-Parents; das Projekt-`systemd/` folgt dem Projektbaum-Owner.
Vendor-Units unter `/usr/lib/systemd`, Runtime-Units unter `/run/systemd` und
User-Units sind nicht Teil dieses BR-Wissen-Direct-Unit-Guards. Abgeschlossene
oneshot-Services im Zustand `inactive` sind erwartbar und kein Fehler. Der Pfad-Scope ist bewusst auf die direkten
BR-Wissen-Unit-Dateien aus der festen `br-wissen-*`-Liste begrenzt; normale
systemd-Enablement-Symlinks unter `*.wants/` werden nicht inspiziert.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Systemd Timer`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Systemd-Loaded-Unit-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-systemd-loaded-units.py
scripts/check-systemd-loaded-units.py --summary
```

Der Guard ist read-only und prueft per `systemctl show` nur die geladenen
systemd-Metadaten der fuenf BR-Wissen-Services und fuenf Timer. Erwartet werden
geladene Units aus `/etc/systemd/system/`, statische Services, aktivierte/aktive
Timer, erfolgreiche/nicht fehlgeschlagene Services, erwartete Service-User,
`Type=oneshot`, `WorkingDirectory=/home/chris/web/br.m11h.eu`, erwartete
`ExecStart`-Pfade und die geladene Healthcheck-`ExecStartPre`-Sequenz. Er startet,
stoppt, restartet, enabled, disabled oder reloadet keine Units und liest keine
Secrets, Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Systemd-Loaded-Unit-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Status-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-status-source-hardening.py
scripts/check-status-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quelle des zentralen
Status-Wrappers `scripts/status-br-wissen.sh`. Geprueft werden erwartete read-only
Defaults, erlaubte Kommandozeilenoptionen, explizite Opt-ins fuer Regressionen,
Duplikatbericht und Image-Pinning-Readiness, die vollstaendige Guard-Abschnitts-
Kette und kompakte Summary-Aufrufe. Er liest keine Secrets, Dumps, Logs,
Antworten, Importe oder Quelleninhalte und ruft keine Statuschecks, kein Docker,
kein `systemctl`, keine Imports, Backups, Restores oder Regressionen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Status-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Healthcheck-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-healthcheck-source-hardening.py
scripts/check-healthcheck-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen des App-
Healthchecks `scripts/healthcheck-br-wissen.py` und dessen Docker-Wrapper
`scripts/healthcheck-br-wissen-docker.sh`. Geprueft werden erwartete read-only
DB-/Datei-Integritaetsabfragen, Failure-Marker, Summary-Ausgabe, Wrapper-`cd`
und `docker compose exec -T app python`-Aufruf sowie verbotene mutierende Marker
wie INSERT/UPDATE/DELETE/DROP/COMMIT oder lokale Loeschoperationen. Er liest
keine Secrets, Dumps, Logs, Antworten oder Quelleninhalte und ruft keinen
Healthcheck, kein Docker, keine DB-Abfragen, Imports, Backups, Restores oder
Regressionen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Healthcheck-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Operational-Wrapper-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-operational-wrapper-source-hardening.py
scripts/check-operational-wrapper-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich operative Wrapper-Quellen fuer
Backup, Restore-Smoke, m00h-/BAG-Import, Regressionen, Antwort-Export, Repair,
Cloudflare-Pattern-Hilfe und OCR. Geprueft werden erwartete Marker fuer
`set -euo pipefail`, kuratierte absolute Helper-Pfade, explizite Opt-in- bzw.
Laufzeitgrenzen, restriktive Log-/Dateirechte und Keine-Secrets-Hinweise. Er
liest keine Backup-Env-Inhalte, Secrets, Dumps, Logs, Antworten, Exporte oder
Quelleninhalte und startet keine Backups, Restores, Docker, rsync, OCR, Imports,
Regressionen, Repairs, Exporte, Restic-, sudo- oder systemd-Aktionen.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Operational-Wrapper-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Script-Permission-Policy-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-script-permission-policy.py
scripts/check-script-permission-policy.py --summary
```

Der Guard ist read-only und prueft metadata-only Dateiart, Modus, Ownership,
Symlink-, World-writable-, Group-writable- und Ausfuehrbarkeits-Policy fuer
`scripts/`, `systemd/`, `docs/` und ausgewaehlte Top-Level-Projektquellen. Die
bekannten nicht ausfuehrbaren Helper-Quellen in `scripts/` sowie `0664`-Doku- und
Unit-Quellen sind dokumentierte Projektquellen; der Guard nimmt keine
`chmod`-/`chown`-Remediation vor. Erwarteter Marker ist
`script_permission_policy_status=ok` mit `executable_policy_failures=0`,
`world_writable=0`, `symlinks=0` und `owner_mismatches=0`.
Der bewusst enge Top-Level-Scope umfasst nur `.env.example`, `.gitignore`,
`Dockerfile`, `README.md`, `docker-compose.yml` und `requirements.txt`; Runtime-
Artefakte, Secrets, Dumps, Logs, Exporte und generierte Dateien bleiben bei
Artifact-, Git- und Storage-Guards.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Script-Permission-Policy-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Access-Runtime-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-access-runtime-source-hardening.py
scripts/check-access-runtime-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen der runtime- und
zugriffsnahen Guards `check-runtime-http-security.py`,
`check-external-access-surface.py`, `check-external-cookie-security.py`,
`check-tls-certificate.py` und `check-app-auth-surface.py`. Geprueft werden
metadata-only-/keine-Credentials-Hinweise, erwartete Header-/Cookie-/TLS-/CSRF-
Marker, Cloudflare-/Basic-Auth-Pfade, TLS-SNI-/SAN-/Ablaufmarker,
Container-interne Auth-Negativproben und Summary-Ausgaben. Er liest keine
Secrets, Dumps, Logs, Antworten oder Quelleninhalte und ruft keine HTTP-/TLS-
Probes, kein Docker, keine DB-Abfragen, Imports, Backups, Restores oder
Regressionen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Access-Runtime-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Network-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-network-source-hardening.py
scripts/check-network-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen der Netzwerk- und
Exposure-Guards. Er validiert erwartete Marker fuer Loopback-Proxy, Cloudflared-
Tunnel, Public-DNS-/Multi-Resolver-/Authoritative-DNS-/CAA-Pruefungen,
Direct-Origin-Bypass, Direct-Origin-Port- und Host-UDP-Pruefungen,
iptables-/ip6tables- und nftables-Auswertung, Network-Policy-Konsistenz,
Runtime-Env-Overrides und Runtime-Summary-Invarianten. Er liest keine Secrets,
Dumps, Logs, Antworten oder Quelleninhalte und ruft keine Docker-, DNS-, HTTP-/
TLS-, Firewall-/nft-, Import-, Backup-, Restore-, Regressions- oder DB-Pruefungen
auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Network-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Host-Kontext-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-host-context.py
scripts/check-host-context.py --summary
```

Der Guard ist read-only und prueft, ob die BR-Wissen-Betriebschecks auf dem
erwarteten Zielhost `m11h.eu` laufen. Geprueft werden `hostname`,
`/etc/opencode-host-context` mit `HOST_ROLE=m11h` und `THIS_SERVER=m11h`, die
erwartete Public IPv4 `31.70.74.139`, die erwartete Tailscale IPv4
`100.102.205.121` sowie `M00H_IS_DIFFERENT_SERVER=true`. Er gibt nur
nicht-sensitive Hostmetadaten aus und liest keine Secret-, Dump-, Log- oder
Backup-Env-Inhalte.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Host-Kontext-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Time-Sync-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-time-sync.py
scripts/check-time-sync.py --summary
```

Der Guard ist read-only und prueft Zeit-/NTP-Metadaten ueber `timedatectl` und
`chronyc tracking`. Er stellt sicher, dass NTP synchron ist und chrony einen
plausiblen Stratum, niedrigen System-/RMS-Offset und `Leap status: Normal` meldet.
Die optionale `SystemClockSynchronized`-Property wird nur dann failend gewertet,
wenn sie auf diesem System verfuegbar ist und explizit `no` meldet; fehlt sie,
erscheint in der Summary `system_clock=-1`. Der Guard aendert keine Zeitdienste
und gibt keine NTP-Servernamen, Secrets, Logs, Dumps, Antworten oder
Quelleninhalte aus.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Time-Sync-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Compose-Service-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-compose-services.py
scripts/check-compose-services.py --summary
```

Der Guard ist read-only und prueft nur Docker-Compose-Metadaten. Erwartet werden
genau die fuenf Services `app`, `db`, `worker`, `proxy` und `cloudflared`.
Alle fuenf muessen `running` sein; `app` und `db` muessen zusaetzlich `healthy`
melden. Der Guard liest keine Containerlogs, Secret-, Dump-, Antwort- oder
Quelleninhalte. Im Live-Betrieb auf `m11h` ist `cloudflared` trotz Compose-
`profile: tunnel` bewusst Pflicht, weil der Cloudflare-Tunnel zum erwarteten
Live-Stack gehoert. Der Parser akzeptiert sowohl zeilenweise JSON-Objekte als
auch JSON-Array-Ausgaben von `docker compose ps --format json`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Compose-Service-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Privilege-Policy-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-privilege-policy.py
scripts/check-privilege-policy.py --summary
```

Der Guard ist read-only und prueft mit `sudo -n -l -U chris` nur aggregierte
Policy-Metadaten der effektiven sudo-Rechte des BR-Betriebsnutzers. Er gibt keine
sudoers-Inhalte, keine vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs,
Antworten oder Quelleninhalte aus. Breite Rechte wie `(ALL) NOPASSWD: ALL`
erscheinen als `broad_sudo=1`, `nopasswd_all=1` und `unrestricted_all=1`, werden
aber nicht als Finding gewertet, weil eine echte sudoers-Restriktion ein eigener,
systemweiter Migrationsblock mit vorheriger Freigabe und Lockout-Schutz waere.
Aktueller erwarteter Marker: `privilege_policy_status=ok`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Privilege-Policy-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Privilege-Risk-Review-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-privilege-risk-review.py
scripts/check-privilege-risk-review.py --summary
```

Der Guard ist read-only und verknuepft den aktuellen aggregierten
Privilege-Policy-Status mit der Risikoakzeptanz in
`docs/PRIVILEGE-RISK-REVIEW.md`. Bei `broad_sudo=1` erwartet er eine bewusste
Akzeptanz (`risk_acceptance_status=accepted`), einen Folgeauftrag
(`least_privilege_followup=required`) und den Marker
`sudoers_auto_change_allowed=0`. Zusaetzlich prueft er `last_review_date` und
`next_review_due`, damit der monatliche Review nicht nur als Absicht, sondern als
faelliger Nachweis sichtbar bleibt. Er gibt keine sudoers-Inhalte, keine
vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs, Antworten oder
Quelleninhalte aus und aendert keine sudoers-Konfiguration. Bei akzeptiertem
kritischem Privilegienrisiko meldet er bewusst
`privilege_risk_review_status=accepted_risk` und `critical_privilege_risk=1`,
statt ein irrefuehrendes `ok` auszugeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Privilege-Risk-Review-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Privilege-Least-Privilege-Plan-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-privilege-least-privilege-plan.py
scripts/check-privilege-least-privilege-plan.py --summary
```

Der Guard ist read-only und prueft den konkreten Folgeplan in
`docs/PRIVILEGE-LEAST-PRIVILEGE-PLAN.md`. Erwartet werden `plan_status=planned`,
`target_due`, `requires_lockout_protection=1`, `requires_rollback_plan=1`,
`requires_visudo_validation=1`, `requires_backup_before_change=1`,
`requires_command_inventory=1`, `requires_staged_rollout=1` und
`sudoers_auto_change_allowed=0`. Er gibt keine sudoers-Inhalte, keine
vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs, Antworten oder
Quelleninhalte aus und aendert keine sudoers-Konfiguration. Aktueller erwarteter
Marker: `privilege_least_privilege_plan_status=planned`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Privilege-Least-Privilege-Plan-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Privilege-Remediation-Gate-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-privilege-remediation-gate.py
scripts/check-privilege-remediation-gate.py --summary
```

Der Guard ist read-only und prueft das geschlossene Remediation-Gate in
`docs/PRIVILEGE-REMEDIATION-GATE.md` gegen Risk-Review und Least-Privilege-Plan.
Erwartete Marker sind `privilege_remediation_gate_status=closed`,
`remediation_allowed=0`, `actual_sudoers_change_allowed=0`,
`accepted_risk_visible=1` und `remediation_complete=0`. Damit wird verhindert,
dass `accepted_risk` oder `planned` als erledigte sudoers-Haertung missverstanden
werden. Der Guard gibt keine sudoers-Inhalte, keine vollstaendigen Kommandolisten,
keine Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte aus und aendert keine
sudoers-Konfiguration.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Privilege-Remediation-Gate-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Privilege-No-Sudoers-Change-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-privilege-no-sudoers-change.py
scripts/check-privilege-no-sudoers-change.py --summary
```

Der Guard ist read-only und prueft die Nutzerentscheidung in
`docs/PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md`: In diesem Arbeitsstrang werden keine
sudoers-Aenderungen vorgenommen. Erwartete Marker sind
`privilege_no_sudoers_change_status=active`, `sudoers_changes_allowed=0`,
`sudoers_remediation_requested=0`, `actual_sudoers_change_allowed=0`,
`remediation_complete=0` und `accepted_risk_continues=1`. Der Guard gibt keine
sudoers-Inhalte, keine vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs,
Antworttexte oder Quelleninhalte aus und aendert keine sudoers-Konfiguration.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Privilege-No-Sudoers-Change-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Core-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-core-source-hardening.py
scripts/check-core-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen von
`scripts/check-host-context.py`, `scripts/check-time-sync.py`,
`scripts/check-compose-services.py`, `scripts/check-privilege-policy.py`,
`scripts/check-privilege-risk-review.py`,
`scripts/check-privilege-least-privilege-plan.py`,
`scripts/check-privilege-remediation-gate.py`,
`scripts/check-privilege-no-sudoers-change.py`, `scripts/check-project-artifacts.sh` und
`scripts/check-runtime-log-markers.sh`. Geprueft werden metadata-only Host-
Kontext-, Zeit-/NTP-, Compose-Service-, Privilege-Policy-, Privilege-Risk-Review-, Privilege-Least-Privilege-Plan-, Privilege-Remediation-Gate-, Privilege-No-Sudoers-Change-, Artefakt- und Runtime-Log-Marker,
kompakte Summary-Ausgaben sowie verbotene mutierende bzw. inhaltslesende Marker.
Er liest keine Secrets, Dumps, Logs, Antworten oder Quelleninhalte und ruft kein
Docker, kein Compose, kein `timedatectl`, kein `chronyc`, kein `hostname`, kein
Tailscale, keine Backups, Restores, Imports, Regressionen oder DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Core-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Container-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-container-hardening.py
scripts/check-container-hardening.py --summary
```

Der Guard ist read-only und prueft nur Docker-Inspect-Metadaten fuer die erwarteten
Container `br-wissen-app`, `br-wissen-db`, `br-wissen-worker`,
`br-wissen-proxy` und `br-wissen-cloudflared`. Er faellt bei `Privileged=true`,
zusaetzlichen Capabilities, Device-Mounts, Host-/Sonder-Namespaces, unerwarteten
Netzwerken, unerwarteten Port-Bindings, fehlenden erwarteten Mounts, schreibbar
gemounteten Secret-/Konfigurationspfaden, fehlendem read-only RootFS, fehlendem
`no-new-privileges`, fehlenden Ressourcenlimits, unerwarteten Runtime-Usern,
fehlendem `cap_drop: ALL` fuer App/DB/Worker/Cloudflared oder abweichender Restart-Policy.
Env-Werte, Logs, Dateiinhalte, Dumps, Antworten oder Quelleninhalte werden nicht
gelesen oder ausgegeben. Der aktuelle Betriebszustand erzwingt read-only RootFS,
`no-new-privileges` und Ressourcenlimits fuer alle fuenf Container. App, DB,
Worker und Cloudflared droppen alle Capabilities; der Caddy-Proxy laeuft als
Nicht-root-User `1001:127`, bleibt aber bei `cap_drop: ALL` bewusst ausgenommen,
weil Caddy damit nicht stabil startete. Caddy-`/data` und `/config` sind tmpfs-
Runtimepfade.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Container-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Container-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-container-source-hardening.py
scripts/check-container-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen von
`scripts/check-container-hardening.py`, `scripts/check-container-images.sh`,
`scripts/check-image-pinning-guard.sh` und
`scripts/check-image-pinning-readiness.sh`. Geprueft werden metadata-only
Docker-Inspect-, Compose-Image-, laufende-Container-Image-, Dockerfile-`FROM`-,
Digest-Pinning-, lokale Build-Ausnahme-, optionaler Remote-Readiness- und
Summary-Marker sowie verbotene mutierende bzw. inhaltslesende Marker. Er liest
keine Secrets, Dumps, Logs, Antworten oder Quelleninhalte und ruft kein Docker,
kein Compose, keine Registry-Lookups, keine Backups, Restores, Imports,
Regressionen oder DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Container-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Compose-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-compose-source-hardening.py
scripts/check-compose-source-hardening.py --summary
```

Der Guard prueft die statische Compose-Quelle `docker-compose.yml`, ohne
`docker compose config` aufzurufen und ohne Env-Dateien zu expandieren. Er
validiert erwartete Services, read-only RootFS, `no-new-privileges`,
`cap_drop: ALL` fuer App/DB/Worker/Cloudflared, die dokumentierte Caddy-Proxy-
Ausnahme, tmpfs inklusive Caddy-`/data` und `/config`, Ressourcenlimits,
Mount-Modi, Port-/Expose-Regeln und User-Marker fuer App/Worker/DB/Proxy. Secretwerte, Logs, Dumps, Antworten oder
Quelleninhalte werden nicht gelesen oder ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Compose-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Guard-Coverage-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-guard-coverage.py
scripts/check-guard-coverage.py --summary
```

Der Guard ist read-only und prueft die Verdrahtung der bestehenden Guard-Skripte
ueber Statuscheck, Backup-Preflight, Projekt- und installierte
systemd-Healthcheck-Unit sowie zentrale Readiness-Marker. Er ist als Meta-Schutz
gedacht: Wenn kuenftig ein Guard nur an einer Flaeche ergaenzt oder entfernt
wird, faellt die Drift frueh auf. Er liest nur Projektquellen, Readiness-Doku und
Unit-Text; Secretwerte, Backup-Env-Inhalte, Dumps, Logs, Antworttexte oder
Quelleninhalte werden nicht gelesen oder ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Guard-Coverage-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Meta-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-meta-source-hardening.py
scripts/check-meta-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Meta-/Governance-
Guardquellen `scripts/check-guard-coverage.py`, `scripts/check-readiness-doc.py`,
`scripts/check-python-syntax.sh`, `scripts/check-shell-syntax.sh` und
`scripts/check-systemd-units.sh`. Geprueft werden erwartete Marker fuer Guard-
Verdrahtung, Readiness-Pflichtmarker, nicht-zirkulaere Summary-Erwartungen,
cachefreie Python-AST-Pruefung, `bash -n`-Shell-Pruefung, systemd-Unit-Sync-
Pruefung, aktive Timer, failed-Service-Erkennung, kompakte Summaries und
verbotene mutierende bzw. inhaltslesende Marker. Er liest keine Secrets, Dumps,
Logs, Antworten, Exporte oder Quelleninhalte und ruft keine Meta-Guards, kein
`systemctl`, kein Docker, keine Backups, Restores, Imports, Regressionen oder
DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Meta-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Doku-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-doc-source-hardening.py
scripts/check-doc-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Dokumentationsquellen
`README.md`, `docs/RUNBOOK.md`, `systemd/README.md` und `docs/READINESS.md`.
Geprueft werden Betriebs-, Guardrail-, Backup-/Restore-, systemd-Healthcheck-,
Readiness-, Protokoll- und Keine-Secrets-Marker sowie verbotene Credential-
Marker. Er liest keine Secrets, Dumps, Logs, Antworten oder Quelleninhalte und
ruft keine Statuschecks, kein Docker, kein `systemctl`, keine Backups, Restores,
Imports, Regressionen oder DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Doku-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Source-Hardening-Coverage-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-source-hardening-coverage.py
scripts/check-source-hardening-coverage.py --summary
```

Der Guard ist read-only und prueft ausschliesslich das `scripts/check-*`-Inventar.
Er validiert, dass jede Check-Datei entweder in einer dokumentierten Source-
Hardening-Gruppe abgedeckt ist, selbst eine Source-Hardening-/Governance-Schicht
bildet oder als explizite Legacy-/Hilfs-Ausnahme dokumentiert ist. Definitionen:
Eine Source-Hardening-Gruppe ist eine statische Quellenpruefung fuer eine fachlich
zusammengehoerige Guard-Familie; eine Governance-Schicht prueft Verdrahtung,
Readiness, Syntax, Doku oder Inventar; eine Legacy-/Hilfs-Ausnahme ist bewusst
nicht in Status/Backup/Healthcheck integriert und muss explizit benannt sein.
Damit fallen neue Checks ohne passende Quellenhaertung frueh auf. Er liest keine
Secrets, Dumps, Logs, Antworten oder Quelleninhalte und ruft keine Guards, kein
Docker, kein `systemctl`, keine Backups, Restores, Imports, Regressionen oder
DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Source-Hardening-Coverage`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Summary-Contract-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-summary-contracts.py
scripts/check-summary-contracts.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Summary-/Statuskey-
Vertraege der zentralen `GuardSpec`-Liste aus `scripts/check-guard-coverage.py`.
Er validiert statisch, dass jeder deklarierte `status_key` in der jeweiligen
Skriptquelle vorkommt und dass `--summary`-integrierte Guards einen passenden
Summary-Vertrag in ihrer Quelle abbilden. Die bekannte Ausnahme ist der
`Runtime-Log-Marker`, der ohne `--summary` in den Healthcheck eingebunden ist. Er
liest keine Secrets, Dumps, Logs, Antworten oder Quelleninhalte und ruft keine
Guards, kein Docker, kein `systemctl`, keine Backups, Restores, Imports,
Regressionen oder DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Summary-Contract-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Surface-Registry-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-surface-registry.py
scripts/check-surface-registry.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die zentrale `GuardSpec`-
Registry sowie die operationalen Oberflaechen `scripts/status-br-wissen.sh`,
`scripts/backup-br-wissen.sh`, `systemd/br-wissen-healthcheck.service` und die
installierte Healthcheck-Unit. Er validiert, dass Status, Backup-Preflight und
Healthcheck die Registry in Reihenfolge und ohne verdeckte Extra-/Missing-
Check-Aufrufe spiegeln. Bewusste Status-only-Hilfen wie
`check-container-images.sh` und `check-image-pinning-readiness.sh` sind explizit
als Detailausnahmen dokumentiert. Er liest keine Secrets, Dumps, Logs, Antworten
oder Quelleninhalte und ruft keine Guards, kein Docker, kein `systemctl`, keine
Backups, Restores, Imports, Regressionen oder DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Surface-Registry-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Guard-Registry-Integrity pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-guard-registry-integrity.py
scripts/check-guard-registry-integrity.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die zentrale `GuardSpec`-
Registry aus `scripts/check-guard-coverage.py`. Er validiert, dass Labels,
Skripte, Statuskeys und Backup-Labels eindeutig sind, dass referenzierte Check-
Skripte vorhanden und ausfuehrbar sind, dass Statuskeys und Backup-Labels den
erwarteten Namensformen entsprechen und dass nur dokumentierte Argumentvertraege
verwendet werden. Er liest keine Secrets, Dumps, Logs, Antworten oder
Quelleninhalte und ruft keine Guards, kein Docker, kein `systemctl`, keine
Backups, Restores, Imports, Regressionen oder DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Guard-Registry-Integrity`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Protocol-Integrity-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-protocol-integrity.py
scripts/check-protocol-integrity.py --summary
```

Der Guard ist read-only und prueft ausschliesslich das Projektprotokoll
`/home/chris/web/diverses/betriebsrat.md` sowie die Backup-Wrapper-Quelle fuer
die Protokoll-Einbindung. Er validiert Strukturmarker, aktuelle Guardrail-
Wartungsbloecke, Backup-/Restore-/Healthcheck-Marker, `protocol_file_status=included`
und offensichtliche Credential-/Header-Leak-Marker. Er liest keine Secrets,
Dumps, Logs, Antworten oder Quelleninhalte und ruft keine Guards, kein Docker,
kein `systemctl`, keine Backups, Restores, Imports, Regressionen oder DB-Abfragen
auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Protocol-Integrity-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Git-Remote-Readiness pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-git-remote-readiness.py
scripts/check-git-remote-readiness.py --summary
```

Der Guard ist read-only und prueft ausschliesslich Git-Metadaten des Projektbaums
und die GitHub-Remote-Head-Sicht. Erwartet werden Branch `main`, Remote
`git@github.com:scheffe2804/scheffe2804-br.m11h.eu.git`, Tracking auf
`origin/main`, gleicher lokaler und remote HEAD, ein sauberer Arbeitsbaum und ein
Git-Index ohne typische Secret-, Dump-, Credential-, Backup- oder Runtime-
Artefakte. `.env.example` ist als nicht-sensitives Beispiel bewusst erlaubt. Im
Root-Backup-Kontext liest der Guard Git-Metadaten per `sudo -n -u <Projektbesitzer>`
als Projektbesitzer; die Summary zeigt dies als `git_user=`.

Der Guard liest keine Secretdateien, gibt keine Diffs oder Dateiinhalte aus und
fuehrt kein Commit, Push, Pull, Fetch, Backup, Restore, Docker, `systemctl`,
Import, Regression oder DB-Abfragen aus. Aktueller Marker:
`git_remote_readiness_status=ok` fuer GitHub-Repo
`scheffe2804/scheffe2804-br.m11h.eu`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Git-Remote-Readiness`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

Bei laufender Entwicklung darf der Einzelaufruf wegen `dirty=1` rot sein; vor
Backup-/Healthcheck-Abschluss muss der Arbeitsstand committed und nach GitHub
gepusht sein.

## Backup-Scope-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-backup-scope.py
scripts/check-backup-scope.py --summary
```

Der Guard ist read-only und validiert metadata-only den neuesten BR-Wissen-
Restic-Snapshot auf erwarteten Host, Tags und Backup-Pfade. Die root-noetige
Restic-Metadatenabfrage laeuft ueber kuratierte absolute Helferpfade
(`/usr/bin/sudo`, `/usr/bin/test`, `/usr/bin/bash` und `/usr/bin/restic` oder
`/usr/local/bin/restic`) statt ueber den Root-`PATH`. Diese Helfer werden auf
Existenz, Symlink-Freiheit, regulaeren Dateityp, `root:root`, Modus,
Ausfuehrbarkeit und unerwartete Sonderbits geprueft. Die Summary meldet neben
`backup_scope_status=ok` auch `helper_binaries=<n>` und `restic_binary=<pfad>`.

Der Guard ist read-only und prueft ausschliesslich Restic-Snapshot-Metadaten des
neuesten BR-Wissen-Backups auf erwarteten Host, erwartete Tags und den erwarteten
Backup-Pfadumfang fuer App, internen Datenbereich und Projektprotokoll. Er nutzt
die root-only Backup-Env nur fuer die Snapshot-Metadatenabfrage, startet keine
Backups oder Restores, ruft kein Docker, kein `systemctl`, keine Imports,
Regressionen oder DB-Abfragen auf und gibt keine Backup-Secretwerte, Dumps, Logs,
Antworttexte, Exporte oder Quelleninhalte aus. Die kompakte Summary enthaelt nur
Status, Zaehler und kurze Snapshot-ID.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Backup-Scope-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Backup-Runtime-Policy-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-backup-runtime-policy.py
scripts/check-backup-runtime-policy.py --summary
```

Der Guard ist read-only und prueft ausschliesslich Metadaten des Backup-
Ausfuehrungsumfelds: Backup-Env-Datei, deren Elternverzeichnis, Restic-Binary und
installierte Backup-Service-Policy. Erwartet werden root-only Backup-Env-Rechte,
restriktiver Parent-Modus, ein nicht setuid/setgid gesetztes Restic-Binary und
`User=root` fuer `br-wissen-backup.service`. Er liest keine Backup-Env-Inhalte,
Secretwerte, Dumps, Logs, Antworten, Exporte oder Quelleninhalte und startet
keine Backups, Restores, Docker, Imports, Regressionen oder DB-Abfragen. Der
root-noetige JSON-Hilfsmodus nutzt `/usr/bin/sudo`; Restic wird nur aus
`/usr/bin/restic` oder `/usr/local/bin/restic` ausgewaehlt und metadata-only auf
Symlink-Freiheit, regulaere Datei, `root:root`, Modus, Ausfuehrbarkeit und
unerwartete Sonderbits geprueft. Die Summary zeigt `helper_binaries=<n>` und
`restic_binary=<pfad>`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Backup-Runtime-Policy-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Restore-Runtime-Policy-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-restore-runtime-policy.py
scripts/check-restore-runtime-policy.py --summary
```

Der Guard ist read-only und prueft ausschliesslich Metadaten des Restore-Smoke-
Ausfuehrungsumfelds: Backup-Env-Datei, Restore-Skripte, Restic-/Docker-Binaries,
`/tmp` sowie installierte Restore-Smoke-Service-/Timer-Policy. Erwartet werden
restriktive Backup-Env-Rechte, nicht gruppenschreibbare Restore-Skripte, kuratierte
Restic-/Docker-Systempfade, keine setuid/setgid-Binaries, `User=root` fuer den
Restore-Smoke-Service und die dokumentierte persistente Wochenplanung. Der Guard
liest keine Backup-Env-Inhalte, Secretwerte, Dumps, Logs, Antworten, Exporte oder
Quelleninhalte und startet keine Backups, Restores, Docker, Imports, Regressionen
oder DB-Abfragen. Der root-noetige JSON-Hilfsmodus nutzt `/usr/bin/sudo`; Restic
und Docker werden nur aus `/usr/bin/restic` oder `/usr/local/bin/restic` bzw.
`/usr/bin/docker` oder `/usr/local/bin/docker` ausgewaehlt und metadata-only auf
Symlink-Freiheit, regulaere Datei, `root:root`, Modus, Ausfuehrbarkeit und
unerwartete Sonderbits geprueft. Die Summary zeigt `helper_binaries=<n>`,
`restic_binary=<pfad>` und `docker_binary=<pfad>`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Restore-Runtime-Policy-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Regression-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-regression-source-hardening.py
scripts/check-regression-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen des Opt-in-
Regressionsrunners `scripts/run-regressions.py`, dessen Docker-Wrapper
`scripts/run-regressions-docker.sh` sowie den read-only Freshness-Guard
`scripts/check-regression-freshness.py`. Geprueft werden die vier Kernfaelle,
erwartete Creator-/Citation-/Klassen-/Quellen-Pruefungen, Export-HTML/PDF,
Manifest- und Safety-Marker, Wrapper-`cd` und `docker compose exec -T app python`,
Freshness-SQL-Marker, Storage-Pfadschutz, Altersgrenze und verbotene mutierende
Marker. Er liest keine Secrets, Dumps, Logs, Antworten oder Quelleninhalte und
ruft keine Regressionen, kein Docker, keine DB-Abfragen, Imports, Backups oder
Restores auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Regression-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Freshness-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-freshness-source-hardening.py
scripts/check-freshness-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen von
`scripts/check-backup-freshness.py` und `scripts/check-restore-freshness.py`.
Geprueft werden metadata-only Sammlung, sudo-JSON-Hilfsmodi, Backup-/Restore-Log-
 und Dump-Marker, Retention, Age-Grenzen, Backup-Env-Metadaten, Restic-Snapshot-
 und Lock-Marker, Restore-Smoke-Marker, DB-Isolation, Dump-/Manifest-/Protokoll-
Marker sowie kompakte Summary-Ausgaben. Er liest keine Secrets, Dumps, Logs,
Antworten oder Quelleninhalte und ruft keine Freshness-Checks, kein `sudo`, kein
Restic, kein Docker, keine Backups, Restores, Imports oder DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Freshness-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Storage-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-storage-source-hardening.py
scripts/check-storage-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen von
`scripts/check-storage-permissions.py` und `scripts/check-storage-capacity.py`.
Geprueft werden metadata-only Rechte-, Owner-, Symlink-, Secret-Kandidaten-,
Cloudflared-Credential-, Dump-/Log-Mode-, Filesystem-, Inode-, Docker-DF- und
Kapazitaets-Summary-Marker sowie verbotene mutierende bzw. inhaltslesende Marker.
Er liest keine Secrets, Dumps, Logs, Antworten oder Quelleninhalte und ruft keine
Storage-Checks, kein `sudo`, kein Docker, keine Backups, Restores, Imports oder
DB-Abfragen auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Storage-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Network-Exposure-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-network-exposure.py
scripts/check-network-exposure.py --summary
```

Der Guard ist read-only und prueft nur Netzwerk-Metadaten aus Docker Compose,
laufenden Compose-Containern, Caddy-Konfiguration, Cloudflare-Tunnel-Konfiguration,
lokalen TCP-Listenern und nft-Firewall-Metadaten. Erwartet wird genau die lokale Proxy-Publikation
`127.0.0.1:18083 -> 8080`; andere BR-Wissen-Publikationen auf Nicht-Loopback-
Interfaces werden als Fehler gemeldet. Zusaetzlich prueft der Guard Caddy auf
`:8080`, Basic Auth, Noindex-/NoStore-Header und `reverse_proxy app:8000` sowie
Cloudflared auf Hostname `br.m11h.eu`, Service `http://proxy:8080`, 404-Fallback
und einen Credential-Pfad unter `/run/br-secrets/cloudflared/`. Credential-
Dateien, Secretwerte, Logs, Dumps, Antworten oder Quelleninhalte werden nicht
gelesen oder ausgegeben. Zusaetzlich zaehlt der Guard metadata-only, ob nft-
NAT-/Redirect-Regeln den lokalen BR-Wissen-Port `18083` erwaehnen; die Regeln
selbst werden nicht ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Network-Exposure-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Public-DNS-Exposure-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-public-dns-exposure.py
scripts/check-public-dns-exposure.py --summary
```

Der Guard ist read-only und prueft die oeffentliche DNS-Aufloesung von
`br.m11h.eu` ueber lokale Resolver-Metadaten. Erwartet werden globale A-/AAAA-
Adressen, aber keine direkte Origin-Exposition: `31.70.74.139` und
`100.102.205.121` duerfen nicht als DNS-Ziel erscheinen. Der aktuelle Live-Stand
zeigt Cloudflare-Adressen (`a_records=2`, `aaaa_records=2`, `forbidden_hits=0`).
DNS-Zonen, Cloudflare-Einstellungen, Secrets, Logs, Dumps, Antworten oder
Quelleninhalte werden nicht gelesen oder geaendert.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_PUBLIC_DNS_HOST` — Standard `br.m11h.eu`.
- `BR_PUBLIC_DNS_FORBIDDEN_IPS` — kommaseparierte verbotene Origin-/interne IPs,
  Standard `31.70.74.139,100.102.205.121`.
- `BR_PUBLIC_DNS_REQUIRE_A` — Standard `1`, verlangt mindestens einen A-Record.
- `BR_PUBLIC_DNS_ALLOW_AAAA` — Standard `1`, erlaubt AAAA-Aufloesung.

Bei Aenderungen an Origin-/Tailscale-/Tunnel-IP-Adressen muss die Forbidden-IP-
Liste im Change-Management mitgeprueft werden.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Public-DNS-Exposure-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Public-DNS-Multiresolver-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-public-dns-multiresolver.py
scripts/check-public-dns-multiresolver.py --summary
```

Der Guard ist read-only und fragt standardmaessig die rekursiven Resolver
`1.1.1.1`, `8.8.8.8` und `9.9.9.9` direkt per DNS-UDP nach A-/AAAA-Metadaten
fuer `br.m11h.eu`. Er ergaenzt den lokalen Public-DNS-Exposure-Guard um eine
unabhaengigere Resolver-Perspektive. Erwartet werden mindestens zwei erfolgreiche
Resolver, globale Records und keine direkte Origin-Exposition: `31.70.74.139`
und `100.102.205.121` duerfen nicht als DNS-Ziel erscheinen. Der aktuelle
Live-Stand zeigt bei drei erfolgreichen Resolvern Cloudflare-Adressen
(`a_records=6`, `aaaa_records=6`, `unique_records=4`, `forbidden_hits=0`).
DNS-Zonen, Cloudflare-Einstellungen, Secrets, Logs, Dumps, Antworten oder
Quelleninhalte werden nicht gelesen oder geaendert.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_PUBLIC_DNS_HOST` — Standard `br.m11h.eu`.
- `BR_PUBLIC_DNS_MULTI_RESOLVERS` — kommaseparierte Resolverliste, Standard
  `1.1.1.1,8.8.8.8,9.9.9.9`.
- `BR_PUBLIC_DNS_MULTI_MIN_SUCCESS` — Standard `2`.
- `BR_PUBLIC_DNS_MULTI_TIMEOUT` — Standard `4` Sekunden pro DNS-Frage.
- `BR_PUBLIC_DNS_FORBIDDEN_IPS` — kommaseparierte verbotene Origin-/interne IPs,
  Standard `31.70.74.139,100.102.205.121`.
- `BR_PUBLIC_DNS_REQUIRE_A` — Standard `1`, verlangt A-Records je erfolgreichem
  Resolver.
- `BR_PUBLIC_DNS_ALLOW_AAAA` — Standard `1`, erlaubt AAAA-Aufloesung.

Bei Aenderungen an Origin-/Tailscale-/Tunnel-IP-Adressen muss die Forbidden-IP-
Liste im Change-Management mitgeprueft werden. Wenn ein einzelner externer
Resolver kurzzeitig nicht erreichbar ist, bleibt der Guard durch
`BR_PUBLIC_DNS_MULTI_MIN_SUCCESS=2` tolerant; systematische Fehler oder direkte
Origin-Treffer schlagen fehl. Der Guard fuehrt bewusst keine DNSSEC-Validierung
durch; die Resolverliste selbst bleibt deshalb Teil des Change-Managements.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Public-DNS-Multiresolver-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Public-DNS-Authoritative-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-public-dns-authoritative.py
scripts/check-public-dns-authoritative.py --summary
```

Der Guard ist read-only und ermittelt zuerst die NS-Records der Zone `m11h.eu`
ueber einen Bootstrap-Resolver. Danach fragt er die autoritativen Nameserver-
Adressen direkt ohne Recursion-Desired-Flag nach A-/AAAA-Metadaten fuer
`br.m11h.eu`. Er ergaenzt den lokalen Resolver-Check und den Multi-Resolver-
Check um die autoritative DNS-Sicht. Erwartet werden mindestens eine erfolgreiche
autoritative Nameserver-Adresse, autoritative Antworten, globale Records und
keine direkte Origin-Exposition: `31.70.74.139` und `100.102.205.121` duerfen
nicht als DNS-Ziel erscheinen. Der aktuelle Live-Stand zeigt zwei Nameserver,
zwoelf erreichbare Nameserver-Adressen, 24 autoritative Antworten und vier
eindeutige Cloudflare-Zieladressen (`forbidden_hits=0`). DNS-Zonen, Cloudflare-
Einstellungen, Secrets, Logs, Dumps, Antworten oder Quelleninhalte werden nicht
gelesen oder geaendert. DNSSEC wird bewusst nicht validiert; Bootstrap-Resolver
und Nameserverliste bleiben Teil des Change-Managements.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_PUBLIC_DNS_HOST` — Standard `br.m11h.eu`.
- `BR_PUBLIC_DNS_ZONE` — Standard `m11h.eu`.
- `BR_PUBLIC_DNS_AUTH_BOOTSTRAP_RESOLVER` — Standard `1.1.1.1`.
- `BR_PUBLIC_DNS_AUTH_MIN_SUCCESS` — Standard `1`.
- `BR_PUBLIC_DNS_AUTH_TIMEOUT` — Standard `4` Sekunden pro DNS-Frage.
- `BR_PUBLIC_DNS_FORBIDDEN_IPS` — kommaseparierte verbotene Origin-/interne IPs,
  Standard `31.70.74.139,100.102.205.121`.
- `BR_PUBLIC_DNS_REQUIRE_A` — Standard `1`, verlangt A-Records je erfolgreicher
  Autoritaet.
- `BR_PUBLIC_DNS_ALLOW_AAAA` — Standard `1`, erlaubt AAAA-Aufloesung.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Public-DNS-Authoritative-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Public-DNS-CAA-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-public-dns-caa.py
scripts/check-public-dns-caa.py --summary
```

Der Guard ist read-only und fragt CAA-Metadaten fuer `br.m11h.eu` und `m11h.eu`
ueber einen oeffentlichen Resolver ab. Er gibt nur Zaehler aus, keine DNS-
Antwortinhalte, Secretwerte, Logs, Dumps, Antworten oder Quelleninhalte. Ziel ist
zu erkennen, ob spaetere CAA-Records den aktuellen Let's-Encrypt-Pfad blockieren
oder unbekannte kritische CAA-Properties setzen. Der aktuelle Live-Stand zeigt
keine CAA-Records (`caa_records=0`) und deshalb `unrestricted=1` sowie
`letsencrypt_allowed=1`.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_PUBLIC_DNS_HOST` — Standard `br.m11h.eu`.
- `BR_PUBLIC_DNS_ZONE` — Standard `m11h.eu`.
- `BR_PUBLIC_DNS_CAA_RESOLVER` — Standard `1.1.1.1`.
- `BR_PUBLIC_DNS_CAA_TIMEOUT` — Standard `4` Sekunden.
- `BR_PUBLIC_DNS_CAA_ALLOWED_CA` — Standard `letsencrypt.org`.

DNSSEC wird bewusst nicht validiert; Resolverwahl und CAA-Policy bleiben Teil des
Change-Managements. Wenn CAA-Records eingefuehrt werden, muss mindestens der
aktuelle CA-Pfad explizit erlaubt bleiben oder die Guard-Konfiguration bewusst
angepasst werden.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Public-DNS-CAA-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Direct-Origin-Bypass-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-direct-origin-bypass.py
scripts/check-direct-origin-bypass.py --summary
```

Der Guard ist read-only und sendet `HEAD`-Anfragen mit `Host: br.m11h.eu` an die
bekannten IPv4-/IPv6-Origin- und Tailscale-Ziele `31.70.74.139`,
`2a01:239:4ba:bf00::1`, `100.102.205.121` und
`fd7a:115c:a1e0::f233:cd79` auf HTTP/HTTPS fuer `/`, `/healthz`, `/login`,
`/queries`, `/sources`, `/answers`, `/search` und `/validation`. Antwortkoerper
werden nicht gelesen; ausgewertet werden nur Verbindungsstatus, HTTP-Status und
Header-Metadaten. Host/Header- und Pfadwerte werden gegen CR/LF-Injection und
nicht absolute Pfade geprueft. Der aktuelle Live-Stand zeigt 64 Probes: 56 sind
geblockt bzw. per Transport/TLS nicht nutzbar, acht sind reine HTTP-Redirects auf
`https://br.m11h.eu/...`, und `valid_https=0`, `bypass_findings=0` sowie
`unsafe_http=0`. HTTPS-Probes nutzen normale Zertifikatsvalidierung fuer
`br.m11h.eu`; jede direkt gueltig nutzbare HTTPS-Antwort am Origin waere failend.
Damit ist kein direkter Inhalts-/Access-Bypass um Cloudflare Access sichtbar.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_DIRECT_ORIGIN_HOST` — Standard `br.m11h.eu`.
- `BR_DIRECT_ORIGIN_TARGETS` — Standard `31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79`.
- `BR_DIRECT_ORIGIN_PATHS` — Standard `/,/healthz,/login,/queries,/sources,/answers,/search,/validation`.
- `BR_DIRECT_ORIGIN_TIMEOUT` — Standard `5` Sekunden.
- `BR_DIRECT_ORIGIN_HTTP_PORT` — Standard `80`.
- `BR_DIRECT_ORIGIN_HTTPS_PORT` — Standard `443`.

Wenn Origin-/Tailscale-IP-Adressen oder direkte Listener bewusst geaendert
werden, muss die Targetliste im Change-Management mitgepflegt werden. Die
Targetliste ist bewusst IP-basiert; benannte Ziele werden als Konfigurationsfehler
abgelehnt, damit kein DNS-/Alias-Pfad die Bezugsgrundlage verschiebt. Firewall-,
DNS-, Caddy- oder App-Konfiguration werden vom Guard nicht geaendert; Secretwerte,
Logs, Dumps, Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Direct-Origin-Bypass-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Direct-Origin-Port-Exposure-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-direct-origin-port-exposure.py
scripts/check-direct-origin-port-exposure.py --summary
```

Der Guard ist read-only und fuehrt TCP-Connect-Probes ohne Anwendungsdaten gegen
die bekannten IPv4-/IPv6-Origin- und Tailscale-Ziele aus. Der kuratierte BR-
relevante Portsatz ist `80`, `443`, `8000`, `8080`, `18083`, `5432` und `2019`.
Nur `80` und `443` sind als offen erlaubt; die dortige Inhalts-/Access-Semantik
wird separat vom Direct-Origin-Bypass-Guard geprueft. Der aktuelle Live-Stand:
`direct_origin_port_exposure_status=ok`, `targets=4`, `ports=7`, `probes=28`,
`open_total=2`, `allowed_open=2`, `unexpected_open=0`, `closed_or_filtered=26`,
`allowed_ports=80:443`.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_DIRECT_ORIGIN_PORT_TARGETS` — Standard `31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79`.
- `BR_DIRECT_ORIGIN_PORTS` — Standard `80,443,8000,8080,18083,5432,2019`.
- `BR_DIRECT_ORIGIN_ALLOWED_OPEN_PORTS` — Standard `80,443`.
- `BR_DIRECT_ORIGIN_PORT_TIMEOUT` — Standard `2` Sekunden.

Dies ist bewusst kein Voll-Portscan. Wenn weitere direkte Ports, externe
Scanstandorte oder automatische Port-/Listener-Erkennung gewuenscht sind, ist das
ein eigener Change-Management-Block. Firewall-, DNS-, Caddy- oder App-
Konfiguration werden vom Guard nicht geaendert; Secretwerte, Logs, Dumps,
Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Direct-Origin-Port-Exposure-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Host-UDP-/QUIC-Exposure-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-host-udp-exposure.py
scripts/check-host-udp-exposure.py --summary
```

Der Guard ist read-only und prueft lokale Host-/Compose-Metadaten fuer den
kuratierten BR-relevanten UDP-Portsatz `443`, `80`, `8000`, `8080`, `18083`,
`5432` und `2019`. Er sendet keine UDP-Pakete und ist kein externer UDP-Portscan.
Standardmaessig sind auf direkten Origin-/Tailscale-Adressen keine BR-relevanten
UDP-Ports erlaubt; eine direkte UDP-443-/QUIC-Exposition waere also failend.
Loopback-only UDP-Listener gelten nicht als direkte Origin-Exposition. Aktueller
Live-Stand: `host_udp_exposure_status=ok`, `checks=8`, `ports=7`,
`direct_hosts=6`, `relevant_listeners=0`, `direct_relevant_listeners=0`,
`loopback_relevant_listeners=0`, `udp_publishers=1`, `host_udp_published=0`,
`unexpected_host_udp=0`, `allowed_udp_ports=none`.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_HOST_UDP_PORTS` — Standard `443,80,8000,8080,18083,5432,2019`.
- `BR_HOST_UDP_ALLOWED_OPEN_PORTS` — Standard leer, also `none`.
- `BR_HOST_UDP_DIRECT_HOSTS` — Standard `0.0.0.0,::,31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79`; `PUBLIC_IPV4` und `TAILSCALE_IPV4` aus `/etc/opencode-host-context` werden zusaetzlich ergaenzt.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Host-UDP-Exposure-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Host-Firewall-BR-Ports-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-host-firewall-br-ports.py
scripts/check-host-firewall-br-ports.py --summary
```

Der Guard ist read-only und prueft lokale Host-Firewall-/NAT-Metadaten ueber
`sudo -n iptables-save` und `sudo -n ip6tables-save`. Er aendert keine
Firewall-Regeln, sendet keine Pakete, liest keine Secrets und gibt keine
Firewall-Regeltexte aus. Bewertet werden unerwartete direkte INPUT-ACCEPTs oder
DNAT-/REDIRECT-Regeln fuer BR-relevante TCP-Ports `8000`, `8080`, `18083`,
`5432`, `2019` und UDP-Ports `443`, `80`, `8000`, `8080`, `18083`, `5432`,
`2019`. Web-TCP `80`/`443` bleibt als Web-Exposition erlaubt und wird inhaltlich
separat vom Direct-Origin-Bypass-Guard validiert. Die erwartete Loopback-NAT-
Regel `127.0.0.1:18083` ist erlaubt; Docker-interne Bridge-Regeln werden nur
gezaehlt. Aktueller Live-Stand: `host_firewall_br_ports_status=ok`, `checks=313`,
`findings=0`, `direct_hosts=6`, `input_accepts=8`, `unexpected_input_accepts=0`,
`nat_rules=3`, `expected_loopback_nat=1`, `unexpected_nat_rules=0`,
`web_accepts=6`, `docker_bridge_rules=70`.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_FIREWALL_TCP_PORTS` — Standard `8000,8080,18083,5432,2019`.
- `BR_FIREWALL_UDP_PORTS` — Standard `443,80,8000,8080,18083,5432,2019`.
- `BR_FIREWALL_ALLOWED_WEB_TCP_PORTS` — Standard `80,443`.
- `BR_FIREWALL_EXPECTED_LOOPBACK_TCP` — Standard `127.0.0.1:18083`.
- `BR_FIREWALL_DIRECT_HOSTS` — Standard `0.0.0.0,::,31.70.74.139,2a01:239:4ba:bf00::1,100.102.205.121,fd7a:115c:a1e0::f233:cd79`; `PUBLIC_IPV4` und `TAILSCALE_IPV4` aus `/etc/opencode-host-context` werden zusaetzlich ergaenzt.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Host-Firewall-BR-Ports-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Host-NFT-BR-Ports-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-host-nft-br-ports.py
scripts/check-host-nft-br-ports.py --summary
scripts/check-host-nft-br-ports.py --self-test
```

Der Guard ist read-only und prueft die native nftables-Regelsicht ueber
`sudo -n nft -j list ruleset`. Er wertet ausschliesslich strukturierte JSON-
Metadaten aus, gibt keine Firewall-Regeltexte aus, aendert keine Firewall-Regeln
und sendet keine Pakete. Er ergaenzt den iptables-/ip6tables-kompatiblen
Host-Firewall-BR-Ports-Guard, damit nft-native Regeln oder die nft-Backend-Sicht
gesondert auffallen. Bewertet werden unerwartete direkte INPUT-ACCEPTs oder
NAT-/DNAT-/REDIRECT-Regeln fuer dieselben BR-relevanten Ports. Web-TCP `80`/`443`,
die erwartete Loopback-NAT-Regel `127.0.0.1:18083` und Docker-interne Bridge-
Regeln werden analog zum iptables-Guard behandelt. Aktueller Live-Stand:
`host_nft_br_ports_status=ok`, `checks=313`, `findings=0`, `direct_hosts=6`,
`tables=8`, `chains=101`, `rules=308`, `input_accepts=4`,
`unexpected_input_accepts=0`, `nat_rules=3`, `expected_loopback_nat=1`,
`unexpected_nat_rules=0`, `web_exposure_rules=6`, `docker_bridge_rules=90`,
`xt_nat_rules=7`, `native_nat_rules=0`, `traversed_jump_rules=0`,
`unresolved_jump_rules=0`, `chain_traversal_rules=0`,
`chain_traversal_cycles=0`, `set_objects=1`, `set_elements=4`,
`expanded_setref_rules=0`, `expanded_setrefs=0`,
`expanded_anonymous_set_rules=0`, `expanded_anonymous_sets=0`,
`unresolved_setref_rules=0`. Relevante BR-Input- oder NAT-Regeln mit
nicht vollstaendig aufgeloesten nft-Konstrukten wie `lookup`, `map`, `vmap`,
`dynset`, `objref`, `flow` oder Set-Referenzen werden failend als unsupported
gemeldet, soweit sie nicht einfache benannte oder anonyme Sets sind, die aus der
JSON-Sicht read-only expandiert werden koennen. Nicht aufloesbare Set-Referenzen
in relevanten Regeln sind failend. BR-relevante Input-/NAT-Regeln mit
dport-gebundenem `jump` oder `goto`
werden read-only in Zielketten hinein verfolgt; nicht aufloesbare oder zyklische
Zielketten sind failend. Aktuell `unsupported_expr_rules=0`,
`unsupported_jump_rules=0`, `set_objects=1`.
Der integrierte Self-Test meldet aktuell `nft_selftest_status=ok cases=19
failed=0` und nutzt nur synthetische JSON-Regeln, ohne die echte Firewall zu
beruehren.

Konfigurierbare Umgebungsvariablen fuer Sonderfaelle:

- `BR_NFT_TCP_PORTS` — Standard aus `BR_FIREWALL_TCP_PORTS` bzw. `8000,8080,18083,5432,2019`.
- `BR_NFT_UDP_PORTS` — Standard aus `BR_FIREWALL_UDP_PORTS` bzw. `443,80,8000,8080,18083,5432,2019`.
- `BR_NFT_ALLOWED_WEB_TCP_PORTS` — Standard aus `BR_FIREWALL_ALLOWED_WEB_TCP_PORTS` bzw. `80,443`.
- `BR_NFT_EXPECTED_LOOPBACK_TCP` — Standard aus `BR_FIREWALL_EXPECTED_LOOPBACK_TCP` bzw. `127.0.0.1:18083`.
- `BR_NFT_DIRECT_HOSTS` — Standard aus `BR_FIREWALL_DIRECT_HOSTS`; `PUBLIC_IPV4` und `TAILSCALE_IPV4` aus `/etc/opencode-host-context` werden zusaetzlich ergaenzt.
- `BR_NFT_MAX_CHAIN_TRAVERSAL_DEPTH` — Standard `12`, maximale Tiefe fuer read-only `jump`-/`goto`-Zielkettenauswertung.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Host-NFT-BR-Ports-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Network-Policy-Consistency-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-network-policy-consistency.py
scripts/check-network-policy-consistency.py --summary
```

Der Guard ist read-only und vergleicht die Policy-Defaults der Direct-Origin-,
Host-UDP-, Host-Firewall- und Host-NFT-Guards. Er stellt sicher, dass die direkten
Origin-/Tailscale-Ziele, Wildcard-Hosts, BR-relevanten TCP-/UDP-Ports, erlaubten
Web-TCP-Ports und die erwartete Loopback-NAT-Regel `127.0.0.1:18083` zwischen den
Guards nicht auseinanderlaufen. Aktueller Live-Stand:
`network_policy_consistency_status=ok`, `checks=26`, `findings=0`,
`concrete_targets=4`, `wildcard_hosts=2`, `tcp_ports=7`, `udp_ports=7`,
`web_tcp=2`, `loopback_tcp=1`.

Der Guard liest nur lokale Guard-Quelltexte und `/etc/opencode-host-context`,
sendet keine Pakete, aendert keine Firewall-/Netzwerkregeln und liest keine
Secrets, Logs, Dumps, Antworten oder Quelleninhalte.
Wichtig: Er prueft Source-/Default-Konsistenz und Host-Kontextwerte, nicht die
aktive Runtime-Netzwerk-/Firewall-Konfiguration. Laufzeit-Drift wird weiterhin
durch die spezialisierten Runtime-, Direct-Origin-, UDP-, iptables- und nftables-
Guards abgedeckt.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Network-Policy-Consistency-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Network-Policy-Runtime-Env-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-network-policy-runtime-env.py
scripts/check-network-policy-runtime-env.py --summary
```

Der Guard ist read-only und prueft, ob BR-Netzwerkpolicy-Environment-Variablen in
der aktuellen Guard-Umgebung, in installierten BR-systemd-Units oder in
Projektquellen ausserhalb erlaubter Guard-/Doku-Dateien gesetzt werden. Er gibt
nur Variablennamen und Zaehler aus, nie Werte. Aktueller Live-Stand:
`network_policy_runtime_env_status=ok`, `checks=122`, `findings=0`,
`env_names=24`, `current_env_overrides=0`, `unit_overrides=0`,
`project_references=80`, `installed_unit_references=0`.

Der Guard soll verhindern, dass Runtime-Overrides fuer Direct-Origin-Ziele,
Portlisten, erlaubte Webports, Loopback-NAT-Ausnahmen oder Host-Kontextpfade die
Spezialguards unbemerkt beeinflussen. Er sendet keine Pakete, aendert keine
Firewall-/Netzwerkregeln und liest keine Secrets, Logs, Dumps, Antworten oder
Quelleninhalte.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Network-Policy-Runtime-Env-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Network-Policy-Runtime-Summary-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-network-policy-runtime-summary.py
scripts/check-network-policy-runtime-summary.py --summary
```

Der Guard ist read-only und fuehrt die Summary-Laeufe der relevanten Netzwerk- und
Exposure-Guards aus. Er prueft nur Status-/Zaehler-Invarianten und gibt keine
Regeltexte, DNS-Antwortinhalte, Headerwerte, Secrets, Logs, Dumps, Antworten oder
Quelleninhalte aus. Aktueller Live-Stand:
`network_policy_runtime_summary_status=ok`, `checks=65`, `findings=0`,
`summaries=12`, `ok_summaries=12`, `failed_summaries=0`, `origin_targets=4`,
`direct_hosts=6`, `tcp_ports=7`, `udp_ports=7`, `web_tcp=2`, `loopback_tcp=1`.

Geprueft werden u. a. grüne Statuswerte der Netzwerkguards, keine DNS-Origin-
Treffer, keine unerwarteten direkten Port-/NAT-/UDP-Expositionen, keine
Network-Policy-Runtime-Env-Overrides sowie keine Host-NFT-Runtime-Findings fuer
unsupported Expressions, unaufgeloeste Jumps, Traversal-Zyklen oder unaufgeloeste
Set-Referenzen.

Wenn dieser Guard Findings meldet, zuerst die konkret genannte Summary und den
zugrunde liegenden Einzelguard manuell im `--summary`- und anschliessend im
Detailmodus ausfuehren. Erwartungswerte wie Ziel-IP-Listen, Portmengen, erlaubte
Webports, Loopback-NAT oder Host-Kontextwerte duerfen nur im Change-Management
angepasst werden; dabei muessen Source-Consistency, Runtime-Env-Guard,
Runtime-Summary-Guard, Readiness-Dossier und Backup-Preflight gemeinsam
nachgezogen werden. Keine Finding-Umgehung per Env-Override ohne dokumentierte
Freigabe.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Network-Policy-Runtime-Summary-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Syntaxcheck ohne Cache-Artefakte

Für normale Syntaxprüfungen nicht `py_compile` verwenden, weil dadurch lokale
`__pycache__`-/`*.pyc`-Artefakte entstehen können. Stattdessen:

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-python-syntax.sh
```

Der Check nutzt `ast.parse(...)` und schreibt keine Bytecode-Dateien.

## Projektbaum auf lokale Artefakte/Secrets prüfen

Nach Wartungs- oder Secret-Arbeiten:

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-project-artifacts.sh
```

Der Check meldet versehentlich abgelegte lokale Artefakte oder Credential-Hinweise
im App-Projektbaum, z. B. `*.pyc`, `*.log`, `.env`, `*.env`,
`__pycache__`, `cloudflared/*.json`, `*credential*` oder `*token*`.

## Runtime-Logs auf sensible Header-Marker prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-runtime-log-markers.sh
```

Der Check meldet nur Containername, Status und Trefferanzahl, aber keine
Logzeilen oder Headerwerte. Der Caddy-Proxy nutzt einen globalen JSON-Logfilter.
Gefiltert werden unter anderem `Authorization`, `Cookie`,
`Cf-Access-Jwt-Assertion`, `Cf-Access-Authenticated-User-Email`,
`Cf-Authorization`, `Proxy-Authorization`, `X-Auth-Token` und `X-Api-Key`.

Der normale Statuscheck (`scripts/status-br-wissen.sh`) zeigt diese Pruefung
ebenfalls unter `Runtime-Log-Marker` an.

## Runtime-HTTP-Security pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-runtime-http-security.py
scripts/check-runtime-http-security.py --summary
```

Der Guard ist read-only und sendet unauthentifizierte GET-Anfragen an den lokalen
Loopback-Proxy `http://127.0.0.1:18083/` und `/healthz`. Erwartet werden jeweils
`401 Unauthorized`, `WWW-Authenticate: Basic`, Noindex-/NoStore-Header,
Content-Security-Policy, Referrer-Policy, X-Frame-Options,
X-Content-Type-Options, Permissions-Policy, COOP, CORP und kein `Server`-Header.
Der Guard liest keine Antwortkoerper und sendet keine Zugangsdaten; Secretwerte,
Logs, Dumps, Antworten oder Quelleninhalte werden nicht ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Runtime-HTTP-Security`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## External-Access-Surface pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-external-access-surface.py
scripts/check-external-access-surface.py --summary
```

Der Guard ist read-only und sendet unauthentifizierte HTTPS-GET-Anfragen an
zentrale oeffentliche Pfade unter `https://br.m11h.eu`, darunter `/`, `/healthz`,
`/login`, `/queries`, `/sources`, `/answers`, `/search` und `/validation`. Er folgt keinen Inhalten, liest keine
Antwortkoerper und gibt nur Status-/Header-Metadaten als Zaehler aus. Erwartet
wird ein geschuetzter externer Pfad: entweder Cloudflare-Access-/Challenge-
Marker mit `cf-access-domain=br.m11h.eu` oder, falls Cloudflare die Anfrage bis
Caddy durchreicht, der bekannte Basic-Auth-401-Pfad. Der aktuelle Live-Pfad wird
durch Cloudflare Access geschuetzt; die lokale Caddy-Basic-Auth wird separat vom
Runtime-HTTP-Security-Guard ueber Loopback geprueft. Cookie-Inhalte,
Zugangsdaten, Secretwerte, Logs, Dumps, Antworten oder Quelleninhalte werden
nicht gelesen oder ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `External-Access-Surface`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## External-Cookie-Security pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-external-cookie-security.py
scripts/check-external-cookie-security.py --summary
```

Der Guard ist read-only und sendet unauthentifizierte HTTPS-GET-Anfragen an `/`,
`/healthz` und `/login`. Er liest keine Antwortkoerper und gibt keine Cookie-Werte
aus. Geprueft werden nur Cookie-Metadaten: erwarteter Cloudflare-Access-Name,
`Secure`, `HttpOnly`, ein gueltiges `SameSite`-Attribut, `Path=/`, ein Ablauf
ueber `Expires` oder `Max-Age` und eine fehlende oder erwartete Domain
(`br.m11h.eu`, `.br.m11h.eu` oder `.m11h.eu`). `SameSite=None` ist mit `Secure`
als Cloudflare-Access-Kompatibilitaetsvariante gueltig. Der aktuelle Live-Stand
zeigt drei Cookies auf drei Pfaden, alle mit den erwarteten Attributen inklusive
`allowed_domain=3`. Zugangsdaten, Secrets, Logs, Dumps, Antworten oder
Quelleninhalte werden nicht gelesen oder ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `External-Cookie-Security`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## TLS-Certificate-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-tls-certificate.py
scripts/check-tls-certificate.py --summary
```

Der Guard ist read-only und baut nur eine TLS-Verbindung zu `br.m11h.eu:443` auf.
Er nutzt die Standard-CA-/Hostname-Pruefung der Python-SSL-Bibliothek und prueft
danach ausschliesslich Zertifikats-/TLS-Metadaten: erwartete TLS-Version
`TLSv1.2` oder `TLSv1.3`, SAN-/Wildcard-Match fuer `br.m11h.eu`, vorhandenen
Issuer, Cipher-Marker und mindestens 14 Tage Restlaufzeit. HTTP-Antwortkoerper,
Zugangsdaten, Cookies, Secretwerte, Logs, Dumps, Antworten oder Quelleninhalte
werden nicht gelesen oder ausgegeben.

Der Guard laeuft auch:

- im normalen Statuscheck unter `TLS-Certificate-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## App-Auth-/CSRF-Surface pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-app-auth-surface.py
scripts/check-app-auth-surface.py --summary
```

Der Guard ist read-only und fuehrt im App-Container interne HTTP-Metadatenchecks
gegen `http://127.0.0.1:8000` aus. Redirects werden nicht verfolgt und
Antwortkoerper werden nicht gelesen. Erwartet wird, dass geschuetzte GET-Routen
unauthentifiziert mit `303` nach `/login` umleiten, dass `/healthz` und `/login`
statusmaessig erreichbar sind und dass unauthentifizierte POST-/Mutationsrouten
ohne CSRF-Token mit `403` blockieren. Die Summary weist unerwartete POST-Erfolge
und POST-Redirects explizit als `post_successes` und `post_redirects` aus. Der
Guard sendet keine Zugangsdaten und liest keine Secretwerte, Logs, Dumps,
Antworten oder Quelleninhalte.

Der Guard laeuft auch:

- im normalen Statuscheck unter `App-Auth-Surface`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Import-Pipeline prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-import-pipeline.py
scripts/check-import-pipeline.py --summary
```

Der Guard ist read-only und prueft ohne Ausgabe von Dokument-, Dump- oder
Secret-Inhalten:

- aktive Timer `br-wissen-import-m00h.timer` und `br-wissen-import-bag.timer`,
- Vorhandensein und Alter der neuesten m00h-/BAG-Importlogs,
- m00h-Checksummenmarker und BAG-Erfolgs-/Fehlerzaehler,
- Datenbank-Invarianten fuer Quellen, Dokumente, Chunks, SHA256-Felder und
  Chunk-Klassen,
- kuerzlich gepruefte/importierte Quellen.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Import-Pipeline-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Import-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-import-source-hardening.py
scripts/check-import-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Import-Quellen
`scripts/import-m00h-betriebsrat.sh`, `scripts/import-bag-feed-docker.sh`,
`scripts/import-bag-feed.py` sowie die zugehoerigen Import-Service-/Timer-Quellen
unter `systemd/`. Geprueft werden erwartete Marker fuer Fail-Fast, m00h-Quell- und
Zielpfade, restriktive Logrechte, `rsync --protect-args`, SHA256-Checksummen,
BAG-Feed-URL, User-Agent, Download-Timeout, Dateimodi, DB-Upserts, Chunk-Neuaufbau,
Importlogs, Docker-Wrapper und systemd-Importtimer. Der Guard liest keine
importierten Quelleninhalte, Logs, Dumps, Backup-Env-Inhalte, Credentials,
Antworten oder Dokumente und ruft keine Imports, kein Docker, kein `rsync`, keine
Netzwerkzugriffe, kein `systemctl` und kein `sudo` auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Import-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Antwort-/Export-Safety prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-answer-export-safety.py
scripts/check-answer-export-safety.py --summary
```

Der Guard ist read-only und prueft ohne Ausgabe von Antwort-, Quellen- oder
Secret-Inhalten:

- Antworten ohne Statements und Statements ohne Citation,
- Citations ohne Chunk oder interne Referenz,
- GELB-Zitationen in aktuellen Antworten,
- Klassenmismatches zwischen Answer-Citation, Chunk und Source,
- Exportpfade ausserhalb des Storage-Roots,
- fehlende HTML/PDF-Dateien oder auffaellig kleine PDFs,
- Noindex-/Wasserzeichen-Marker in HTML-Exporten,
- verbotene Pfad-, direkte Datei- und Secret-/Header-Marker in HTML-Exporten.
- technische Export-Manifeste (`manifest.json`) inklusive Manifest-Version,
  Antwort-ID, Policyflags, Validierungsdaten sowie HTML/PDF-Hash und
  Dateigroesse.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Answer-Export-Safety`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

Hinweis zur Parallelitaet: strukturierte Antwortgeneratoren schreiben
Antwortzeile, Statements, Citations und Audit-Eintrag in einer gemeinsamen
Transaktion. Dadurch bleiben systemd-/Status-Guards stabil, auch wenn sie
parallel zu Regressionen oder manueller Antworterzeugung laufen.

Bestehende Exporte koennen bei Bedarf mit technischen Manifesten nachgezogen
werden, ohne Antwort-, HTML- oder PDF-Inhalte zu veraendern:

```bash
cd /home/chris/web/br.m11h.eu
docker compose exec -T app python - < scripts/backfill-export-manifests.py
```

## Audit-Trail prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-audit-trail.py
scripts/check-audit-trail.py --summary
```

Der Guard ist read-only und prueft ohne Ausgabe von Audit-Details, Antworttexten,
Quelleninhalten oder Secrets:

- leere Actor/Actions/Object-UIDs,
- unbekannte Audit-Aktionen,
- Audit-Zukunftszeitstempel,
- Audit-Abdeckung fuer Antworterzeugung,
- Audit-Abdeckung fuer validierte Exporte,
- bekannte Legacy-Ausnahmen aus fruehen Bootstrap-/Test-Exporten.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Audit-Trail`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## DB-Schema und Betriebsindexes prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-db-schema.py
scripts/check-db-schema.py --summary
```

Der Guard ist read-only und prueft ohne Ausgabe von Tabelleninhalten,
Antworttexten, Quelleninhalten oder Secrets:

- Extension `vector`,
- erwartete Tabellen und Spalten,
- Unique-/Such-/FK-nahe Betriebsindexes fuer Quellen, Dokumente, Chunks,
  Antworten, Antwort-Citations und Audit-Log.

Der Guard laeuft auch:

- im normalen Statuscheck unter `DB-Schema`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Data-Integrity-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-data-integrity-source-hardening.py
scripts/check-data-integrity-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen von
`scripts/check-answer-export-safety.py`, `scripts/check-audit-trail.py` und
`scripts/check-db-schema.py`. Geprueft werden metadata-only Antwort-/Export-
Safety-Marker, Export-Manifest-Erwartungen, Audit-Zaehler und bekannte Legacy-
Ausnahmen, DB-Extension-/Tabellen-/Spalten-/Index-Erwartungen, kompakte Summary-
Ausgaben sowie verbotene mutierende bzw. inhaltslesende Marker. Er liest keine
Secrets, Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte und ruft kein
Docker, keine DB-Abfragen, keine Backups, Restores, Imports oder Regressionen
auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Data-Integrity-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Backup-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-backup-source-hardening.py
scripts/check-backup-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quelle des Backup-Wrappers
`scripts/backup-br-wissen.sh`. Geprueft werden erwartete Marker fuer
`set -euo pipefail`, `umask`, Backup-Env-/Protokollpfad, lokale Retention,
Fail-Fast-Status, Preflight-Kette, `pg_dump`, Dump-/Log-Modi, Restic-Backup,
Restic-Retention sowie lokale Dump-/Log-Retention. Er liest keine Backup-Env-
Inhalte, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft kein Backup,
kein Restic, kein Docker und kein `systemctl` auf.

Der Backup-Wrapper waehlt Restic fuer `backup` und `forget` ueber `RESTIC_BIN`
aus den kuratierten absoluten Pfaden `/usr/bin/restic` und `/usr/local/bin/restic`.
Ein unqualifizierter Root-`PATH` wird fuer diese Restic-Aufrufe nicht mehr genutzt;
im Backup-Log erscheint nur `restic_bin=<pfad>`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Backup-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Restore-Source-Hardening-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-restore-source-hardening.py
scripts/check-restore-source-hardening.py --summary
```

Der Guard ist read-only und prueft ausschliesslich die Quellen der Restore-Smoke-
Skripte `scripts/run-restore-smoke-drill.sh` und
`scripts/restore-smoke-br-wissen.sh`. Geprueft werden erwartete Marker fuer
Fail-Fast, `/tmp/br-wissen-restore-*`-Zielpfadschutz, restriktive Logrechte,
Storage-Capacity-Preflight, Restic-Restore, erforderliche Restore-Dateien,
Dump-Strukturmarker, isolierten DB-Restore mit `--network none`, Cleanup-Trap,
temporäre Docker-Ressourcen und Restore-Log-Retention. Er liest keine Backup-Env-
Inhalte, Dumps, Logs, Antworttexte, wiederhergestellten Dateien oder
Quelleninhalte und ruft keinen Restore, kein Restic, kein Docker, kein `sudo` und
kein `systemctl` auf.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Restore-Source-Hardening`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Backup-Freshness und lokale Retention prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-backup-freshness.py
scripts/check-backup-freshness.py --summary
```

Der Guard ist read-only und prueft ohne Ausgabe von Backup-Secretwerten,
Dump-Inhalten oder Log-Inhalten:

- Anzahl lokaler Backup-Logs und lokaler Dumps gegen die Retention-Ziele,
- Alter des neuesten Backup-Logs, neuesten Dumps und neuesten Restic-Snapshots,
- Erfolgsmarker `status=backup_done`, Snapshot-Marker und Dump-Referenz im letzten
  Backup-Log,
- Preflight-OK-Marker im letzten Backup-Log,
- Abgleich zwischen Snapshot im letzten Backup-Log und neuestem Restic-Snapshot,
- metadata-only Abgleich, dass der neueste Restic-Snapshot den Projektprotokollpfad
  enthaelt und nicht aelter als der aktuelle Protokollstand ist; die Summary zeigt
  dies als `protocol_snapshot_current=1`,
- vorhandene Restic-Repository-Locks als metadata-only Zaehler ohne Lock-ID-Ausgabe;
  failend sind nur stale Locks, aktive Locks werden nur gezaehlt. Die Lock-Abfrage
  setzt `LC_ALL=C`, damit der `stale`-Marker moeglichst stabil erkannt wird;
  `no locks`-Statuszeilen werden nicht als Lock gezaehlt,
- die Restic-Env-Datei metadata-only auf Existenz, regulaere Datei,
  Symlink-Freiheit, `root:root` und Modus `600`; die Summary zeigt
  `backup_env_mode=600`,
- den root-noetigen Scan, die Restic-Snapshot-Abfrage und die Lock-Abfrage ueber
  kuratierte absolute Helferpfade statt ueber den Root-`PATH`; die Summary zeigt
  `helper_binaries=<n>`, `python_binary=<pfad>` und `restic_binary=<pfad>`.

Der Guard laeuft:

- im normalen Statuscheck unter `Backup-Freshness`,
- als `ExecStartPre` im systemd-Healthcheck.

Er laeuft bewusst nicht als Backup-Preflight, damit ein neues Backup nicht durch
ein altes/fehlendes vorheriges Backup oder einen frischen Protokollnachtrag
blockiert wird.
Der root-noetige Scan laeuft ueber `--scan-json`, damit `sudo`-/Journald-Zeilen
kompakt bleiben. Er wird mit `/usr/bin/sudo` und einem kuratierten absoluten
Python-Interpreter gestartet; `/usr/bin/test`, `/usr/bin/bash` und der
ausgewaehlte Restic-Pfad werden metadata-only auf Datei-/Owner-/Mode-Policy
geprueft. Der Guard erwartet im neuesten Backup-Log auch den
Storage-/Permission-Preflight.

## Restic-Repository-Integritaet manuell pruefen

```bash
cd /home/chris/web/br.m11h.eu
sudo -n bash -lc 'set -euo pipefail; set -a; source /etc/web-backup/repos.d/m11h-br-wissen.env; set +a; restic check'
```

Der Check ist read-only gegen das verschluesselte Restic-Repository und nutzt die
root-only Backup-Env, ohne Secret-/Env-Werte auszugeben. Er erzeugt keine Dumps,
startet keine Container, fuehrt keine Restores aus und liest keine App-/Quellen-
oder Antwortinhalte. Weil `restic check` einen exklusiven Repository-Lock nimmt
und je nach Repository-Groesse laenger laufen kann, ist er bewusst kein Backup-
Preflight und kein Standard-Healthcheck. Empfohlen ist er nach groesseren Backup-
oder Restore-Haertungsbloecken, nach auffaelligen Restic-Fehlern oder als
periodischer Wartungscheck. Letzter dokumentierter Lauf: `2026-06-06T06:25:14Z`,
48 Snapshots geprueft, Ergebnis `no errors were found`.

Der leichte Freshness-Guard fuer diesen Nachweis startet keinen `restic check`,
nimmt keinen Repository-Lock und liest keine Backup-Env-Werte. Er prueft nur, ob
das Readiness-Dossier einen frischen erfolgreichen Repository-Check dokumentiert:

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-restic-repository-check.py --summary
```

Die Summary meldet `restic_repository_check_status=ok`, `last_check=<zeit>`,
`age_h=<stunden>`, `snapshots=<n>`, `documented_success=1` und
`lock_preflight=0`. Der Guard ist in Status, systemd-Healthcheck-Preflight und
Backup-Preflight verdrahtet; der schwere `restic check` selbst bleibt explizit.

Der Restore-Smoke protokolliert bei `snapshot=latest` zusaetzlich die konkret
aufgeloeste Restic-Snapshot-ID als `restore_resolved_snapshot=<id>`. Der
Restore-Freshness-Guard erwartet diesen Marker und zeigt ihn in der Summary, damit
der tatsaechlich gepruefte Snapshot nachvollziehbar ist, ohne Restore-Inhalte,
Dump-Inhalte, Secretwerte oder Antworttexte auszugeben.

## Storage-/Permission-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-storage-permissions.py
scripts/check-storage-permissions.py --summary
```

Der Guard ist metadata-only und prueft ohne Ausgabe von Secret-, Dump-, Log- oder
Export-Inhalten:

- Existenz und Modus von `/srv/br-wissensdatenbank` und `secrets/`,
- Symlinks und world-writable Dateien im Storage,
- Secret-Kandidaten und world-writable Dateien im App-Projektbaum,
- group/world-Bits auf Secret-Dateien,
- Cloudflared-Credential-Owner/-Modus fuer UID/GID `65532:65532`,
- Modi lokaler PostgreSQL-Dumps und Backup-Logs.

Der root-noetige Metadatenscan wird ueber das Skript selbst mit `--scan-json`
ausgefuehrt. Dadurch bleiben `sudo`-/Journald-Zeilen kompakt und enthalten keinen
grossen Inline-Code. Der Guard laeuft auch:

- im normalen Statuscheck unter `Storage-Permissions`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Storage-/Capacity-Guard pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-storage-capacity.py
scripts/check-storage-capacity.py --summary
```

Der Guard ist read-only und prueft ohne Ausgabe von Datei-, Dump-, Log- oder
Secret-Inhalten:

- freie Bytes und Belegungsprozent fuer `/`, App-Pfad,
  `/srv/br-wissensdatenbank`, `/tmp` und `/var/lib/docker`,
- Inode-Belegung fuer dieselben Pfade,
- kompakte Docker-System-DF-Metadaten inklusive grober Gesamt- und
  reclaimable-Groesse.

Standardgrenzen:

- mindestens 10 GiB frei fuer Root/App/Storage/Docker,
- mindestens 2 GiB frei fuer `/tmp`,
- maximal 90 Prozent Byte-Belegung,
- maximal 90 Prozent Inode-Belegung.

Der Guard laeuft:

- im normalen Statuscheck unter `Storage-Capacity`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic,
- als Preflight im automatisierten Restore-Smoke-Drill.

## Restore-Freshness und automatisierten Restore-Smoke pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-restore-freshness.py
scripts/check-restore-freshness.py --summary
sudo systemctl start br-wissen-restore-smoke.service
sudo systemctl status br-wissen-restore-smoke.service --no-pager
```

Der Restore-Freshness-Guard ist read-only und prueft ohne Ausgabe von
Secretwerten, Restore-Log-Inhalten oder Dump-Inhalten:

- Vorhandensein, Alter, Modus und Retention der Restore-Smoke-Logs,
- `restore_drill_status=ok`, `restore_status=ok` und `db_restore_status=ok`,
- den SQL-Bereitschaftsmarker `restore_sql_ready_wait`,
- Dump-Groesse und Dump-Marker,
- Export-/Manifestzaehler und Artefaktfreiheit,
- DB-Konsistenzzaehler fuer Antworten/Statements/Citations,
- `vector`-Extension und erwartete Betriebsindexes,
- Isolation des DB-Restores (`--network none`, keine publizierten Ports),
- metadata-only Restic-Abgleich der konkret aufgeloesten
  `restore_resolved_snapshot`: vorhanden, Tags `br-wissen` und
  `includes-internal-sources`, erwartete Pfade `/home/chris/web/br.m11h.eu`,
  `/srv/br-wissensdatenbank` und `/home/chris/web/diverses/betriebsrat.md`.

Der root-noetige Scan laeuft ueber `--scan-json`. Der Guard laeuft:

- im normalen Statuscheck unter `Restore-Freshness`,
- als `ExecStartPre` im systemd-Healthcheck.

Der woechentliche Restore-Smoke-Drill wird durch
`br-wissen-restore-smoke.timer` gestartet. Die Service-Unit fuehrt
`scripts/run-restore-smoke-drill.sh` aus, der einen Restore nach `/tmp`, einen
isolierten DB-Restore und eine restriktive Logdatei unter
`/srv/br-wissensdatenbank/logs/restore-smoke-*.log` erzeugt. Standardmaessig
bleiben die letzten 20 Restore-Smoke-Logs erhalten (`BR_RESTORE_LOG_KEEP=20`).
Der DB-Restore wartet nach `pg_isready` zusaetzlich auf eine echte SQL-Antwort
per `SELECT 1`; die Wartezeit ist ueber `BR_RESTORE_SQL_READY_WAIT`
konfigurierbar und betraegt standardmaessig 15 Sekunden.
Die Summary zeigt den Restic-Metadatenabgleich mit
`restore_resolved_snapshot_present=<0|1>` und
`restore_resolved_snapshot_paths=<n>`, ohne Secret-, Dump-, Log-, Restore- oder
Antwortinhalte auszugeben. Die Restic-Metadatenabfrage wird dabei nicht ueber den
Root-`PATH` aufgeloest, sondern nur ueber einen kuratierten ausfuehrbaren Pfad
`/usr/bin/restic` oder `/usr/local/bin/restic`. Die noetigen Helfer fuer sudo,
Datei-/Binary-Tests und Shell-Ausfuehrung werden ebenfalls mit absoluten Pfaden
`/usr/bin/sudo`, `/usr/bin/test`, `/usr/bin/bash` und fuer den root-noetigen
JSON-Scan einen kuratierten absoluten Python-Interpreter gestartet. Aktuell wird
`/usr/bin/python3.13` gewaehlt, weil es eine regulaere root-owned Datei ist;
Symlinks wie `/usr/bin/python3` werden nicht akzeptiert. Der Guard prueft diese
Helfer und die ausgewaehlten Python-/Restic-Pfade metadata-only auf Existenz,
Symlink-Freiheit, regulaere Datei, `root:root`, nicht gruppen-/world-writable,
Ausfuehrbarkeit und erwartete Sonderbits; die Summary enthaelt
`helper_binaries=<n>` und den aktuell ausgewaehlten Python-Pfad als
`python_binary=<pfad>`.
Zusaetzlich prueft der Guard sein eigenes Skript metadata-only auf Existenz,
Symlink-Freiheit, regulaere Datei, nicht gruppen-/world-writable,
Ausfuehrbarkeit und Mindestgroesse. Die Summary enthaelt diese Selbstpruefung
als `self_script_policy=<0|1>`; die Guard-Datei ist dafuer auf Modus `755`
gehaertet.
Ergaenzend prueft der Guard die projektbezogenen Parent-Verzeichnisse
`/home/chris/web/br.m11h.eu` und `/home/chris/web/br.m11h.eu/scripts`
metadata-only auf Existenz, Symlink-Freiheit, Verzeichnistyp, Owner-/Group-
Konsistenz zum Skript, nicht gruppen-/world-writable und Suchbarkeit. Die
Summary enthaelt dies als `self_parent_policy=<0|1>`.

## Readiness-Doku-Freshness pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-readiness-doc.py
scripts/check-readiness-doc.py --summary
```

Der Guard ist read-only und prueft ohne Ausgabe von Secret-, Dump-, Log- oder
Credential-Inhalten:

- Stand-Zeitstempel in `docs/READINESS.md`,
- Pflichtmarker fuer Status, Backup-/Restore-/Storage-/Image-/Git-Hinweise,
- Statusmarker und Erreichbarkeit bestehender Summary-Guards,
- kompakte Backup-/Restore-Evidenzwerte: `backup_snapshot=<id>` aus dem
  Backup-Scope-Guard und `restore_dump=<dump>` aus dem Restore-Freshness-Guard,
- Protokollnachtrag in `/home/chris/web/diverses/betriebsrat.md`.

Dynamische Snapshot-IDs und Dumpnamen werden nicht als exakter Dossierinhalt
erzwungen. Der Backup-Freshness-Guard wird bewusst nicht aufgerufen, damit eine
frische Doku- oder Protokollergaenzung das naechste Backup nicht durch einen
Kreisschluss blockiert. Dadurch wird der Guard nicht nach jedem regulaeren
Nachtbackup rot, solange das Dossier insgesamt frisch genug ist.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Readiness-Doku`,
- als `ExecStartPre` im systemd-Healthcheck.

## Regression-Freshness pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-regression-freshness.py
scripts/check-regression-freshness.py --summary
```

Der Guard ist read-only und erzeugt keine neuen Antworten, Exporte oder
Datenbankzeilen. Er prueft ohne Ausgabe von Antwort-, Quellen-, Secret-, Dump-
oder Log-Inhalten:

- die zuletzt vorhandene Antwort fuer jeden der vier Kernfaelle,
- Alter der Regressionsantworten,
- Statement-/Citation-Abdeckung,
- erlaubte und erforderliche Quellenklassen,
- erforderliche Quellen-UIDs,
- doppelte Chunk-IDs und gemischte Duplicate-Dokument-SHA-Gruppen,
- vorhandene HTML-/PDF-/Manifest-Exporte.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Regression-Freshness`,
- als `ExecStartPre` im systemd-Healthcheck.

Frische Regressionen werden weiterhin nur explizit mit
`scripts/status-br-wissen.sh --with-regressions` oder
`scripts/run-regressions-docker.sh` erzeugt.

## Systemd-Units und Timer pruefen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-systemd-units.sh
scripts/check-systemd-units.sh --summary
```

Der Guard ist failend. Er prueft:

- alle zehn BR-Wissen-Service-/Timer-Dateien auf Sync zwischen Projektquelle
  `systemd/` und `/etc/systemd/system/`,
- die fuenf erwarteten Timer auf `active`,
- die fuenf erwarteten BR-Wissen-Service-Units auf systemd-Zustand `failed`.

Abgeschlossene oneshot-Services im Zustand `inactive` sind normal und gelten
nicht als Fehler.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Systemd Timer`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Container-Image-Inventar prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-container-images.sh
```

Der Check ist read-only und statusbewertet. Er zeigt, ob Images lokale Builds,
tag-gepinnt, digest-gepinnt, `latest` oder unversioniert sind. Der normale
Statuscheck zeigt eine kompakte Summary unter `Container-Images`. Der Check
beruecksichtigt sowohl `docker compose config --images` als auch laufende
Projektcontainer, damit Profil-Container wie `cloudflared` sichtbar bleiben.
`container_image_status=ok` gilt nur bei vorhandenen Images ohne tag-only-,
`latest`- oder unversionierte Referenzen. Solche Referenzen ergeben `warning`; eine
leere Imagebasis ergibt `failed`. Nach dem Digest-Rollout sollen die externen
Laufzeitimages als `digest_pinned` erscheinen.

## Image-Pinning-Readiness prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-image-pinning-readiness.sh
scripts/status-br-wissen.sh --image-pinning
```

Der Check ist read-only und statusbewertet. Er sammelt Compose-Images, laufende
Projektcontainer und Dockerfile-`FROM`-Images. Bei erreichbarer Registry ermittelt
er Index- und Plattform-Digests. `image_pinning_readiness_status=ok` gilt nur bei
vorhandenen Referenzen ohne Tag-, `latest`- oder unversionierte Pinning-Kandidaten
und ohne Remote-Ausfaelle. Offene Kandidaten oder Remote-Ausfaelle ergeben
`warning`; fehlende Referenzen ergeben `failed`.

Der normale Statuscheck nutzt die lokale/offline Variante
`scripts/check-image-pinning-readiness.sh --summary --no-remote`. Dadurch bleiben
externe Registry-Ausfaelle aus dem Standardstatus heraus. Der optionale
`scripts/status-br-wissen.sh --image-pinning` fuehrt zusaetzlich den
remote-aktivierten Check aus; `warning` mit `remote_unavailable>0` ist dann als
Registry-Verfuegbarkeitswarnung zu lesen, nicht automatisch als Pinning-Verstoss.
Zur Einordnung meldet die Summary `remote_expected`, `remote_coverage_pct` und
`remote_unavailable_refs=<kommagetrennte Referenzen>` ohne Digest-Suffix.

Wichtig: Dieser Check ersetzt keine Images, baut nichts neu und startet keine
Container neu. Nach dem Digest-Rollout dient er als Kontrollcheck: Es sollen keine
Tag- oder `latest`-Pinning-Kandidaten mehr gemeldet werden. Kuenftige Image-
Aenderungen bleiben eigene Wartungsbloecke mit vorherigem Backup, Rollback-Notiz,
Rebuild/Rollout und anschliessender Validierung.

## Image-Pinning-Guard prüfen

```bash
cd /home/chris/web/br.m11h.eu
scripts/check-image-pinning-guard.sh
scripts/check-image-pinning-guard.sh --summary
```

Der Guard ist lokal/offline und failend. Er sammelt Compose-Images, laufende
Projektcontainer und Dockerfile-`FROM`-Images. Er erlaubt lokale Build-Images
`brm11heu-*` sowie Digest-Referenzen. Tag-only-, unversionierte oder
`latest`-ohne-Digest-Referenzen werden als Verstoß gemeldet und fuehren zu
Exitcode `1`.

Der Guard laeuft auch:

- im normalen Statuscheck unter `Image-Pinning-Guard`,
- als `ExecStartPre` im systemd-Healthcheck,
- als Preflight im Backup-Skript vor Dump/Restic.

## Verschlüsseltes Backup manuell starten

```bash
sudo systemctl start br-wissen-backup.service
sudo systemctl status br-wissen-backup.service --no-pager
```

Backup-Secrets liegen root-geschützt unter `/etc/web-backup/`; Werte niemals
anzeigen, kopieren oder protokollieren.

Das Projektprotokoll `/home/chris/web/diverses/betriebsrat.md` liegt ausserhalb
von App- und Storage-Pfad, wird aber als eigener Restic-Pfad mitgesichert.

Das Backup-Skript erstellt vor dem verschlüsselten Restic-Backup einen lokalen
PostgreSQL-Dump unter `/srv/br-wissensdatenbank/backups/postgres-*.sql` und
startet vorher den Host-Kontext-Guard, den Time-Sync-Guard, den Compose-Service-Guard, den
Core-Source-Hardening-Guard, den Container-Hardening-Guard, den Network-Exposure-Guard sowie den Projektartefakt-
Guard in kompakter Form. Wenn
der Host nicht dem erwarteten `m11h`-Kontext entspricht, Time-Sync unplausibel ist,
ein erwarteter Compose-Service fehlt/nicht laeuft, `app` oder `db` nicht healthy sind, eine
unerwartete Nicht-Loopback-Netzwerkpublikation auftaucht oder im App-Projektbaum
z. B. `.env`, `*.pyc`, `__pycache__`, `*.log`,
`cloudflared/*.json`, `*credential*` oder `*token*` liegt, wird das Backup
abgebrochen, damit falsche Zielsysteme oder lokale Artefakte nicht konserviert
werden.
Vor Dump/Restic laufen außerdem Image-Pinning-, Systemd-Unit-,
Runtime-HTTP-Security-, External-Access-Surface-, TLS-Certificate-, App-Auth-Surface-, Import-Pipeline-, Antwort-/Export-Safety-, Audit-Trail-, DB-Schema-,
Storage-/Permission-, Storage-/Capacity-, Readiness-Doku- und
Regression-Freshness-Preflight.
Das Backup-Log muss zusaetzlich `protocol_file_status=included`,
`host_context_status=ok`, `time_sync_status=ok`, `compose_service_status=ok`,
`core_source_hardening_status=ok`, `container_hardening_status=ok`, `network_exposure_status=ok`,
`host_firewall_br_ports_status=ok`, `host_nft_br_ports_status=ok`, `runtime_http_security_status=ok`,
`external_access_surface_status=ok`, `tls_certificate_status=ok` und
`app_auth_surface_status=ok` enthalten.
Alle Backup-Preflights laufen explizit fail-fast: bei einem roten Guard wird
`status=<preflight>_preflight_failed` ins Backup-Log geschrieben und vor Dump/
Restic mit Exitcode 1 abgebrochen.
Backup-Freshness wird separat im Status/systemd-Healthcheck ueberwacht und nicht
als Backup-Preflight verwendet.

Das Backup-Skript setzt `umask 027` und legt das Backup-Log vor den Preflights
mit Modus `640` an. So bleiben auch Fail-Fast-Abbrueche vor Dump/Restic bei den
Logrechten restriktiv.

## Restore-Readiness prüfen

Restore-Tests niemals direkt in Produktivpfade ausführen. Standard ist das
dedizierte Restore-Smoke-Skript:

```bash
cd /home/chris/web/br.m11h.eu
scripts/restore-smoke-br-wissen.sh --snapshot latest
scripts/restore-smoke-br-wissen.sh --snapshot latest --db
```

Das Skript:

- erlaubt als Ziel nur `/tmp/br-wissen-restore-*`,
- prueft App-/Datenverzeichnis, zentrale Dateien, Artefaktfreiheit,
  Export-/Manifestzaehler und Dump-Marker,
- gibt keine Secretwerte, Credential-Dateien oder Dump-Inhalte aus,
- entfernt temporaere Restore-Pfade automatisch, ausser `--keep-target` ist gesetzt,
- kann mit `--db` den neuesten Dump in einen isolierten Container mit
  `--network none` und ohne Ports einspielen.

Der automatisierte woechentliche Drill nutzt denselben Restore-Smoke mit `--db`,
aber ueber `scripts/run-restore-smoke-drill.sh`, damit ein restriktives Log und
Logrotation entstehen. Vor dem Restore prueft der Wrapper die Storage-/Capacity-
Reserve, damit `/tmp`, Docker und Storage nicht erst waehrend des Drills voll
laufen.

## Isolierten DB-Restore manuell testen

Nur in eine temporaere Testdatenbank ohne publizierte Ports einspielen, niemals
direkt in die Produktivdatenbank. Beispielablauf:

```bash
latest=$(ls -1t /srv/br-wissensdatenbank/backups/postgres-*.sql | head -n 1)
docker volume create br_wissen_restore_test_pgdata
docker run -d --name br-wissen-restore-test-db --network none \
  -e POSTGRES_USER=br_app \
  -e POSTGRES_PASSWORD=restore_test_password \
  -e POSTGRES_DB=br_wissen_restore \
  -v br_wissen_restore_test_pgdata:/var/lib/postgresql/data \
  pgvector/pgvector:pg16@sha256:00ba258a66dac104fd5171074a0084462a64a1369d8513f3d0a634e2f24d15bc
docker exec br-wissen-restore-test-db pg_isready -U br_app -d br_wissen_restore
sudo bash -lc 'docker exec -i br-wissen-restore-test-db psql -v ON_ERROR_STOP=1 -U br_app -d br_wissen_restore < "$1"' _ "$latest"
```

Nur Zaehler und Marker pruefen, keine Dump-Inhalte ausgeben:

```bash
docker exec br-wissen-restore-test-db psql -U br_app -d br_wissen_restore -Atc \
  "SELECT 'restore_sources=' || count(*) FROM sources; \
   SELECT 'restore_documents=' || count(*) FROM documents; \
   SELECT 'restore_chunks=' || count(*) FROM chunks; \
   SELECT 'restore_queries=' || count(*) FROM queries; \
   SELECT 'restore_answers=' || count(*) FROM answers; \
   SELECT 'restore_exports=' || count(*) FROM answers WHERE html_path IS NOT NULL OR pdf_path IS NOT NULL; \
   SELECT 'restore_vector_extension=' || count(*) FROM pg_extension WHERE extname='vector'; \
   SELECT 'restore_operational_indexes=' || count(*) FROM pg_indexes WHERE schemaname='public' AND indexname IN ('idx_sources_citation_status','idx_sources_last_checked','idx_documents_sha256','idx_chunks_document','idx_chunks_source_class','idx_answers_query','idx_answers_created_at','idx_answers_export_paths','idx_answer_statements_answer','idx_answer_citations_statement','idx_answer_citations_chunk','idx_answer_citations_source_class','idx_audit_log_action_created','idx_audit_log_object');"
```

Cleanup immer ausfuehren:

```bash
docker rm -f br-wissen-restore-test-db
docker volume rm br_wissen_restore_test_pgdata
```

Lokale Dumps werden anschließend rotiert. Standardmäßig bleiben die letzten 20
lokalen Dumps erhalten:

```bash
BR_LOCAL_DUMP_KEEP=20 sudo -E systemctl start br-wissen-backup.service
```

Die lokale Dump-Rotation ist unabhängig von der verschlüsselten Restic-Retention.

Backup-Logs unter `/srv/br-wissensdatenbank/logs/backup-*.log` werden ebenfalls
rotiert. Standardmäßig bleiben die letzten 50 Backup-Logs erhalten:

```bash
BR_BACKUP_LOG_KEEP=50 sudo -E systemctl start br-wissen-backup.service
```

Andere Logtypen werden durch diese Rotation nicht gelöscht.

## Cloudflare Tunnel

- Keine globalen API-Keys im Projekt speichern.
- Echte Tunnel-Credentials nicht committen und nicht protokollieren.
- `cloudflared/config.yml.example` ist nur Vorlage.
- Echte Tunnel-Credentials liegen nicht im App-Projektbaum, sondern unter
  `/srv/br-wissensdatenbank/secrets/cloudflared/`.
- Das Cloudflared-Image laeuft als UID/GID `65532:65532`; das
  Cloudflared-Secret-Unterverzeichnis und die Credentials-Datei sind deshalb
  restriktiv auf diese UID/GID gesetzt (`700`/`600`).
- `docker-compose.yml` mountet nur `cloudflared/config.yml` aus dem Projektbaum
  und das Secret-Verzeichnis separat nach `/run/br-secrets/cloudflared`.

## Not-Aus / Sperrmodus

Sofortmaßnahme bei Verdacht:

```bash
cd /home/chris/web/br.m11h.eu
docker compose stop cloudflared proxy app
```

Zusätzlich Cloudflare-Route/Access-Regel deaktivieren, falls bereits eingerichtet.
