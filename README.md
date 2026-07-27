# BR Wissensdatenbank (`br.m11h.eu`)

Geschuetzte Betriebsrats-Wissensdatenbank auf `m11h`.

## Wichtige Pfade

- App/Compose/Code: `/home/chris/web/br.m11h.eu`
- Sensible Quellen, Texte, Exporte, Logs: `/srv/br-wissensdatenbank`
- Projektprotokoll: `/home/chris/web/diverses/betriebsrat.md`
- Dokumentierter amtlicher Grundbestand: `docs/OFFICIAL-BASELINE.md`

## Betriebsbefehle

Alle Befehle vom Projektverzeichnis aus ausfuehren:

```bash
cd /home/chris/web/br.m11h.eu
```

### Kompakter Statuscheck

```bash
scripts/status-br-wissen.sh
scripts/status-br-wissen.sh --image-pinning
```

Prueft Hostkontext, den Host-Kontext-Guard, Docker-Stack, den
Compose-Service-Guard, systemd-Timer und den read-only Healthcheck.
Standardmaessig werden keine neuen Testantworten erzeugt. Der Statuscheck prueft
zusaetzlich den App-Projektbaum auf lokale Artefakte/Credential-Hinweise und die
aktuellen Containerlogs auf sensible Header-Marker. Die normale Statusausgabe
enthaelt eine lokale/offline Image-Pinning-Readiness ohne Registry-Abhaengigkeit;
mit `--image-pinning` wird zusaetzlich die remote-aktivierte
Image-Pinning-Readiness eingeblendet; der
Image-Pinning-Guard laeuft ohnehin im normalen Statuscheck.

### Ausfuehrlicher Healthcheck

```bash
scripts/status-br-wissen.sh --verbose-health
```

Gibt das vollstaendige JSON des read-only Healthchecks aus.

### Statuscheck mit frischen Regressionen

```bash
scripts/status-br-wissen.sh --with-regressions
```

Erzeugt neue Testantworten und Exporte fuer die Kernfaelle. Nur nutzen, wenn neue
Regressionsergebnisse gewuenscht sind.

### Regression-Source-Hardening-Guard pruefen

```bash
scripts/check-regression-source-hardening.py
scripts/check-regression-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen des Opt-in-Regressionsrunners
`scripts/run-regressions.py`, dessen Docker-Wrapper
`scripts/run-regressions-docker.sh` sowie den read-only
`scripts/check-regression-freshness.py`. Geprueft werden Kernfall-Marker,
Citation-/Export-/Manifest-/Safety-Pruefungen, Wrapper-Aufruf, Freshness-SQL-
Marker, Storage-Pfadschutz und verbotene mutierende Marker. Er liest keine
Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft keine
Regressionen, kein Docker, keine DB-Abfragen, Imports, Backups oder Restores auf.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight vor Dump/Restic.

### Freshness-Source-Hardening-Guard pruefen

```bash
scripts/check-freshness-source-hardening.py
scripts/check-freshness-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen von
`scripts/check-backup-freshness.py` und `scripts/check-restore-freshness.py` auf
erwartete metadata-only Sammlung, sudo-JSON-Hilfsmodi, Retention-, Age-, Rechte-,
Restic-, Dump-, Restore-Smoke- und Summary-Marker. Er liest keine Secrets, Dumps,
Logs, Antworttexte oder Quelleninhalte und ruft keine Freshness-Checks, kein
`sudo`, kein Restic, kein Docker, keine Backups, Restores, Imports oder
DB-Abfragen auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Storage-Source-Hardening-Guard pruefen

```bash
scripts/check-storage-source-hardening.py
scripts/check-storage-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen von
`scripts/check-storage-permissions.py` und `scripts/check-storage-capacity.py` auf
erwartete metadata-only Rechte-, Symlink-, Secret-Kandidaten-, Dump-/Log-Mode-,
Filesystem-, Inode- und Docker-Kapazitaetsmarker. Er liest keine Secrets, Dumps,
Logs, Antworttexte oder Quelleninhalte und ruft keine Storage-Checks, kein
`sudo`, kein Docker, keine Backups, Restores, Imports oder DB-Abfragen auf. Der
Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight vor Dump/Restic.

### Container-Source-Hardening-Guard pruefen

```bash
scripts/check-container-source-hardening.py
scripts/check-container-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen von
`scripts/check-container-hardening.py`, `scripts/check-container-images.sh`,
`scripts/check-image-pinning-guard.sh` und
`scripts/check-image-pinning-readiness.sh` auf erwartete metadata-only
Docker-/Compose-/Image-Referenzmarker, Container-Hardening-Policy, Image-
Inventar, Digest-Pinning und optionale Readiness-Remote-Lookup-Marker. Er ruft
kein Docker, kein Compose, keine Registry-Lookups, keine Backups, Restores,
Imports, Regressionen oder DB-Abfragen auf und liest keine Secrets, Dumps, Logs,
Antworttexte oder Quelleninhalte. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Network-Source-Hardening-Guard pruefen

```bash
scripts/check-network-source-hardening.py
scripts/check-network-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen der Netzwerk-/Exposure-Guards:
Network-Exposure, Public-DNS, Multi-Resolver-DNS, Authoritative-DNS, CAA,
Direct-Origin-Bypass, Direct-Origin-Port, Host-UDP, Host-Firewall, Host-NFT,
Network-Policy-Consistency, Network-Policy-Runtime-Env und
Network-Policy-Runtime-Summary. Geprueft werden metadata-only-/keine-Secrets-
Marker, erwartete Origin-/Tailscale-Ziele, BR-relevante TCP-/UDP-Ports,
Loopback-Proxy- und Tunnelmarker, DNS-/CAA-/Direct-Origin-/Firewall-/nft-
Parsingmarker, Network-Policy-Invarianten und kompakte Summary-Ausgaben. Er ruft
keine Docker-, DNS-, HTTP-/TLS-, Firewall-/nft-, Import-, Backup-, Restore-,
Regressions- oder DB-Pruefungen auf und liest keine Secrets, Dumps, Logs,
Antworttexte oder Quelleninhalte. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Access-Runtime-Source-Hardening-Guard pruefen

```bash
scripts/check-access-runtime-source-hardening.py
scripts/check-access-runtime-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen von
`scripts/check-runtime-http-security.py`,
`scripts/check-external-access-surface.py`,
`scripts/check-external-cookie-security.py`,
`scripts/check-tls-certificate.py` und `scripts/check-app-auth-surface.py` auf
erwartete unauthentifizierte metadata-only Header-, Cookie-, TLS- und
CSRF-Negativprobe-Marker sowie kompakte Summary-Ausgaben. Er liest keine Secrets,
Dumps, Logs, Antworttexte oder Quelleninhalte und ruft keine HTTP-/TLS-Probes,
kein Docker, keine Imports, Backups, Restores, Regressionen oder DB-Abfragen auf.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight vor Dump/Restic.

### Statuscheck mit Duplikatbericht

```bash
scripts/status-br-wissen.sh --duplicates
```

Gibt zusaetzlich einen read-only Bericht zu identischen Dokument-SHA-Gruppen aus.
Es wird nichts geloescht oder zusammengefuehrt.

### Nur read-only Healthcheck

```bash
scripts/healthcheck-br-wissen-docker.sh
```

Prueft u. a. Tabellenzaehlungen, chunklose Quellen, OCR-Reparaturintegritaet,
Exportkonsistenz und aktuelle Antwort-Citations. Veraendert keine Quellen und
erzeugt keine Antworten.

Einzeilige Summary fuer Logs/Journald:

```bash
scripts/healthcheck-br-wissen-docker.sh --summary
```

Lesbare Summary fuer manuelle Kontrolle:

```bash
scripts/healthcheck-br-wissen-docker.sh --summary --pretty
```

### Kernregressionen direkt

```bash
scripts/run-regressions-docker.sh
```

Erzeugt frische strukturierte Antworten und geschuetzte HTML/PDF-Exporte fuer:

- OCR/Tarif/JobService-Corona
- BAG/GRUEN-only
- DSGVO/BDSG/GRUEN-only
- DemografieTV/Tarif-Dedupe

### Duplikatbericht direkt

```bash
scripts/report-duplicate-documents-docker.sh
```

Listet identische Dokument-SHA-Gruppen mit Quellen, Quellentypen, Chunkanzahlen
und read-only Einschaetzung fuer die Antwort-Dedupe.

### Python-Syntaxcheck ohne Bytecode-Artefakte

```bash
scripts/check-python-syntax.sh
scripts/check-python-syntax.sh --summary
```

Der Python-Syntax-Guard prueft alle Python-Dateien in `app/`, `scripts/` und
`worker/` per AST-Parse. Dieser Check erzeugt keine `__pycache__`-Verzeichnisse
und keine `*.pyc`-Dateien im Projektbaum, liest keine Secrets, Dumps, Logs,
Antworttexte oder Quelleninhalte und gibt im Summary-Modus nur kompakte Zaehler
aus. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight
und im Backup-Preflight vor Dump/Restic.

### Shell-Syntax-Guard pruefen

```bash
scripts/check-shell-syntax.sh
scripts/check-shell-syntax.sh --summary
```

Der Shell-Syntax-Guard prueft Shell-Skripte im `scripts/`-Verzeichnis per
`bash -n`, ohne die Skripte auszufuehren. Er liest keine Secrets, Dumps, Logs,
Antworttexte oder Quelleninhalte und gibt im Summary-Modus nur kompakte Zaehler
aus. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight
und im Backup-Preflight vor Dump/Restic.

### Systemd-Source-Hardening-Guard pruefen

```bash
scripts/check-systemd-source-hardening.py
scripts/check-systemd-source-hardening.py --summary
```

Der Guard ist read-only und validiert die systemd-Projektquellen unter
`systemd/` auf erwartete Service-/Timer-Marker: Beschreibungen, Wants/After,
Type, User, WorkingDirectory, ExecStart, Healthcheck-ExecStartPre-Kette,
OnCalendar, Persistent, RandomizedDelaySec und WantedBy. Er ruft kein `systemctl`
auf, veraendert keine installierten Units und liest keine Secrets, Dumps, Logs,
Antworttexte oder Quelleninhalte. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Status-Source-Hardening-Guard pruefen

```bash
scripts/check-status-source-hardening.py
scripts/check-status-source-hardening.py --summary
```

Der Guard ist read-only und validiert den zentralen Status-Wrapper
`scripts/status-br-wissen.sh` auf erwartete read-only Defaults, explizite Opt-ins
fuer regressions-/berichtserzeugende Pfade, Guard-Abschnitte und kompakte
Summary-Aufrufe. Er liest keine Secrets, Dumps, Logs, Antworten, Importe oder
Quelleninhalte und ruft keine Statuschecks, kein Docker, kein `systemctl`, keine
Imports, Backups, Restores oder Regressionen auf. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight vor
Dump/Restic.

### Healthcheck-Source-Hardening-Guard pruefen

```bash
scripts/check-healthcheck-source-hardening.py
scripts/check-healthcheck-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen des App-Healthchecks
`scripts/healthcheck-br-wissen.py` sowie dessen Docker-Wrapper
`scripts/healthcheck-br-wissen-docker.sh` auf erwartete read-only DB-/Datei-
Integritaetschecks, Summary-Ausgabe, Fehlerbedingungen und Wrapper-Marker. Er
liest keine Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft
keinen Healthcheck, kein Docker, keine DB-Abfragen, Imports, Backups, Restores
oder Regressionen auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Operational-Wrapper-Source-Hardening-Guard pruefen

```bash
scripts/check-operational-wrapper-source-hardening.py
scripts/check-operational-wrapper-source-hardening.py --summary
```

Der Guard ist read-only und validiert operative Wrapper-Quellen fuer Backup,
Restore-Smoke, Importe, Regressionen, Exporte, Repair, Cloudflare-Pattern-Hilfe
und OCR auf erwartete Fail-Fast-, absolute Helper-Pfad-, Laufzeitgrenzen- und
Keine-Secrets-Marker. Er liest keine Backup-Env-Inhalte, Secrets, Dumps, Logs,
Antworttexte, Exporte oder Quelleninhalte und startet keine Backups, Restores,
Docker, rsync, OCR, Imports, Regressionen, Repairs, Exporte, Restic-, sudo- oder
systemd-Aktionen. Der Guard laeuft im normalen Statuscheck, im systemd-
Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Script-Permission-Policy-Guard pruefen

```bash
scripts/check-script-permission-policy.py
scripts/check-script-permission-policy.py --summary
```

Der Guard ist read-only und prueft metadata-only Dateiart, Modus, Ownership,
Symlink-, World-writable-, Group-writable- und Ausfuehrbarkeits-Policy fuer
`scripts/`, `systemd/`, `docs/` und ausgewaehlte Top-Level-Projektquellen.
Bewusst nicht ausfuehrbare Helper-Quellen in `scripts/` sowie `0664`-Doku- und
Unit-Quellen werden als dokumentierte Projektquellen behandelt; es erfolgt keine
`chmod`-/`chown`-Remediation. Der Summary-Marker ist
`script_permission_policy_status=ok`. Der bewusst enge Top-Level-Scope umfasst
nur `.env.example`, `.gitignore`, `Dockerfile`, `README.md`, `docker-compose.yml`
und `requirements.txt`; Runtime-Artefakte, Secrets, Dumps, Logs, Exporte und
generierte Dateien bleiben bei Artifact-, Git- und Storage-Guards. Der Guard liest
keine Secrets, Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte und laeuft
im normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight
vor Dump/Restic.

### Projektbaum auf lokale Artefakte/Secrets pruefen

```bash
scripts/check-project-artifacts.sh
```

Prueft, ob versehentlich lokale Artefakte oder Credential-Hinweise im
App-Projektbaum liegen, z. B. `*.pyc`, `__pycache__`, `*.log`, `.env`,
`*.env`, `cloudflared/*.json`, `*credential*` oder `*token*`.

### Guard-Coverage-Guard pruefen

```bash
scripts/check-guard-coverage.py
scripts/check-guard-coverage.py --summary
```

Der Guard ist read-only und prueft, ob die Guard-Skripte selbst konsistent in den
operativen Flaechen verdrahtet sind: normaler Statuscheck, Backup-Preflight,
Projekt- und installierte systemd-Healthcheck-Unit sowie zentrale Readiness-
Marker. Er liest nur Projektquellen, Doku und Unit-Text; Secretwerte,
Backup-Env-Inhalte, Dumps, Logs, Antworttexte oder Quelleninhalte werden nicht
gelesen oder ausgegeben. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Meta-Source-Hardening-Guard pruefen

```bash
scripts/check-meta-source-hardening.py
scripts/check-meta-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Meta-/Governance-Guardquellen
`scripts/check-guard-coverage.py`, `scripts/check-readiness-doc.py`,
`scripts/check-python-syntax.sh`, `scripts/check-shell-syntax.sh` und
`scripts/check-systemd-units.sh` auf erwartete Verdrahtungs-, Readiness-, Syntax-
und systemd-Unit-Marker sowie kompakte Summary-Ausgaben. Er ruft keine dieser
Guards, kein `systemctl`, kein Docker, keine Backups, Restores, Imports,
Regressionen oder DB-Abfragen auf und liest keine Secrets, Dumps, Logs,
Antworttexte, Exporte oder Quelleninhalte. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight vor
Dump/Restic.

### Doku-Source-Hardening-Guard pruefen

```bash
scripts/check-doc-source-hardening.py
scripts/check-doc-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Dokumentationsquellen `README.md`,
`docs/RUNBOOK.md`, `systemd/README.md` und `docs/READINESS.md` auf erwartete
Betriebs-, Guardrail-, Backup-/Restore-, systemd- und Keine-Secrets-Marker. Er
liest keine Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft keine
Statuschecks, kein Docker, kein `systemctl`, keine Backups, Restores, Imports,
Regressionen oder DB-Abfragen auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Source-Hardening-Coverage-Guard pruefen

```bash
scripts/check-source-hardening-coverage.py
scripts/check-source-hardening-coverage.py --summary
```

Der Guard ist read-only und validiert das Inventar aller `scripts/check-*`-
Hilfen. Jede Check-Datei muss entweder einer dokumentierten Source-Hardening-
Schicht zugeordnet sein, selbst eine Source-Hardening-/Governance-Schicht sein
oder als explizite Legacy-/Hilfs-Ausnahme dokumentiert sein. Er liest keine
Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft keine Guards,
kein Docker, kein `systemctl`, keine Backups, Restores, Imports, Regressionen
oder DB-Abfragen auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Summary-Contract-Guard pruefen

```bash
scripts/check-summary-contracts.py
scripts/check-summary-contracts.py --summary
```

Der Guard ist read-only und validiert die Summary-/Statuskey-Vertraege der in
`check-guard-coverage.py` deklarierten GuardSpec-Liste. Er prueft statisch, ob
jeder deklarierte `status_key` in der jeweiligen Skriptquelle vorkommt und ob
`--summary`-integrierte Guards einen Summary-Vertrag in der Quelle abbilden. Er
liest keine Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft keine
Guards, kein Docker, kein `systemctl`, keine Backups, Restores, Imports,
Regressionen oder DB-Abfragen auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Surface-Registry-Guard pruefen

```bash
scripts/check-surface-registry.py
scripts/check-surface-registry.py --summary
```

Der Guard ist read-only und validiert, dass Status-Wrapper, Backup-Preflight und
systemd-Healthcheck die zentrale `GuardSpec`-Registry aus
`check-guard-coverage.py` in Reihenfolge und ohne verdeckte Extra-/Missing-
Check-Aufrufe spiegeln. Bewusste Status-only-Hilfen wie Container-Image- und
Image-Pinning-Readiness-Details sind explizit dokumentiert. Er liest keine
Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft keine Guards,
kein Docker, kein `systemctl`, keine Backups, Restores, Imports, Regressionen
oder DB-Abfragen auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Guard-Registry-Integrity pruefen

```bash
scripts/check-guard-registry-integrity.py
scripts/check-guard-registry-integrity.py --summary
```

Der Guard ist read-only und validiert die zentrale `GuardSpec`-Registry selbst:
Duplikate bei Labels, Skripten, Statuskeys und Backup-Labels, fehlende oder nicht
ausfuehrbare Check-Skripte, Statuskey-/Backup-Label-Formate und einfache
Argumentvertraege. Er liest keine Secrets, Dumps, Logs, Antworttexte oder
Quelleninhalte und ruft keine Guards, kein Docker, kein `systemctl`, keine
Backups, Restores, Imports, Regressionen oder DB-Abfragen auf. Der Guard laeuft
im normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight
vor Dump/Restic.

### Protocol-Integrity-Guard pruefen

```bash
scripts/check-protocol-integrity.py
scripts/check-protocol-integrity.py --summary
```

Der Guard ist read-only und validiert das Projektprotokoll
`/home/chris/web/diverses/betriebsrat.md` auf erwartete Struktur, aktuelle
Guardrail-/Backup-/Restore-/Healthcheck-Marker, Restic-Backup-Einbindung und
offensichtliche Credential-/Header-Leak-Marker. Er liest keine Secrets, Dumps,
Logs, Antworttexte oder Quelleninhalte und ruft keine Guards, kein Docker, kein
`systemctl`, keine Backups, Restores, Imports, Regressionen oder DB-Abfragen auf.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight vor Dump/Restic.

### Git-Remote-Readiness pruefen

```bash
scripts/check-git-remote-readiness.py
scripts/check-git-remote-readiness.py --summary
```

Der Guard ist read-only und validiert, dass der Projektbaum ein sauberes Git-Repo
auf Branch `main` ist, `origin` auf
`git@github.com:scheffe2804/scheffe2804-br.m11h.eu.git` zeigt, `main` nach
`origin/main` trackt, lokaler HEAD und GitHub-Remote-HEAD uebereinstimmen und im
Git-Index keine typischen Secret-, Dump-, Credential-, Backup- oder Runtime-
Artefakte versioniert sind. `.env.example` ist die einzige bewusst erlaubte
Env-Datei im Index. Wenn der Guard im Root-Backup-Kontext laeuft, werden Git-
Metadaten per `sudo -n -u <Projektbesitzer>` als Projektbesitzer gelesen, damit
SSH-Key/known_hosts konsistent bleiben; die Summary zeigt dies als `git_user=`.
Der Guard liest keine Secretdateien, gibt keine Diffs oder Dateiinhalte aus und
fuehrt kein Commit, Push, Pull, Fetch, Backup, Restore, Docker, `systemctl`,
Import, Regression oder DB-Abfragen aus. Aktueller erwarteter Marker ist
`git_remote_readiness_status=ok` fuer das GitHub-Repo
`scheffe2804/scheffe2804-br.m11h.eu`.

Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight vor Dump/Restic. Waehrend eines bewusst offenen Arbeitsblocks ist
`dirty=1` erwartbar; vor Backup-/Healthcheck-Abschluss muss der Arbeitsbaum durch
Commit und Push wieder sauber sein.

### Host-Kontext-Guard pruefen

```bash
scripts/check-host-context.py
scripts/check-host-context.py --summary
```

Der Guard ist read-only und prueft, ob die BR-Wissen-Betriebschecks auf dem
erwarteten Zielhost `m11h.eu` mit `HOST_ROLE=m11h`, `THIS_SERVER=m11h`, Public
IPv4 `31.70.74.139` und Tailscale IPv4 `100.102.205.121` laufen. Er gibt nur
nicht-sensitive Hostmetadaten aus und liest keine Secrets, Dump-, Log- oder
Backup-Env-Inhalte. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Time-Sync-Guard pruefen

```bash
scripts/check-time-sync.py
scripts/check-time-sync.py --summary
```

Der Guard ist read-only und prueft Zeit-/NTP-Metadaten, die fuer TLS-
Zertifikatsgueltigkeit, Backup-Freshness und Restore-Freshness relevant sind. Er
nutzt `timedatectl` und `chronyc tracking`, aendert keine Zeitdienste und gibt
nur Status, Zeitzone, Stratum, Offset- und Leap-Status-Marker aus. NTP muss
synchron sein; chrony muss einen plausiblen Stratum, niedrigen System-/RMS-Offset
und `Leap status: Normal` melden. Falls die optionale `SystemClockSynchronized`-
Property auf diesem System nicht verfuegbar ist, wird sie als `system_clock=-1`
informativ ausgegeben und nicht als Fehler gewertet, solange chrony sauber ist.
Servernamen, Secrets, Logs, Dumps, Antworten oder Quelleninhalte werden nicht
ausgegeben. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-
Preflight und im Backup-Preflight.

### Compose-Service-Guard pruefen

```bash
scripts/check-compose-services.py
scripts/check-compose-services.py --summary
```

Der Guard ist read-only und prueft Docker-Compose-Metadaten fuer die fuenf
erwarteten Services `app`, `db`, `worker`, `proxy` und `cloudflared`. Alle fuenf
muessen genau einmal vorhanden und `running` sein; fuer `app` und `db` wird
zusaetzlich `healthy` verlangt. Es werden keine Containerlogs, Secrets, Dumps,
Antworten oder Quelleninhalte gelesen. Der Guard laeuft im normalen Statuscheck,
im systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic. Fuer
den Live-Betrieb auf `m11h` ist `cloudflared` trotz Compose-`profile: tunnel`
bewusst Pflicht, weil der Cloudflare-Tunnel Teil des erwarteten Live-Stacks ist.

### Privilege-Policy-Guard pruefen

```bash
scripts/check-privilege-policy.py
scripts/check-privilege-policy.py --summary
```

Der Guard ist read-only und prueft mit `sudo -n -l -U chris` nur aggregierte
Policy-Metadaten der effektiven sudo-Rechte des BR-Betriebsnutzers. Er gibt keine
sudoers-Datei, keine vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs,
Antworten oder Quelleninhalte aus, sondern nur Zaehler und Policy-Klassen wie
`nopasswd_all=<0|1>`, `unrestricted_all=<0|1>` und `broad_sudo=<0|1>`. Breite
sudo-Rechte werden bewusst als Risiko-Metadaten sichtbar gemacht, aber nicht als
Fehler gewertet, weil eine Restriktion von sudoers ein separater systemweiter
Migrationsblock mit Lockout-/Workflow-Risiko ist. Aktueller erwarteter Marker:
`privilege_policy_status=ok`. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Privilege-Risk-Review-Guard pruefen

```bash
scripts/check-privilege-risk-review.py
scripts/check-privilege-risk-review.py --summary
```

Der Guard ist read-only und verknuepft den aktuellen aggregierten
Privilege-Policy-Status mit der dokumentierten Risikoakzeptanz in
`docs/PRIVILEGE-RISK-REVIEW.md`. Er bleibt nur gruen, wenn `broad_sudo=1`
bewusst akzeptiert, `least_privilege_followup=required` dokumentiert und
`sudoers_auto_change_allowed=0` gesetzt ist. Zusaetzlich prueft er
`last_review_date` und `next_review_due`, damit der vereinbarte Review-Zeitraum nicht nur
als Absicht, sondern als faelliger Nachweis sichtbar bleibt. Er gibt keine sudoers-Inhalte,
keine vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs, Antworttexte
oder Quelleninhalte aus und aendert keine sudoers-Konfiguration. Bei akzeptiertem
kritischem Privilegienrisiko meldet er bewusst
`privilege_risk_review_status=accepted_risk` und `critical_privilege_risk=1`,
statt ein irrefuehrendes `ok` auszugeben. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight
vor Dump/Restic.

### Privilege-Least-Privilege-Plan-Guard pruefen

```bash
scripts/check-privilege-least-privilege-plan.py
scripts/check-privilege-least-privilege-plan.py --summary
```

Der Guard ist read-only und prueft den konkreten Folgeplan in
`docs/PRIVILEGE-LEAST-PRIVILEGE-PLAN.md`. Erwartet werden `plan_status=planned`,
`target_due`, `requires_lockout_protection=1`, `requires_rollback_plan=1`,
`requires_visudo_validation=1`, `requires_backup_before_change=1`,
`requires_command_inventory=1`, `requires_staged_rollout=1` und
`sudoers_auto_change_allowed=0`. Er gibt keine sudoers-Inhalte, keine
vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs, Antworttexte oder
Quelleninhalte aus und aendert keine sudoers-Konfiguration. Aktueller erwarteter
Marker: `privilege_least_privilege_plan_status=planned`. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight
vor Dump/Restic.

### Privilege-Remediation-Gate-Guard pruefen

```bash
scripts/check-privilege-remediation-gate.py
scripts/check-privilege-remediation-gate.py --summary
```

Der Guard ist read-only und prueft `docs/PRIVILEGE-REMEDIATION-GATE.md` sowie die
aktuellen Risk-/Plan-Summaries. Erwartet werden
`privilege_remediation_gate_status=closed`, `remediation_allowed=0`,
`actual_sudoers_change_allowed=0`, `accepted_risk_visible=1` und
`remediation_complete=0`. Damit bleibt klar: Der aktuelle Stand ist keine echte
sudoers-Remediation und keine automatische sudoers-Aenderung. Der Guard gibt keine
sudoers-Inhalte, keine vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs,
Antworttexte oder Quelleninhalte aus und laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Privilege-No-Sudoers-Change-Guard pruefen

```bash
scripts/check-privilege-no-sudoers-change.py
scripts/check-privilege-no-sudoers-change.py --summary
```

Der Guard ist read-only und prueft `docs/PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md`.
Erwartet werden `privilege_no_sudoers_change_status=active`,
`sudoers_changes_allowed=0`, `sudoers_remediation_requested=0`,
`actual_sudoers_change_allowed=0`, `remediation_complete=0` und
`accepted_risk_continues=1`. Damit ist dokumentiert, dass in diesem Arbeitsstrang
keine sudoers-Aenderungen vorgenommen werden. Der Guard gibt keine sudoers-Inhalte,
keine vollstaendigen Kommandolisten, keine Secrets, Dumps, Logs, Antworttexte oder
Quelleninhalte aus und laeuft im normalen Statuscheck, im systemd-Healthcheck-
Preflight und im Backup-Preflight vor Dump/Restic.

### Core-Source-Hardening-Guard pruefen

```bash
scripts/check-core-source-hardening.py
scripts/check-core-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen von
`scripts/check-host-context.py`, `scripts/check-time-sync.py`,
`scripts/check-compose-services.py`, `scripts/check-privilege-policy.py`,
`scripts/check-privilege-risk-review.py`,
`scripts/check-privilege-least-privilege-plan.py`,
`scripts/check-privilege-remediation-gate.py`,
`scripts/check-privilege-no-sudoers-change.py`, `scripts/check-project-artifacts.sh` und
`scripts/check-runtime-log-markers.sh` auf erwartete metadata-only Host-, Zeit-,
Compose-Service-, Privilege-Policy-, Privilege-Risk-Review-, Privilege-Least-Privilege-Plan-, Privilege-Remediation-Gate-, Privilege-No-Sudoers-Change-, Artefakt- und Runtime-Log-Marker sowie kompakte Summaries. Er
ruft kein Docker, kein Compose, kein `timedatectl`, kein `chronyc`, kein
`hostname`, kein Tailscale, keine Backups, Restores, Imports, Regressionen oder
DB-Abfragen auf und liest keine Secrets, Dumps, Logs, Antworttexte oder
Quelleninhalte. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-
Preflight und im Backup-Preflight vor Dump/Restic.

### Container-Hardening-Guard pruefen

```bash
scripts/check-container-hardening.py
scripts/check-container-hardening.py --summary
```

Der Guard ist read-only und prueft Docker-Inspect-Metadaten fuer die fuenf
erwarteten Container. Er meldet unter anderem privilegierte Container, zusaetzliche
Capabilities, Device-Mounts, Host-/Sonder-Namespaces, unerwartete Netzwerke,
unerwartete Port-Bindings, fehlende erwartete Mounts, nicht read-only gemountete
Secret-/Konfigurationspfade, fehlendes read-only RootFS, fehlendes
`no-new-privileges`, fehlende Ressourcenlimits, unerwartete Runtime-User,
fehlendes `cap_drop: ALL` fuer App/DB/Worker/Cloudflared und abweichende
Restart-Policies.
Env-Werte, Logs, Dateiinhalte, Dumps, Antworten oder Quelleninhalte werden nicht
gelesen oder ausgegeben. Der aktuelle Betriebszustand erzwingt read-only RootFS,
`no-new-privileges` und Ressourcenlimits fuer alle fuenf Container; App, DB,
Worker und Cloudflared droppen alle Capabilities. Der Caddy-Proxy laeuft als
Nicht-root-User `1001:127`, bleibt aber bei `cap_drop: ALL` bewusst ausgenommen,
weil Caddy damit nicht stabil startete; die uebrigen Hardening-Schichten bleiben
dort aktiv. Caddy-`/data` und `/config` sind tmpfs-Runtimepfade.

### Compose-Source-Hardening-Guard pruefen

```bash
scripts/check-compose-source-hardening.py
scripts/check-compose-source-hardening.py --summary
```

Der Guard ist read-only und prueft nur `docker-compose.yml` als statische Quelle.
Er ruft bewusst nicht `docker compose config` auf, damit Env-Dateien nicht
expandiert und keine Secretwerte sichtbar werden. Er validiert die erwarteten
Hardening-Keys, User, tmpfs inklusive Caddy-`/data` und `/config`,
Ressourcenlimits, Mount-Modi und Port-/Expose-Regeln inklusive dokumentierter
Caddy-Proxy-Ausnahme bei `cap_drop: ALL`.

### Network-Exposure-Guard pruefen

```bash
scripts/check-network-exposure.py
scripts/check-network-exposure.py --summary
```

Der Guard ist read-only und prueft nur Docker-/Compose-, Proxy-, Tunnel-,
Listener- und nft-Firewall-Metadaten. Er stellt sicher, dass der lokale Proxy nur ueber
`127.0.0.1:18083 -> 8080` publiziert ist, keine erwarteten BR-Wissen-Services auf
nicht-Loopback-Interfaces veroeffentlicht werden, Caddy weiterhin auf `:8080` mit
Basic Auth, Noindex-/NoStore-Headern und Reverse Proxy zu `app:8000` konfiguriert
ist und der Cloudflare-Tunnel `br.m11h.eu` auf `http://proxy:8080` mit
404-Fallback routet. Credential-Dateien, Secretwerte, Logs, Dumps, Antworten oder
Quelleninhalte werden nicht gelesen oder ausgegeben. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Public-DNS-Exposure-Guard pruefen

```bash
scripts/check-public-dns-exposure.py
scripts/check-public-dns-exposure.py --summary
```

Der Guard ist read-only und prueft die oeffentliche DNS-Aufloesung von
`br.m11h.eu`. Erwartet werden globale A-/AAAA-Adressen ohne direkte Origin-
Exposition: die m11h-Public-IP `31.70.74.139` und die Tailscale-IP
`100.102.205.121` duerfen nicht als DNS-Ziel auftauchen. DNS-Zonen oder
Cloudflare-Einstellungen werden nicht geaendert; Secretwerte, Logs, Dumps,
Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben. Der Guard
laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

### Public-DNS-Multiresolver-Guard pruefen

```bash
scripts/check-public-dns-multiresolver.py
scripts/check-public-dns-multiresolver.py --summary
```

Der Guard ist read-only und fragt eine kleine feste Menge externer rekursiver
Resolver (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) per DNS-UDP nach A-/AAAA-Metadaten
fuer `br.m11h.eu`. Er ergaenzt den lokalen Public-DNS-Exposure-Guard, damit
lokales Resolver-Caching oder Propagationseffekte auffallen. Erwartet werden
ausreichend erfolgreiche Resolver, globale Records und keine direkten Treffer auf
die m11h-Public-IP `31.70.74.139` oder die Tailscale-IP `100.102.205.121`.
DNS-Zonen oder Cloudflare-Einstellungen werden nicht geaendert; Secretwerte,
Logs, Dumps, Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben.
DNSSEC wird bewusst nicht validiert; die Resolverliste bleibt Teil des Change-
Managements.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

### Public-DNS-Authoritative-Guard pruefen

```bash
scripts/check-public-dns-authoritative.py
scripts/check-public-dns-authoritative.py --summary
```

Der Guard ist read-only, ermittelt die NS-Records der Zone `m11h.eu` ueber einen
Bootstrap-Resolver und fragt die autoritativen Nameserver direkt ohne rekursive
DNS-Anforderung nach A-/AAAA-Metadaten fuer `br.m11h.eu`. Er ergaenzt lokalen und
Multi-Resolver-Check um die autoritative Sicht. Erwartet werden autoritative
Antworten mit globalen Records und ohne direkte Treffer auf `31.70.74.139` oder
`100.102.205.121`. DNS-Zonen oder Cloudflare-Einstellungen werden nicht
geaendert; Secretwerte, Logs, Dumps, Antworten oder Quelleninhalte werden nicht
gelesen oder ausgegeben. DNSSEC wird bewusst nicht validiert; Bootstrap-Resolver
und Nameserverliste bleiben Teil des Change-Managements. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Public-DNS-CAA-Guard pruefen

```bash
scripts/check-public-dns-caa.py
scripts/check-public-dns-caa.py --summary
```

Der Guard ist read-only und fragt CAA-Metadaten fuer `br.m11h.eu` und `m11h.eu`
ueber einen oeffentlichen Resolver ab. Er prueft, ob vorhandene CAA-Records den
aktuellen Let's-Encrypt-Zertifikatspfad erlauben und ob unbekannte kritische
CAA-Properties auftauchen. Aktuell sind keine CAA-Records vorhanden; das wird als
unbeschraenkte Ausstellung und `letsencrypt_allowed=1` dokumentiert. DNS-Zonen,
Cloudflare- oder TLS-Konfiguration werden nicht geaendert; Secretwerte, Logs,
Dumps, Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben.
DNSSEC wird bewusst nicht validiert; Resolverwahl und CAA-Policy bleiben Teil des
Change-Managements. Der Guard laeuft im normalen Statuscheck, im systemd-
Healthcheck-Preflight und im Backup-Preflight.

### Direct-Origin-Bypass-Guard pruefen

```bash
scripts/check-direct-origin-bypass.py
scripts/check-direct-origin-bypass.py --summary
```

Der Guard ist read-only und prueft bekannte IPv4-/IPv6-Origin- und Tailscale-IP-
Pfade mit `Host: br.m11h.eu` per `HEAD` auf HTTP/HTTPS. Standardziele sind die
oeffentliche m11h-IPv4/IPv6 und die Tailscale-IPv4/IPv6; Standardpfade sind `/`,
`/healthz`, `/login`, `/queries`, `/sources`, `/answers`, `/search` und
`/validation`. Er liest keine Antwortkoerper und wertet nur Verbindungsstatus,
HTTP-Status und Header-Metadaten aus. Host/Header- und Pfadwerte werden gegen
CR/LF-Injection und nicht absolute Pfade geprueft. Erwartet wird, dass ein
direkter Zugriff ohne Cloudflare Access entweder blockiert ist, per TLS nicht
nutzbar ist, Basic Auth verlangt oder nur auf `https://br.m11h.eu/...`
redirectet. HTTPS-Probes nutzen normale Zertifikatsvalidierung fuer `br.m11h.eu`;
jede direkt gueltig nutzbare HTTPS-Antwort am Origin waere failend. 2xx-/
Inhaltsantworten oder sonstige unerwartete direkte HTTP-Antworten waeren ebenfalls
failend. Die Targetliste ist bewusst IP-basiert; benannte Ziele werden als
Konfigurationsfehler abgelehnt. Firewall-, DNS-, Caddy- oder App-Konfiguration
werden nicht geaendert; Secretwerte, Logs, Dumps, Antworten oder Quelleninhalte
werden nicht gelesen oder ausgegeben. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight.

### Direct-Origin-Port-Exposure-Guard pruefen

```bash
scripts/check-direct-origin-port-exposure.py
scripts/check-direct-origin-port-exposure.py --summary
```

Der Guard ist read-only und prueft bekannte IPv4-/IPv6-Origin- und Tailscale-IP-
Ziele per TCP-Connect auf einen kuratierten BR-relevanten Portsatz: `80`, `443`,
`8000`, `8080`, `18083`, `5432` und `2019`. Es werden keine Anwendungsdaten
gesendet und keine Antwortkoerper gelesen. Nur die Webports `80`/`443` duerfen als
offen erscheinen; deren Inhalts-/Access-Semantik prueft weiterhin der Direct-
Origin-Bypass-Guard. App-, Proxy-, Datenbank- oder Admin-Ports auf den direkten
Origin-/Tailscale-Zielen waeren failend. Dies ist bewusst kein Voll-Portscan;
weitere Ports oder externe Scanstandorte bleiben eigene Change-Management-Bloecke.
Firewall-, DNS-, Caddy- oder App-Konfiguration werden nicht geaendert; Secretwerte,
Logs, Dumps, Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

### Host-UDP-/QUIC-Exposure-Guard pruefen

```bash
scripts/check-host-udp-exposure.py
scripts/check-host-udp-exposure.py --summary
```

Der Guard ist read-only und prueft lokale Host-/Compose-Metadaten fuer einen
kuratierten BR-relevanten UDP-Portsatz: `443`, `80`, `8000`, `8080`, `18083`,
`5432` und `2019`. Es werden keine UDP-Pakete gesendet und keine Antwortdaten
gelesen. Standardmaessig ist fuer direkte Origin-/Tailscale-Adressen kein
BR-relevanter UDP-Port erlaubt; insbesondere eine direkte UDP-443-/QUIC-
Exposition waere failend. Loopback-only UDP-Listener sind keine direkte Origin-
Exposition. Der Guard ist bewusst kein UDP-Portscan gegen externe Ziele.
Firewall-, DNS-, Caddy- oder App-Konfiguration werden nicht geaendert; Secretwerte,
Logs, Dumps, Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

### Host-Firewall-BR-Ports-Guard pruefen

```bash
scripts/check-host-firewall-br-ports.py
scripts/check-host-firewall-br-ports.py --summary
```

Der Guard ist read-only und prueft lokale `iptables-save`-/`ip6tables-save`-
Metadaten fuer BR-relevante Host-Firewall- und NAT-Regeln. Er aendert keine
Firewall-Regeln, sendet keine Pakete und gibt keine Regeltexte aus. Gezaehlt und
bewertet werden unerwartete direkte INPUT-ACCEPTs oder DNAT-/REDIRECT-Regeln fuer
BR-relevante TCP-Ports `8000`, `8080`, `18083`, `5432`, `2019` sowie UDP-Ports
`443`, `80`, `8000`, `8080`, `18083`, `5432`, `2019`. Web-TCP `80`/`443` ist
als Web-Exposition erlaubt und wird inhaltlich separat ueber den Direct-Origin-
Bypass-Guard validiert. Die erwartete Loopback-NAT-Regel `127.0.0.1:18083` ist
erlaubt; Docker-interne Bridge-Regeln werden gezaehlt, aber nicht als direkte
Origin-Exposition gewertet. Secretwerte, Logs, Dumps, Antworten oder
Quelleninhalte werden nicht gelesen oder ausgegeben. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Host-NFT-BR-Ports-Guard pruefen

```bash
scripts/check-host-nft-br-ports.py
scripts/check-host-nft-br-ports.py --summary
scripts/check-host-nft-br-ports.py --self-test
```

Der Guard ist read-only und prueft die native nftables-Sicht ueber
`sudo -n nft -j list ruleset`. Er ergaenzt den iptables-/ip6tables-kompatiblen
Host-Firewall-BR-Ports-Guard, aendert keine Firewall-Regeln, sendet keine Pakete
und gibt keine Regeltexte aus. Bewertet werden strukturierte JSON-Metadaten zu
unerwarteten direkten INPUT-ACCEPTs oder NAT-/DNAT-/REDIRECT-Regeln fuer dieselben
BR-relevanten TCP-/UDP-Ports. Web-TCP `80`/`443`, die erwartete Loopback-NAT-
Regel `127.0.0.1:18083` und Docker-interne Bridge-Regeln werden analog zum
iptables-Guard behandelt. Der Guard erkennt native nft NAT-Ausdruecke und
iptables-kompatible `xt:DNAT`-/`xt:REDIRECT`-Ausdruecke. Relevante BR-Input- oder
NAT-Regeln mit nicht vollstaendig aufgeloesten nft-Konstrukten wie `lookup`,
`map`, `vmap`, `dynset`, `objref`, `flow` oder Set-Referenzen werden failend als
unsupported gemeldet, damit solche Konstrukte nicht still uebersehen werden. Einfache
benannte und anonyme nft-Sets fuer Ports/Adressen werden aus der JSON-Sicht
read-only expandiert; nicht aufloesbare Set-Referenzen in relevanten Regeln sind
failend.
BR-relevante Input-/NAT-Regeln mit dport-gebundenem `jump` oder `goto` werden
read-only in Zielketten hinein verfolgt. Dabei werden geerbte Port-/Protokoll-
Kontexte mit Zielketten-Actions kombiniert. Nicht aufloesbare oder zyklische
Zielketten werden failend als Findings gemeldet, damit kein relevanter Pfad still
uebersehen wird.
Secretwerte, Logs, Dumps, Antworten oder Quelleninhalte werden nicht gelesen oder
ausgegeben. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-
Preflight und im Backup-Preflight.
Mit `--self-test` prueft der Guard rein lokal synthetische nft-JSON-Regeln fuer
bekannte gute und schlechte Policy-Faelle inklusive aufgeloester und nicht
aufloesbarer `jump`-/`goto`-Pfade sowie einfacher named/anonymous Sets; dabei
wird die echte Firewall nicht beruehrt.

### Network-Policy-Consistency-Guard pruefen

```bash
scripts/check-network-policy-consistency.py
scripts/check-network-policy-consistency.py --summary
```

Der Guard ist read-only und vergleicht die nicht-sensitiven Policy-Defaults der
Direct-Origin-, Host-UDP-, Host-Firewall- und Host-NFT-Guards. Er prueft, dass die
bekannten direkten Origin-/Tailscale-Ziele, Wildcard-Hosts, BR-relevanten TCP-/
UDP-Ports, erlaubten Web-TCP-Ports und die erwartete Loopback-NAT-Regel
`127.0.0.1:18083` zwischen den Guards konsistent bleiben. Gelesen werden nur
lokale Guard-Quelltexte und `/etc/opencode-host-context`; es werden keine Pakete
gesendet, keine Firewall-Regeln geaendert und keine Secrets, Logs, Dumps,
Antworten oder Quelleninhalte gelesen. Der Guard laeuft im normalen Statuscheck,
im systemd-Healthcheck-Preflight und im Backup-Preflight.
Wichtig: Dieser Guard prueft Source-/Default-Konsistenz und Host-Kontextwerte,
nicht die aktive Runtime-Netzwerk-/Firewall-Konfiguration; dafuer bleiben die
jeweiligen Runtime-/Firewall-/Direct-Origin-Guards zustaendig.

### Network-Policy-Runtime-Env-Guard pruefen

```bash
scripts/check-network-policy-runtime-env.py
scripts/check-network-policy-runtime-env.py --summary
```

Der Guard ist read-only und prueft, dass BR-Netzwerkpolicy-Environment-Variablen
nicht unbemerkt in der aktuellen Guard-Umgebung, in installierten BR-systemd-
Units oder in Projektquellen ausserhalb erlaubter Guard-/Doku-Dateien gesetzt
werden. Er gibt nur Variablennamen/Zaehlwerte aus, nie Werte. So sollen Runtime-
Overrides wie abweichende Direct-Origin-Ziele, Portlisten, erlaubte Webports oder
Loopback-NAT-Ausnahmen auffallen, bevor sie andere Guards beeinflussen. Es werden
keine Pakete gesendet, keine Firewall-Regeln geaendert und keine Secrets, Logs,
Dumps, Antworten oder Quelleninhalte gelesen. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

Kompakte Ausgabe fuer systemd/Journald:

```bash
scripts/check-network-policy-runtime-env.py --summary
```

### Network-Policy-Runtime-Summary-Guard pruefen

```bash
scripts/check-network-policy-runtime-summary.py
scripts/check-network-policy-runtime-summary.py --summary
```

Der Guard ist read-only und fuehrt die kompakten Summary-Laeufe der relevanten
Netzwerk-/Exposure-Guards aus. Er prueft nur Status- und Zaehler-Invarianten,
z. B. direkte Origin-Ziele, erlaubte Webports, unerwartete NAT-/Input-Findings,
DNS-Origin-Treffer, Runtime-Env-Overrides sowie neue Host-NFT-Zaehler fuer
Chain-Traversal und Set-Expansion. Er gibt nur aggregierte Zaehler und
Finding-Labels aus, keine Regeltexte, DNS-Antwortinhalte, Headerwerte,
Secretwerte, Dumps, Logs, Antworten oder Quelleninhalte. Er aendert keine
Firewall-, DNS-, Cloudflare-, Caddy- oder App-Konfiguration. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Runtime-Logs auf sensible Header-Marker pruefen

```bash
scripts/check-runtime-log-markers.sh
```

Die Pruefung gibt nur Containername, Status und Trefferanzahl aus, keine
Logzeilen oder Headerwerte. Der Caddy-Proxy filtert sensible Request-Header in
seinem JSON-Logging, unter anderem `Authorization`, `Cookie` und
Cloudflare-Access-Header.

### Runtime-HTTP-Security pruefen

```bash
scripts/check-runtime-http-security.py
scripts/check-runtime-http-security.py --summary
```

Der Guard ist read-only und ruft den lokalen Loopback-Proxy ohne Zugangsdaten ab.
Er prueft fuer `/` und `/healthz`, dass Caddy unauthentifiziert mit `401` und
`WWW-Authenticate: Basic` blockt, dass Security-Header wie Noindex, NoStore,
Content-Security-Policy, Referrer-Policy, X-Frame-Options, X-Content-Type-Options,
Permissions-Policy, COOP und CORP auch auf der vorgeschalteten Basic-Auth-
Fehlerantwort vorhanden sind und dass kein `Server`-Header ausgeliefert wird.
Antwortkoerper, Secrets, Logs, Dumps, Antworten oder Quelleninhalte werden nicht
gelesen. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-
Preflight und im Backup-Preflight.

### External-Access-Surface pruefen

```bash
scripts/check-external-access-surface.py
scripts/check-external-access-surface.py --summary
```

Der Guard ist read-only und ruft zentrale oeffentliche HTTPS-Pfade unter
`https://br.m11h.eu` ohne Zugangsdaten ab, darunter `/`, `/healthz`, `/login`,
`/queries`, `/sources`, `/answers`, `/search` und `/validation`. Er liest keine
Antwortkoerper und prueft nur Header-/Status-Metadaten. Erwartet wird, dass der
Pfad unauthentifiziert entweder bereits durch Cloudflare Access/Challenge-Marker
geschuetzt ist oder, falls die Anfrage bis Caddy durchgereicht wird, durch den
lokalen Basic-Auth-401-Pfad blockiert wird. Im aktuellen Live-Betrieb ist der
Cloudflare-Access-Pfad aktiv: `cf-access-domain=br.m11h.eu`, Cloudflare-Marker,
CSP-/Frame-/Content-Type-Header und Access-Cookie-Metadaten sind sichtbar;
Caddy-Basic-Auth bleibt zusaetzlich ueber den lokalen Runtime-HTTP-Security-Guard
abgesichert. Cookie-Inhalte, Zugangsdaten, Secrets, Logs, Dumps, Antworten oder
Quelleninhalte werden nicht gelesen oder ausgegeben. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### External-Cookie-Security pruefen

```bash
scripts/check-external-cookie-security.py
scripts/check-external-cookie-security.py --summary
```

Der Guard ist read-only und ruft den oeffentlichen HTTPS-Pfad ohne Zugangsdaten
fuer `/`, `/healthz` und `/login` ab. Er liest keine Antwortkoerper und prueft nur
`Set-Cookie`-Attribute, ohne Cookie-Werte auszugeben. Erwartet werden Cloudflare-
Access-Cookies mit `Secure`, `HttpOnly`, gueltigem `SameSite`-Attribut, `Path=/`,
Ablauf (`Expires` oder `Max-Age`) und fehlender oder erwarteter Domain
(`br.m11h.eu`, `.br.m11h.eu` oder `.m11h.eu`). `SameSite=None` wird nur zusammen
mit `Secure` als gueltige Cloudflare-Access-Kompatibilitaetsvariante akzeptiert.
Cookie-Werte, Zugangsdaten, Secrets, Logs, Dumps, Antworten oder Quelleninhalte
werden nicht gelesen oder ausgegeben. Der Guard laeuft im normalen Statuscheck,
im systemd-Healthcheck-Preflight und im Backup-Preflight.

### TLS-Certificate-Guard pruefen

```bash
scripts/check-tls-certificate.py
scripts/check-tls-certificate.py --summary
```

Der Guard ist read-only und oeffnet nur eine TLS-Verbindung zu `br.m11h.eu:443`.
Er validiert dabei Zertifikats-/Protokoll-Metadaten: erfolgreiche
Standard-CA-Pruefung, TLS-Version `TLSv1.2` oder `TLSv1.3`, gueltigen
SAN-/Wildcard-Namen fuer `br.m11h.eu`, vorhandenen Issuer und mindestens 14 Tage
Restlaufzeit. HTTP-Antwortkoerper, Zugangsdaten, Cookies, Secrets, Logs, Dumps,
Antworten oder Quelleninhalte werden nicht gelesen oder ausgegeben. Der Guard
laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

### App-Auth-/CSRF-Surface pruefen

```bash
scripts/check-app-auth-surface.py
scripts/check-app-auth-surface.py --summary
```

Der Guard ist read-only und prueft im App-Container ohne Zugangsdaten und ohne
Redirect-Following nur Status-/Header-Metadaten auf dem internen App-Port. Er
erwartet, dass geschuetzte GET-Routen unauthentifiziert per `303` nach `/login`
umleiten, dass `/healthz` und `/login` erreichbar sind und dass nicht eingeloggte
POST-/Mutationsrouten ohne CSRF-Token mit `403` blockieren. Die Summary weist
unerwartete POST-Erfolge und POST-Redirects explizit als `post_successes` und
`post_redirects` aus. Antwortkoerper, Secrets, Dumps, Logs, Antworten oder
Quelleninhalte werden nicht gelesen. Der Guard laeuft im normalen Statuscheck,
im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Import-Pipeline pruefen

```bash
scripts/check-import-pipeline.py
scripts/check-import-pipeline.py --summary
```

Der Guard ist read-only und gibt nur Status, Zaehler und Log-Alter aus. Er prueft
unter anderem aktive Import-Timer, aktuelle m00h-/BAG-Importlogs,
Checksummen-/Erfolgsmarker, Basis-Invarianten der Quellen-/Dokumenten-/Chunk-
Tabellen sowie kuerzlich gepruefte Quellen. Secretwerte, Logzeilen mit Inhalten
oder Dokumentinhalte werden nicht ausgegeben. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Import-Source-Hardening-Guard pruefen

```bash
scripts/check-import-source-hardening.py
scripts/check-import-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Import-Quellen
`scripts/import-m00h-betriebsrat.sh`, `scripts/import-bag-feed-docker.sh`,
`scripts/import-bag-feed.py` sowie die zugehoerigen Import-Service-/Timer-Quellen
unter `systemd/` auf erwartete Fail-Fast-, Pfad-, Log-, Rechte-, Checksum-,
Docker-, BAG-Feed-, Storage- und DB-Marker. Er liest keine importierten
Quelleninhalte, Logs, Dumps, Backup-Env-Inhalte, Credentials, Antworten oder
Dokumente und ruft keine Imports, kein Docker, kein `rsync`, keine Netzwerkzugriffe,
kein `systemctl` und kein `sudo` auf. Der Guard laeuft im normalen Statuscheck,
im systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Antwort-/Export-Safety pruefen

```bash
scripts/check-answer-export-safety.py
scripts/check-answer-export-safety.py --summary
```

Der Guard ist read-only und prueft gespeicherte Antworten und erzeugte
HTML/PDF-Exporte ohne Ausgabe von Antwort-, Quellen- oder Secret-Inhalten. Er
kontrolliert unter anderem Citation-Abdeckung, Antwort-/Chunk-Klassenkonsistenz,
GELB-Zitationen, Exportpfade im Storage-Root, vorhandene HTML/PDF-Dateien,
Mindestgroessen, Noindex-/Wasserzeichen-Marker sowie verbotene Pfad-, Datei- und
Secret-/Header-Marker. Seit der Manifest-Haertung prueft er ausserdem fuer jeden
Export `manifest.json`, Manifest-Version, Antwort-ID, Policyflags,
Validierungsdaten sowie HTML/PDF-Hash und Dateigroesse. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.
Strukturierte Antworten werden atomar gespeichert: Antwortzeile, Statements,
Citations und Audit-Eintrag werden erst gemeinsam committed, damit parallele
Guards keine gerade entstehenden Antworten als fehlerhaften Zwischenstand sehen.

Bestehende Exporte koennen nur fuer technische Manifestdateien nachgezogen
werden, ohne HTML/PDF oder Antwortinhalte zu veraendern:

```bash
docker compose exec -T app python - < scripts/backfill-export-manifests.py
```

### Audit-Trail pruefen

```bash
scripts/check-audit-trail.py
scripts/check-audit-trail.py --summary
```

Der Guard ist read-only und prueft den Audit-Trail ueber Zaehler und bekannte
Aktionsklassen, ohne Audit-Details, Antworttexte, Quelleninhalte oder Secrets
auszugeben. Er kontrolliert leere Actor/Actions/Object-UIDs, unbekannte Aktionen,
Zukunftszeitstempel sowie Abdeckung fuer Antworterzeugung und validierte
Exporte. Explizit dokumentierte historische Bootstrap-/Testluecken bleiben als
Legacy-Ausnahmen erlaubt; neue Luecken fuehren zum Fehler. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### DB-Schema und Betriebsindexes pruefen

```bash
scripts/check-db-schema.py
scripts/check-db-schema.py --summary
```

Der Guard ist read-only und prueft erwartete Extension, Tabellen, Spalten und
Betriebsindexes, ohne Dateninhalte, Antworttexte, Quelleninhalte oder Secrets
auszugeben. Er stellt sicher, dass die produktive DB und Restore-Dumps die fuer
Healthchecks, Exporte, Audit und Betriebsabfragen benoetigten Indexes enthalten.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

### Data-Integrity-Source-Hardening-Guard pruefen

```bash
scripts/check-data-integrity-source-hardening.py
scripts/check-data-integrity-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Quellen von
`scripts/check-answer-export-safety.py`, `scripts/check-audit-trail.py` und
`scripts/check-db-schema.py` auf erwartete metadata-only Antwort-/Export-,
Audit- und DB-Schema-Marker, explizite Legacy-Ausnahmen, Export-Manifest- und
Betriebsindex-Erwartungen sowie kompakte Summary-Ausgaben. Er liest keine
Secrets, Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte und ruft kein
Docker, keine DB-Abfragen, keine Backups, Restores, Imports oder Regressionen
auf. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight
und im Backup-Preflight vor Dump/Restic.

### Backup-Source-Hardening-Guard pruefen

```bash
scripts/check-backup-source-hardening.py
scripts/check-backup-source-hardening.py --summary
```

Der Guard ist read-only und validiert das Backup-Skript
`scripts/backup-br-wissen.sh` auf erwartete Fail-Fast-, Env-, Protokoll-,
Preflight-, Dump-, Restic-, Rechte- und Retention-Marker. Er liest keine
Backup-Env-Inhalte, Dumps, Logs, Antworttexte oder Quelleninhalte und ruft kein
Backup, kein Restic, kein Docker und kein `systemctl` auf. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight
vor Dump/Restic. Der Backup-Wrapper nutzt fuer die eigentlichen Restic-Aufrufe
keinen unqualifizierten Root-`PATH`, sondern waehlt `RESTIC_BIN` aus den
kuratierten absoluten Pfaden `/usr/bin/restic` und `/usr/local/bin/restic` und
protokolliert nur den gewaehlt Pfad als `restic_bin=<pfad>`.

### Restore-Source-Hardening-Guard pruefen

```bash
scripts/check-restore-source-hardening.py
scripts/check-restore-source-hardening.py --summary
```

Der Guard ist read-only und validiert die Restore-Smoke-Quellen
`scripts/run-restore-smoke-drill.sh` und `scripts/restore-smoke-br-wissen.sh` auf
erwartete Fail-Fast-, Zielpfad-, Rechte-, Storage-Preflight-, Restic-Restore-,
isolierte DB-Restore-, Cleanup-, Marker- und Retention-Marker. Er liest keine
Backup-Env-Inhalte, Dumps, Logs, Antworttexte, wiederhergestellten Dateien oder
Quelleninhalte und ruft keinen Restore, kein Restic, kein Docker, kein `sudo` und
kein `systemctl` auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Restore-Runtime-Policy-Guard pruefen

```bash
scripts/check-restore-runtime-policy.py
scripts/check-restore-runtime-policy.py --summary
```

Der Guard ist read-only und prueft metadata-only das Restore-Smoke-
Ausfuehrungsumfeld: Backup-Env-Rechte, Restore-Skriptmodi, Restic-/Docker-Binary-
Metadaten, `/tmp`-Policy sowie installierte Restore-Smoke-Service-/Timer-Policy
mit `User=root`, erwarteter `ExecStart`-/`WorkingDirectory`-Verdrahtung und
persistenter Wochenplanung. Er liest keine Backup-Env-Inhalte, keine Secretwerte,
Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte und startet keine Backups,
Restores, Docker, Imports, Regressionen oder DB-Abfragen. Der root-noetige JSON-
Hilfsmodus wird ueber `/usr/bin/sudo` gestartet; Restic und Docker werden nur aus
kuratierten absoluten Pfaden (`/usr/bin/restic`, `/usr/local/bin/restic`,
`/usr/bin/docker`, `/usr/local/bin/docker`) ausgewaehlt und metadata-only auf
Datei-/Owner-/Mode-/Symlink-/Sonderbit-Policy geprueft. Die Summary zeigt nur
Status, Zaehler, Dateimodi, zentrale Service-/Timer-Policy-Bits und
Helfermetadaten (`helper_binaries=<n>`, `restic_binary=<pfad>`,
`docker_binary=<pfad>`). Der Guard
laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-
Preflight vor Dump/Restic.

### Backup-Scope-Guard pruefen

```bash
scripts/check-backup-scope.py
scripts/check-backup-scope.py --summary
```

Der Guard ist read-only und validiert metadata-only den neuesten BR-Wissen-
Restic-Snapshot auf erwarteten Host, erwartete Tags und den erwarteten Backup-
Pfadumfang fuer App, internen Datenbereich und Projektprotokoll. Er nutzt die
root-only Backup-Env nur fuer `restic snapshots --json`, startet keine Backups
oder Restores, ruft kein Docker, kein `systemctl`, keine Imports, Regressionen
oder DB-Abfragen auf und gibt keine Backup-Secretwerte, Dump-Inhalte, Log-
Inhalte, Antworttexte, Exporte oder Quelleninhalte aus. Root-noetige Metadaten-
Aufrufe nutzen kuratierte absolute Helferpfade: `/usr/bin/sudo`, `/usr/bin/test`,
`/usr/bin/bash` und einen erlaubten Restic-Pfad aus `/usr/bin/restic` oder
`/usr/local/bin/restic`, statt vom Root-`PATH` abzuhaengen. Diese Helfer werden
metadata-only auf Existenz, Symlink-Freiheit, regulaere Datei, `root:root`, Modus,
Ausfuehrbarkeit und unerwartete Sonderbits geprueft. Die Summary bleibt auf
Status, Zaehler, kurze Snapshot-ID und Helfermetadaten beschraenkt und meldet
`helper_binaries=<n>` sowie `restic_binary=<pfad>`. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight vor
Dump/Restic.

### Backup-Runtime-Policy-Guard pruefen

```bash
scripts/check-backup-runtime-policy.py
scripts/check-backup-runtime-policy.py --summary
```

Der Guard ist read-only und prueft metadata-only das Backup-Ausfuehrungsumfeld:
root-only Backup-Env-Datei und Elternverzeichnis, Restic-Binary-Metadaten sowie
die installierte Backup-Service-Policy mit `User=root` und erwarteter
`ExecStart`-/`WorkingDirectory`-Verdrahtung. Er liest keine Backup-Env-Inhalte,
keine Secretwerte, Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte und
startet keine Backups, Restores, Docker, Imports, Regressionen oder DB-Abfragen.
Der root-noetige JSON-Hilfsmodus wird ueber `/usr/bin/sudo` gestartet; Restic wird
nur aus `/usr/bin/restic` oder `/usr/local/bin/restic` ausgewaehlt und metadata-
only auf Datei-/Owner-/Mode-/Symlink-/Sonderbit-Policy geprueft. Die Summary zeigt
nur Status, Zaehler, Dateimodi, ob der Backup-Service als root konfiguriert ist
und Helfermetadaten (`helper_binaries=<n>`, `restic_binary=<pfad>`). Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.
Der Backup-Wrapper selbst nutzt denselben kuratierten Restic-Pfadumfang
(`/usr/bin/restic` oder `/usr/local/bin/restic`) fuer `backup` und `forget`.

### Backup-Freshness und lokale Retention pruefen

```bash
scripts/check-backup-freshness.py
scripts/check-backup-freshness.py --summary
```

Der Guard ist read-only und prueft aktuelle Backup-Logs, lokale Dumps,
Retention-Zaehler, Erfolgsmarker des letzten Backup-Logs, Preflight-Marker und den
neuesten Restic-Snapshot. Zusaetzlich prueft er metadata-only, ob Restic-Locks im
Repository vorhanden sind, meldet deren Gesamtanzahl und faellt nur bei stale
Locks. Die Lock-Abfrage laeuft mit `LC_ALL=C`, damit der `stale`-Marker moeglichst
stabil englisch erkannt wird; `no locks`-Statuszeilen werden nicht als Lock
gezaehlt. Ausserdem prueft er metadata-only die Restic-Env-Datei auf Existenz,
regulaere Datei, Symlink-Freiheit, `root:root` und Modus `600`. Er gibt keine
Backup-Secretwerte, Dump-Inhalte, Lock-IDs oder Log-Inhalte aus. Der Guard laeuft
im normalen Statuscheck und im
systemd-Healthcheck-Preflight, aber bewusst nicht als Backup-Preflight, damit ein
neues Backup nicht durch ein veraltetes vorheriges Backup blockiert wird.
Die Summary zeigt den geprueften Env-Dateimodus als `backup_env_mode=600`.
Der root-noetige Scan laeuft ueber `--scan-json`; er wird wie beim Restore-
Freshness-Guard ueber `/usr/bin/sudo` und einen kuratierten absoluten Python-
Interpreter gestartet. Restic-Snapshot- und Lock-Metadatenabfragen nutzen nur
kuratiert erlaubte absolute Restic-Pfade (`/usr/bin/restic` oder
`/usr/local/bin/restic`) sowie `/usr/bin/test` und `/usr/bin/bash`, statt vom
Root-`PATH` abzuhaengen. Diese Helfer werden metadata-only auf Existenz,
Symlink-Freiheit, regulaeren Dateityp, `root:root`, Modus, Ausfuehrbarkeit und
unerwartete Sonderbits geprueft. Die kompakte Summary weist das als
`helper_binaries=<n>`, `python_binary=<pfad>` und `restic_binary=<pfad>` aus.
Der Guard zaehlt auch den Storage-/Permission-
Preflight im neuesten Backup-Log. Zusaetzlich validiert er, dass der neueste
Restic-Snapshot den Projektprotokollpfad enthaelt und nicht aelter als der
aktuelle Protokollstand ist; die kompakte Summary meldet dies als
`protocol_snapshot_current=1`. Diese Pruefung laeuft absichtlich erst nach
Backups, nicht als Backup-Preflight, damit ein neuer Protokollnachtrag das
notwendige Folgebackup nicht blockiert.

### Restic-Repository-Integritaet manuell pruefen

```bash
sudo -n bash -lc 'set -euo pipefail; set -a; source /etc/web-backup/repos.d/m11h-br-wissen.env; set +a; restic check'
```

Dieser Check ist ein expliziter, read-only Repository-Integritaetsnachweis ueber
die root-only Backup-Env. Secret-/Env-Werte werden dabei nicht ausgegeben. Der
Check nimmt einen exklusiven Restic-Repository-Lock und ist deshalb bewusst nicht
Teil des Backup-Preflights oder des regulaeren systemd-Healthchecks. Er soll als
manueller bzw. periodischer Wartungscheck nach groesseren Backup-/Restore-
Haertungsbloecken oder bei Verdacht auf Repository-Probleme laufen. Zuletzt lief
er am `2026-06-06T06:25:14Z` erfolgreich ueber 48 Snapshots mit dem Ergebnis
`no errors were found`.

Der leichte Freshness-Guard dazu startet keinen `restic check` und nimmt keinen
Repository-Lock. Er prueft nur das dokumentierte Ergebnis im Readiness-Dossier:

```bash
scripts/check-restic-repository-check.py --summary
```

Die Summary lautet `restic_repository_check_status=ok ... documented_success=1
... lock_preflight=0`. Dieser Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight; der schwere `restic check`
selbst bleibt weiterhin ein expliziter Wartungslauf.

### Storage-/Permission-Guard pruefen

```bash
scripts/check-storage-permissions.py
scripts/check-storage-permissions.py --summary
```

Der Guard prueft ausschliesslich Metadaten wie Modus, Owner, Symlink- und
Kandidatenzaehler. Er liest oder druckt keine Secret-, Dump-, Log- oder
Export-Inhalte. Geprueft werden unter anderem world-writable Dateien,
Symlinks im Storage, Secret-Kandidaten im Projektbaum, zu offene Secret-Dateien,
Cloudflared-Credential-Owner/-Modus sowie lokale Dump-/Backup-Log-Modi. Der
root-noetige Scan laeuft ueber `--scan-json`, damit Journald keine grossen
Inline-Skripte protokolliert. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight vor Dump/Restic.

### Storage-/Capacity-Guard pruefen

```bash
scripts/check-storage-capacity.py
scripts/check-storage-capacity.py --summary
```

Der Guard prueft nur Kapazitaets-Metadaten fuer `/`, App-Pfad,
`/srv/br-wissensdatenbank`, `/tmp` und `/var/lib/docker`: freie Bytes,
Belegungsprozent, Inode-Belegung sowie eine kompakte Docker-System-DF-Summary.
Er liest keine Datei-, Dump-, Log- oder Secret-Inhalte. Standardgrenzen:
mindestens 10 GiB frei fuer Root/App/Storage/Docker, mindestens 2 GiB fuer `/tmp`,
maximal 90 Prozent Byte- und Inode-Belegung. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight, im Backup-Preflight vor Dump/Restic
und vor automatisierten Restore-Smoke-Drills.

### Restore-Freshness und Restore-Smoke-Drill pruefen

```bash
scripts/check-restore-freshness.py
scripts/check-restore-freshness.py --summary
sudo systemctl start br-wissen-restore-smoke.service
sudo systemctl status br-wissen-restore-smoke.service --no-pager
```

Der Restore-Freshness-Guard prueft nur Metadaten und Marker des neuesten
Restore-Smoke-Logs: Alter, Logmodus, `restore_status=ok`, `db_restore_status=ok`,
den angeforderten Snapshot, die konkret aufgeloeste Restic-Snapshot-ID
`restore_resolved_snapshot=<id>`, den konfigurierten SQL-Readiness-Wert
`restore_sql_ready_wait`, Dump-Marker, Manifest-/Exportzaehler, DB-Isolation
(`--network none`, keine Ports), `vector`-Extension und Betriebsindexes. Er liest
keine Secretwerte und gibt keine Dump- oder Log-Inhalte aus. Der root-noetige Scan
laeuft ueber `--scan-json`. Der Guard laeuft im normalen Statuscheck und im
systemd-Healthcheck-Preflight.

Zusaetzlich gleicht der Guard die im neuesten Restore-Smoke-Log genannte
`restore_resolved_snapshot` metadata-only gegen Restic ab: Der Snapshot muss im
Repository vorhanden sein, die erwarteten Tags `br-wissen` und
`includes-internal-sources` tragen und exakt die erwarteten Backup-Pfade
`/home/chris/web/br.m11h.eu`, `/srv/br-wissensdatenbank` sowie
`/home/chris/web/diverses/betriebsrat.md` enthalten. Die Summary weist diesen
Abgleich mit `restore_resolved_snapshot_present=<0|1>` und
`restore_resolved_snapshot_paths=<n>` aus; Secret-, Dump-, Log- oder
Restore-Inhalte werden dafuer nicht gelesen oder ausgegeben. Die Restic-Abfrage
nutzt bewusst keinen unqualifizierten Root-`PATH`, sondern nur einen kuratierten
ausfuehrbaren Restic-Pfad aus `/usr/bin/restic` oder `/usr/local/bin/restic`.
Auch die dafuer noetigen lokalen Helfer werden mit absoluten Pfaden aufgerufen:
`/usr/bin/sudo`, `/usr/bin/test`, `/usr/bin/bash` und fuer den root-noetigen
JSON-Scan einen kuratierten absoluten Python-Interpreter statt der Skript-
Shebang. Aktuell wird `/usr/bin/python3.13` gewaehlt, weil es eine regulaere
root-owned Datei ist; Symlinks wie `/usr/bin/python3` werden nicht akzeptiert.
Der Guard prueft diese Helfer sowie den ausgewaehlten Python- und Restic-Pfad metadata-only auf Existenz,
Symlink-Freiheit, regulaere Datei, `root:root`, nicht gruppen-/world-writable,
Ausfuehrbarkeit und erwartete Sonderbits; die Summary meldet die Anzahl als
`helper_binaries=<n>` und den aktuell ausgewaehlten Python-Pfad als
`python_binary=<pfad>`.
Zusaetzlich prueft der Guard sein eigenes Skript metadata-only auf Existenz,
Symlink-Freiheit, regulaere Datei, nicht gruppen-/world-writable,
Ausfuehrbarkeit und Mindestgroesse. Die Summary meldet diese Selbstpruefung als
`self_script_policy=<0|1>`; die Guard-Datei ist dafuer auf Modus `755`
gehaertet.
Ergaenzend prueft der Guard die projektbezogenen Parent-Verzeichnisse
`/home/chris/web/br.m11h.eu` und `/home/chris/web/br.m11h.eu/scripts`
metadata-only auf Existenz, Symlink-Freiheit, Verzeichnistyp, Owner-/Group-
Konsistenz zum Skript, nicht gruppen-/world-writable und Suchbarkeit; die
Summary meldet dies als `self_parent_policy=<0|1>`.

Der woechentliche Restore-Smoke-Drill laeuft ueber
`br-wissen-restore-smoke.timer` und nutzt den Wrapper
`scripts/run-restore-smoke-drill.sh`. Dieser schreibt restriktive Logs unter
`/srv/br-wissensdatenbank/logs/restore-smoke-*.log`, behaelt standardmaessig die
letzten 20 Restore-Smoke-Logs (`BR_RESTORE_LOG_KEEP=20`) und fuehrt den
Restore-Smoke mit isoliertem DB-Restore aus. Vor dem Dump-Import wartet der
Restore-Smoke nach `pg_isready` zusaetzlich auf eine echte SQL-Antwort per
`SELECT 1`; die Wartezeit ist ueber `BR_RESTORE_SQL_READY_WAIT` konfigurierbar
und betraegt standardmaessig 15 Sekunden. Bei `snapshot=latest` loest der Restore-
Smoke vor dem Restore die tatsaechliche Restic-Snapshot-ID auf und schreibt sie
als `restore_resolved_snapshot=<id>` ins metadata-only Restore-Smoke-Log, damit der
gepruefte Snapshot nachvollziehbar bleibt, ohne Restore-, Dump-, Secret- oder
Antwortinhalte auszugeben.

### Readiness-Doku-Freshness pruefen

```bash
scripts/check-readiness-doc.py
scripts/check-readiness-doc.py --summary
```

Der Guard ist read-only und prueft `docs/READINESS.md` auf einen aktuellen
Stand-Zeitstempel, Pflichtmarker, statische Backup-/Restore-/Import-/Storage-
Statusmarker, erreichbare nicht-zirkulaere Summary-Guards, den Protokollnachtrag
sowie kompakte Backup-/Restore-Evidenzwerte. Die Summary loest
`backup_snapshot=<id>` aus dem Backup-Scope-Guard und `restore_dump=<dump>` aus
dem Restore-Freshness-Guard auf. Er ruft bewusst weiterhin nicht den
Backup-Freshness-Guard auf, damit frische Doku- oder Protokollnachtraege den
naechsten Sicherungslauf nicht durch einen Kreisschluss blockieren. Dynamische
Snapshot-IDs und Dumpnamen werden nicht als exakter Dossierinhalt erzwungen,
damit regulaere Nachtbackups den Guard nicht unnoetig rot machen. Er gibt keine
Secretwerte, Dump-Inhalte, Log-Inhalte oder Credential-Inhalte aus. Der Guard
laeuft im normalen Statuscheck und im systemd-Healthcheck-Preflight.

### Regression-Freshness pruefen

```bash
scripts/check-regression-freshness.py
scripts/check-regression-freshness.py --summary
```

Der Guard ist read-only und erzeugt keine neuen Antworten oder Exporte. Er prueft
die zuletzt vorhandenen Kern-Regressionsantworten auf Alter, Statements,
Citation-Abdeckung, erlaubte/erforderliche Quellenklassen, erforderliche Quellen,
doppelte Chunk-IDs, gemischte Duplicate-Dokument-SHA-Gruppen sowie vorhandene
HTML-/PDF-/Manifest-Exporte. Er gibt keine Antworttexte, Quelleninhalte,
Secretwerte, Dump-Inhalte oder Log-Inhalte aus. Der Guard laeuft im normalen
Statuscheck und im systemd-Healthcheck-Preflight.

### Systemd-Units und Timer pruefen

```bash
scripts/check-systemd-units.sh
scripts/check-systemd-units.sh --summary
```

Prueft, ob die zehn BR-Wissen-Service-/Timer-Dateien im Projekt mit
`/etc/systemd/system/` synchron sind, ob die Unit-Dateien keine Symlinks oder
irregulaeren Dateien sind, ob installierte Units nicht group-/world-writable sind,
ob keine Projekt- oder installierte Unit world-writable ist
(`unit_policy_failures=0`), ob installierte Units `root:root` gehoeren, ob
Projekt-Units denselben Owner/dieselbe Group wie `systemd/` haben und ob die
Parent-Verzeichnisse `systemd/`, `/etc/systemd` und `/etc/systemd/system` keine
unerwarteten Symlink-/Typ-/Owner-/Schreibrechte zeigen
(`parent_policy_failures=0`), ob vorhandene Linux-Dateiattribute per `lsattr`
keine unerwarteten Flags ausser dem normalen Extents-Flag `e` zeigen
(`attr_policy_failures=0`, `lsattr_available=1`) und ob die fuenf erwarteten
Timer aktiv sind.
ACL-/xattr-Tools sind auf diesem Host nicht installiert und werden nicht
nachinstalliert; die Summary macht das transparent als `acl_tool_available=0` und
`xattr_tool_available=0` sichtbar.
Die `root:root`-Anforderung gilt dabei nur fuer die installierten `/etc/systemd*`-
Parents; das Projekt-`systemd/` folgt dem Projektbaum-Owner. Vendor-Units unter
`/usr/lib/systemd`, Runtime-Units unter `/run/systemd` und User-Units sind nicht
Teil dieses BR-Wissen-Direct-Unit-Guards.
Geprueft werden nur die direkten BR-Wissen-Unit-Dateien aus der festen
`br-wissen-*`-Liste; normale systemd-Enablement-Symlinks unter `*.wants/` sind
nicht Teil dieses Guards.
Zusaetzlich prueft er, ob eine der fuenf erwarteten BR-Wissen-Service-Units im
systemd-Zustand `failed` haengt. Abgeschlossene oneshot-Services im Zustand
`inactive` sind dabei erwartbar und gelten nicht als Fehler. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Systemd-Loaded-Unit-Guard pruefen

```bash
scripts/check-systemd-loaded-units.py
scripts/check-systemd-loaded-units.py --summary
```

Der Guard ist read-only und prueft per `systemctl show` ausschliesslich geladene
systemd-Metadaten der fuenf BR-Wissen-Services und fuenf Timer: `LoadState`,
`FragmentPath`, `UnitFileState`, `ActiveState`, `Result`, Service-`Type`, `User`,
`WorkingDirectory`, `ExecStart` und die Healthcheck-`ExecStartPre`-Sequenz. Er
startet, stoppt, restartet, enabled, disabled oder reloadet keine Units und liest
keine Secrets, Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte. Erwarteter
Summary-Marker ist `systemd_loaded_unit_status=ok`. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight vor
Dump/Restic und ergaenzt den Datei-Sync-/Rechte-Guard `check-systemd-units.sh` um
die Sicht auf die von systemd tatsaechlich geladene Unit-Konfiguration.

### Container-Image-Inventar pruefen

```bash
scripts/check-container-images.sh
```

Die Pruefung ist read-only und statusbewertet. Sie zeigt lokale Builds,
tag-gepinnte Images, Digest-Pins sowie `latest`-/unversionierte Tags. Der normale
Statuscheck gibt eine kompakte Summary aus. `container_image_status=ok` gilt nur,
wenn Images gefunden werden und keine tag-only-, `latest`- oder unversionierten
Images gemeldet werden. Tag-only-, `latest`- oder unversionierte Images ergeben
`warning`; eine leere Imagebasis ergibt `failed`. Nach dem Digest-Rollout sollen
die externen Laufzeitimages als `digest_pinned` erscheinen.

### Image-Pinning-Readiness pruefen

```bash
scripts/check-image-pinning-readiness.sh
scripts/status-br-wissen.sh --image-pinning
```

Diese Pruefung ist ebenfalls read-only und aendert keine Images. Sie ergaenzt das
Container-Image-Inventar um Dockerfile-`FROM`-Images und, wenn erreichbar,
Registry-Digests. `image_pinning_readiness_status=ok` gilt nur, wenn Referenzen
gefunden werden, keine Tag-, `latest`- oder unversionierten Pinning-Kandidaten
offen sind und keine Remote-Registry-Abfrage fehlschlaegt. Offene Kandidaten oder
Remote-Ausfaelle ergeben `warning`; fehlende Referenzen ergeben `failed`. Nach dem
Digest-Rollout sollen keine Tag- oder `latest`-Pinning-Kandidaten mehr gemeldet
werden. Kuenftige Image-Aenderungen bleiben eigene Wartungsbloecke mit Backup,
Rollback-Notiz, Rebuild/Rollout und anschliessender Validierung.

Der normale Statuscheck nutzt `scripts/check-image-pinning-readiness.sh --summary
--no-remote`, damit externe Registry-Ausfaelle den Standardstatus nicht
verfaelschen. Der optionale `scripts/status-br-wissen.sh --image-pinning` zeigt
zusätzlich den remote-aktivierten Readiness-Check; dort bedeutet `warning` bei
`remote_unavailable>0` eine Registry-Verfuegbarkeitswarnung, nicht automatisch ein
ungepinntes Projektimage. Die Summary nennt dafuer `remote_expected`,
`remote_coverage_pct` und `remote_unavailable_refs=<kommagetrennte Referenzen>`;
Referenzen werden fuer diese Uebersicht ohne Digest-Suffix ausgegeben.

### Image-Pinning-Guard pruefen

```bash
scripts/check-image-pinning-guard.sh
scripts/check-image-pinning-guard.sh --summary
```

Der Guard ist lokal/offline und failend. Er erlaubt lokale Build-Images
`brm11heu-*` sowie digest-gepinnte Referenzen. Tag-only-, unversionierte oder
`latest`-ohne-Digest-Referenzen werden als Verstoß gemeldet. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

### Restore-Readiness pruefen

Nur in einen isolierten temporaeren Pfad wiederherstellen, niemals direkt in die
Produktivpfade:

```bash
scripts/restore-smoke-br-wissen.sh --snapshot latest
scripts/restore-smoke-br-wissen.sh --snapshot latest --db
```

Das Skript stellt nur nach `/tmp/br-wissen-restore-*` wieder her, prueft Struktur,
Dateiexistenz, Groessen, Dump-Marker und optional einen DB-Restore in einem
isolierten Docker-Container mit `--network none`. Es gibt keine Secretwerte,
Credential-Dateien oder Dump-Inhalte aus und entfernt temporaere Restore-Pfade,
Container und Volumes automatisch, sofern nicht `--keep-target` gesetzt ist. Beim
DB-Restore wird nach `pg_isready` eine SQL-Bereitschaftspruefung per `SELECT 1`
ausgefuehrt; `BR_RESTORE_SQL_READY_WAIT` kann fuer langsame Systeme erhoeht
werden.

## systemd-Timer

Installierte Timer:

- `br-wissen-healthcheck.timer` — read-only Healthcheck, taeglich vor Import/Backup.
- `br-wissen-import-m00h.timer` — m00h-/Tailshare-Importpruefung.
- `br-wissen-import-bag.timer` — BAG-Entscheidungen-Import.
- `br-wissen-backup.timer` — verschluesseltes Backup.
- `br-wissen-restore-smoke.timer` — woechentlicher automatisierter Restore-Smoke-Drill.

Status anzeigen:

```bash
systemctl list-timers br-wissen-healthcheck.timer br-wissen-import-m00h.timer br-wissen-import-bag.timer br-wissen-backup.timer br-wissen-restore-smoke.timer --no-pager
```

Journal pruefen:

```bash
sudo journalctl -u br-wissen-healthcheck.service -n 120 --no-pager
sudo journalctl -u br-wissen-backup.service -n 120 --no-pager
sudo journalctl -u br-wissen-restore-smoke.service -n 120 --no-pager
```

## Backups

Manuelles Backup:

```bash
sudo systemctl start br-wissen-backup.service
sudo systemctl status br-wissen-backup.service --no-pager
```

Backup-Konfiguration liegt root-geschuetzt unter `/etc/web-backup/`. Secrets oder
Tokens niemals ausgeben, kopieren oder committen.

Das Projektprotokoll `/home/chris/web/diverses/betriebsrat.md` liegt ausserhalb
von App- und Storage-Pfad, wird aber als eigener Restic-Pfad mitgesichert.

Vor dem verschluesselten Backup laufen der Host-Kontext-Guard, der
Time-Sync-Guard, der Compose-Service-Guard, der Core-Source-Hardening-Guard, der Container-Hardening-Guard, der Network-Exposure-Guard
und der Projektartefakt-Guard
in kompakter Form. Der Artefakt-Guard prueft derzeit 8 Kategorien inklusive
`__pycache__`-Verzeichnissen. Zusaetzlich laufen
Image-Pinning-, Systemd-Unit-, Runtime-HTTP-Security-, External-Access-Surface-, TLS-Certificate-, App-Auth-Surface-, Import-Pipeline-,
Antwort-/Export-Safety-, Audit-Trail-, DB-Schema-, Storage-/Permission- und
Storage-/Capacity-, Readiness-Doku- und Regression-Freshness-Preflight, bevor ein
Dump erzeugt oder Restic gestartet wird. Das Backup-Log enthaelt ausserdem den
Marker `protocol_file_status=included`, den Host-Marker `host_context_status=ok`,
den Time-Sync-Marker `time_sync_status=ok`, den Compose-Service-Marker `compose_service_status=ok`, den
Core-Source-Hardening-Marker `core_source_hardening_status=ok`, den
Container-Hardening-Marker `container_hardening_status=ok`, den
Network-Exposure-Marker `network_exposure_status=ok` und den
Runtime-HTTP-Security-Marker `runtime_http_security_status=ok`, den
External-Access-Surface-Marker `external_access_surface_status=ok`, den
TLS-Certificate-Marker `tls_certificate_status=ok` und den
App-Auth-Surface-Marker `app_auth_surface_status=ok` sowie den
Host-Firewall-BR-Ports-Marker `host_firewall_br_ports_status=ok` und den
Host-NFT-BR-Ports-Marker `host_nft_br_ports_status=ok`.
Alle Backup-Preflights laufen explizit fail-fast: bei einem roten Guard wird
`status=<preflight>_preflight_failed` ins Backup-Log geschrieben und vor Dump/
Restic mit Exitcode 1 abgebrochen. Backup-Freshness wird im Status/systemd-Healthcheck ueberwacht, aber nicht als
Backup-Preflight verwendet.

Backup-Logs werden vor den Preflights mit restriktivem Modus `640` angelegt,
damit auch vorzeitig abbrechende Fail-Fast-Backups keine world-readable Logs
zuruecklassen.

Lokale PostgreSQL-Dumps unter `/srv/br-wissensdatenbank/backups/postgres-*.sql`
werden vom Backup-Skript nach erfolgreicher Dump-Erzeugung konservativ rotiert.
Standard: die letzten 20 lokalen Dumps behalten (`BR_LOCAL_DUMP_KEEP=20`). Die
verschluesselte Restic-Retention ist davon getrennt.

Backup-Logdateien unter `/srv/br-wissensdatenbank/logs/backup-*.log` werden
ebenfalls konservativ rotiert. Standard: die letzten 50 Backup-Logs behalten
(`BR_BACKUP_LOG_KEEP=50`). Andere Logtypen bleiben unberuehrt.

## Sicherheitsregeln

- Nichts aus `/srv/br-wissensdatenbank` direkt oeffentlich ausliefern.
- Keine Secrets in Git, Logs, Compose-Dateien, Markdown oder Chat ausgeben.
- Originalquellen nicht veraendern; OCR/Text/Chunks/Exporte sind Arbeitsdaten.
- Antworten/Exporte nur quellengebunden verwenden: keine Aussage ohne Citation.

## Readiness-Dossier

Der aktuelle Betriebs-, Sicherheits-, Backup-, Restore- und Regressionstand ist
in `docs/READINESS.md` zusammengefasst. Stand des letzten Doku-Abgleichs:
2026-06-04; dabei wurden nur read-only Status-/Summary-Guards genutzt und keine
produktiven Container neu gestartet.
