# Systemd-Units

Diese Units liegen als Projektquellen unter `/home/chris/web/br.m11h.eu/systemd/`.
Auf `m11h` sind die BR-Wissen-Timer inzwischen installiert und aktiviert.

## Installierte Timer auf m11h

- `br-wissen-healthcheck.timer` — read-only Healthcheck, taeglich ab 04:12 Uhr plus bis zu 15 Minuten Zufallsverzoegerung.
- `br-wissen-import-m00h.timer` — m00h-/Tailshare-Importpruefung, taeglich ab 04:17 Uhr plus bis zu 20 Minuten Zufallsverzoegerung.
- `br-wissen-import-bag.timer` — BAG-Entscheidungen-Import, taeglich ab 04:43 Uhr plus bis zu 20 Minuten Zufallsverzoegerung.
- `br-wissen-backup.timer` — verschluesseltes Backup, taeglich ab 04:47 Uhr plus bis zu 30 Minuten Zufallsverzoegerung.
- `br-wissen-restore-smoke.timer` — automatisierter Restore-Smoke-Drill, sonntags ab 06:10 Uhr plus bis zu 45 Minuten Zufallsverzoegerung.

Status pruefen:

```bash
systemctl list-timers 'br-wissen*' --all --no-pager
systemctl is-active br-wissen-healthcheck.timer br-wissen-import-m00h.timer br-wissen-import-bag.timer br-wissen-backup.timer br-wissen-restore-smoke.timer
```

Der Healthcheck-Service fuehrt vor dem read-only App-Healthcheck kompakte Guards
aus:

```text
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-host-context.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-time-sync.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-compose-services.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-privilege-policy.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-privilege-risk-review.py --summary --allow-accepted-risk
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-privilege-least-privilege-plan.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-privilege-remediation-gate.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-privilege-no-sudoers-change.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-core-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-container-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-container-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-compose-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-network-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-network-exposure.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-public-dns-exposure.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-public-dns-multiresolver.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-public-dns-authoritative.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-public-dns-caa.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-direct-origin-bypass.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-direct-origin-port-exposure.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-host-udp-exposure.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-host-firewall-br-ports.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-host-nft-br-ports.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-network-policy-consistency.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-network-policy-runtime-env.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-network-policy-runtime-summary.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-project-artifacts.sh --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-image-pinning-guard.sh --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-systemd-units.sh --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-systemd-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-status-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-healthcheck-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-python-syntax.sh --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-shell-syntax.sh --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-guard-coverage.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-meta-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-doc-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-source-hardening-coverage.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-summary-contracts.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-surface-registry.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-guard-registry-integrity.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-protocol-integrity.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-git-remote-readiness.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-runtime-log-markers.sh
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-access-runtime-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-runtime-http-security.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-external-access-surface.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-external-cookie-security.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-tls-certificate.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-app-auth-surface.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-import-pipeline.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-import-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-answer-export-safety.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-data-integrity-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-audit-trail.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-db-schema.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-backup-scope.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-backup-runtime-policy.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-backup-freshness.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-backup-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-restore-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-restore-runtime-policy.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-freshness-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-storage-source-hardening.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-storage-permissions.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-storage-capacity.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-restore-freshness.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-readiness-doc.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-regression-freshness.py --summary
ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-regression-source-hardening.py --summary
```

Damit schlaegt der automatische Healthcheck fehl, wenn der Host-Kontext nicht
dem erwarteten `m11h`-Zielsystem entspricht, wenn die Hostzeit/NTP-Synchronisation
fuer TLS-/Freshness-Pruefungen unplausibel ist, wenn erwartete Compose-Services
fehlen/nicht laufen oder `app`/`db` nicht healthy sind. `cloudflared` ist im
Live-Betrieb auf `m11h` trotz Compose-`profile: tunnel` bewusst Pflicht. Der
Privilege-Policy-Guard macht die effektive sudo-Policy fuer `chris` read-only als
aggregierte Zaehler sichtbar (`privilege_policy_status=ok`, `broad_sudo=<0|1>`),
ohne sudoers-Inhalte, vollstaendige Kommandolisten oder Secrets auszugeben.
Breite sudo-Rechte werden als Risiko-Metadaten dokumentiert, aber nicht failend
bewertet, weil eine Restriktion ein eigener systemweiter Migrationsblock ist.
Der Privilege-Risk-Review-Guard schlaegt fehl, wenn fuer `broad_sudo=1` keine
dokumentierte Risikoakzeptanz in `docs/PRIVILEGE-RISK-REVIEW.md`, kein
`least_privilege_followup=required` oder kein `sudoers_auto_change_allowed=0`
vorliegt oder `next_review_due` ueberfaellig ist. Bei akzeptiertem kritischem
Privilegienrisiko ist der erwartete Marker
`privilege_risk_review_status=accepted_risk` plus `critical_privilege_risk=1`.
Er liest keine
sudoers-Inhalte und aendert keine sudoers-Konfiguration.
Der Privilege-Least-Privilege-Plan-Guard schlaegt fehl, wenn kein konkreter
Least-Privilege-Folgeplan in `docs/PRIVILEGE-LEAST-PRIVILEGE-PLAN.md`, kein
`target_due`, kein Lockout-/Rollback-/visudo-/Backup-/Inventar-/Staged-Rollout-
Marker oder keine `sudoers_auto_change_allowed=0`-Begrenzung vorliegt. Erwarteter
Marker ist `privilege_least_privilege_plan_status=planned`.
Der Privilege-Remediation-Gate-Guard schlaegt fehl, wenn das read-only Gate in
`docs/PRIVILEGE-REMEDIATION-GATE.md` nicht geschlossen ist oder wenn
`remediation_allowed=0`, `actual_sudoers_change_allowed=0`,
`accepted_risk_visible=1` bzw. `remediation_complete=0` nicht sichtbar sind.
Erwarteter Marker ist `privilege_remediation_gate_status=closed`. Das Gate trennt
accepted-risk-/Plan-Betrieb klar von einer echten sudoers-Remediation.
Der Privilege-No-Sudoers-Change-Guard schlaegt fehl, wenn die aktive Policy in
`docs/PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md` fehlt oder wenn
`sudoers_changes_allowed=0`, `sudoers_remediation_requested=0`,
`actual_sudoers_change_allowed=0`, `remediation_complete=0` bzw.
`accepted_risk_continues=1` nicht sichtbar sind. Erwarteter Marker ist
`privilege_no_sudoers_change_status=active`.
Der Core-Source-Hardening-Guard schlaegt fehl, wenn die Basis-Guardquellen fuer
Host-Kontext, Time-Sync, Compose-Services, Privilege-Policy, Privilege-Risk-Review, Privilege-Least-Privilege-Plan, Privilege-Remediation-Gate, Privilege-No-Sudoers-Change, Projektartefakte
oder Runtime-Log-Marker ihre erwarteten metadata-only-, Summary- oder
Verbotsmarker verlieren oder mutierende Marker enthalten. Der
Container-Hardening-Guard schlaegt fehl, wenn erwartete Container privilegiert
laufen, unerwartete Zusatz-Capabilities, Devices, unerwartete Netzwerke/Ports,
schreibbare Secret-/Konfigurationsmounts, fehlendes read-only RootFS, fehlendes
`no-new-privileges`, fehlende Ressourcenlimits, unerwartete Runtime-User oder
fehlendes `cap_drop: ALL` fuer App/DB/Worker/Cloudflared haben. Der
Container-Source-Hardening-Guard schlaegt fehl, wenn die Container-/Image-
Guardquellen ihre erwarteten metadata-only Docker-/Compose-/Image-Referenz-,
Digest-Pinning-, lokale-Build-Ausnahme-, Readiness- oder Summary-Marker verlieren
oder mutierende Marker enthalten. Der
Compose-Source-Hardening-Guard schlaegt fehl, wenn die statische Compose-Quelle
von den erwarteten Hardening-Keys, Usern, tmpfs-, Mount-, Port-/Expose- oder
Ressourcenlimit-Regeln abweicht. Er ruft bewusst nicht `docker compose config`
auf, damit Env-Dateien nicht expandiert werden. Der Caddy-Proxy laeuft als
Nicht-root-User `1001:127`, bleibt aber bei `cap_drop: ALL` als dokumentierte
Ausnahme bestehen. Der Network-Source-Hardening-Guard schlaegt fehl, wenn die
Netzwerk-/Exposure-Guardquellen ihre erwarteten metadata-only-, DNS-,
Direct-Origin-, UDP-, Firewall-/nft- oder Network-Policy-Marker verlieren oder
mutierende Marker enthalten. Der Network-Exposure-Guard schlaegt zusaetzlich fehl, wenn der lokale BR-Wissen-Proxy
nicht nur ueber `127.0.0.1:18083` erreichbar ist, wenn eine unerwartete
Nicht-Loopback-Publikation auftaucht oder wenn zentrale Caddy-/Tunnel-Marker
fehlen. Der Public-DNS-Exposure-Guard schlaegt fehl, wenn `br.m11h.eu` nicht global
aufloest oder direkt auf die m11h-Origin-IP bzw. Tailscale-IP zeigt. Der
Public-DNS-Multiresolver-Guard fragt zusaetzlich mehrere externe rekursive
Resolver ab und schlaegt fehl, wenn zu wenige Resolver antworten, keine globalen
Records sichtbar sind oder direkte Origin-/Tailscale-Treffer auftauchen. Der
Public-DNS-Authoritative-Guard fragt zusaetzlich die autoritativen Nameserver der
Zone direkt ab und schlaegt fehl, wenn keine autoritative Sicht erreichbar ist,
keine globalen Records sichtbar sind oder direkte Origin-/Tailscale-Treffer
auftauchen. Der Public-DNS-CAA-Guard schlaegt fehl, wenn CAA-Records den aktuellen
Let's-Encrypt-Zertifikatspfad blockieren oder unbekannte kritische CAA-Properties
auftauchen. Der Direct-Origin-Bypass-Guard schlaegt fehl, wenn bekannte IPv4-/IPv6-
Origin- oder Tailscale-IP-Pfade mit `Host: br.m11h.eu` direkt geschuetzte HTTP-
Inhalte ausliefern, einen unerwarteten direkten HTTP-Zugriff erlauben, direkt
gueltig nutzbares HTTPS anbieten oder Host-/Pfad-Konfigurationen mit CR/LF- bzw.
nicht absoluten Pfaden enthalten. Der Direct-Origin-Port-Exposure-Guard schlaegt
fehl, wenn auf den bekannten direkten IPv4-/IPv6-Origin- oder Tailscale-Zielen
unerwartete BR-relevante App-, Proxy-, Datenbank- oder Admin-Ports offen sind;
die Webports `80`/`443` duerfen offen sein und werden inhaltlich separat vom
Bypass-Guard validiert. Der Host-UDP-/QUIC-Exposure-Guard schlaegt fehl, wenn
BR-relevante UDP-Ports wie `443`, `80`, `8000`, `8080`, `18083`, `5432` oder
`2019` direkt auf Origin-/Tailscale-Adressen bzw. Wildcard-Adressen offen sind;
Loopback-only UDP-Listener sind dabei keine direkte Origin-Exposition. Der
Host-Firewall-BR-Ports-Guard schlaegt fehl, wenn lokale Host-Firewall-/NAT-
Metadaten unerwartete direkte INPUT-ACCEPTs oder DNAT-/REDIRECT-Regeln fuer BR-
relevante Ports zeigen; Web-TCP `80`/`443` und die erwartete Loopback-NAT-
Publikation `127.0.0.1:18083` sind erlaubt, Docker-interne Bridge-Regeln werden
nur gezaehlt. Der Host-NFT-BR-Ports-Guard prueft dieselbe Policy zusaetzlich ueber
die native nftables-JSON-Sicht inklusive nativer NAT- und `xt:DNAT`-/`xt:REDIRECT`-
Ausdruecke, einfacher named/anonymous Sets und verfolgt BR-relevante `jump`-/`goto`-Zielketten read-only; nicht
aufloesbare oder zyklische Zielketten sind failend. Der Network-Policy-Consistency-Guard schlaegt fehl, wenn direkte
Origin-/Tailscale-Ziele, Wildcard-Hosts, BR-relevante TCP-/UDP-Ports, erlaubte
Web-TCP-Ports oder die erwartete Loopback-NAT-Regel zwischen den Netzwerkguards
auseinanderlaufen. Der Network-Policy-Runtime-Env-Guard schlaegt fehl, wenn BR-
Netzwerkpolicy-Environment-Variablen in der Guard-Umgebung, in installierten BR-
Units oder unerwarteten Projektquellen gesetzt sind. Der Network-Policy-Runtime-
Summary-Guard schlaegt fehl, wenn aktuelle Summary-Zaehler der Netzwerkguards
nicht zur erwarteten Live-Policy passen, z. B. direkte DNS-Origin-Treffer,
unerwartete direkte Port-/NAT-/UDP-Expositionen, Runtime-Env-Overrides oder
Host-NFT-Runtime-Findings fuer Traversal-/Set-Auswertung. Der Healthcheck schlaegt auch fehl, wenn z. B. `.env`,
`*.pyc`, `__pycache__`, `*.log`, `cloudflared/*.json`, `*credential*` oder
`*token*` im App-Projektbaum auftauchen, wenn externe Images nicht digest-gepinnt sind oder
wenn der Guard-Coverage-Guard eine Drift zwischen Statuscheck, Backup-Preflight,
Projekt-/installierter Healthcheck-Unit oder Readiness-Doku erkennt oder
wenn der Meta-Source-Hardening-Guard unerwartete Aenderungen an Guard-Coverage-,
Readiness-Doku-, Python-/Shell-Syntax-, Systemd-Unit- oder Doku-Source-
Guardquellen erkennt oder
wenn der Doku-Source-Hardening-Guard unerwartete Aenderungen an README-,
Runbook-, systemd-README- oder Readiness-Dokumentation erkennt oder
wenn der Source-Hardening-Coverage-Guard neue oder verschobene `scripts/check-*`-
Hilfen ohne dokumentierte Source-Hardening-Abdeckung erkennt oder
wenn der Summary-Contract-Guard fehlende Statuskey-/Summary-Vertraege in
Guard-Skriptquellen erkennt oder
wenn der Surface-Registry-Guard Abweichungen zwischen zentraler Guard-Registry,
Status-Wrapper, Backup-Preflight oder systemd-Healthcheck-Reihenfolge erkennt oder
wenn der Guard-Registry-Integrity-Guard Duplikate, fehlende Skripte, fehlende
Ausfuehrbarkeit oder Formfehler in der zentralen GuardSpec-Registry erkennt oder
wenn der Protocol-Integrity-Guard fehlende Protokollstruktur, fehlende aktuelle
Guardrail-/Backup-/Restore-/Healthcheck-Marker oder offensichtliche Secret-/
Header-Marker im Projektprotokoll erkennt oder
wenn der Python-Syntax-Guard Syntaxfehler in `app/`, `scripts/` oder `worker/`
findet oder
wenn der Shell-Syntax-Guard Syntaxfehler in Shell-Skripten unter `scripts/`
findet oder
wenn der Systemd-Source-Hardening-Guard unerwartete Service-/Timer-Quellenmarker
oder fehlende Healthcheck-Preflights erkennt oder wenn der Status-Source-
Hardening-Guard unerwartete Aenderungen am zentralen Status-Wrapper, seinen
read-only Defaults, Opt-in-Pfaden oder Guard-Abschnitten erkennt oder wenn der
Healthcheck-Source-Hardening-Guard unerwartete Aenderungen an App-Healthcheck-
Quelle, Summary-/Failure-Markern, read-only DB-/Datei-Pruefungen oder Docker-
Wrapper erkennt oder
wenn der Access-Runtime-Source-Hardening-Guard unerwartete Aenderungen an den
runtime- und zugriffsnahen Guardquellen fuer Header-, Cookie-, TLS- oder
Auth-/CSRF-Negativproben erkennt oder
wenn Runtime-Logs sensible Header-Marker zeigen oder wenn unauthentifizierte
Loopback-Proxy-Antworten nicht mit Basic Auth blocken bzw. zentrale Security-
Header fehlen oder wenn der oeffentliche HTTPS-Pfad nicht durch Cloudflare-
Access-/Challenge-Marker oder den Caddy-Basic-Auth-Pfad geschuetzt ist oder wenn
oeffentliche Cloudflare-Access-Cookies zentrale Sicherheitsattribute verlieren oder wenn
das oeffentliche TLS-Zertifikat nicht gueltig ist, nicht zu `br.m11h.eu` passt,
unerwartete TLS-Versionen nutzt oder zu bald ablaeuft oder wenn interne App-Routen unauthentifiziert nicht wie erwartet
nach `/login` umleiten bzw. Mutationsrouten ohne CSRF nicht mit `403` blockieren
oder unerwartete POST-Erfolge/-Redirects auftreten. Er schlaegt auch fehl, wenn die installierten BR-Wissen-Units nicht mit den Projektquellen synchron sind,
erwartete Timer inaktiv sind oder eine erwartete BR-Wissen-Service-Unit im
systemd-Zustand `failed` haengt. Abgeschlossene oneshot-Services im Zustand
`inactive` sind normal. Import-Pipeline-Guards melden ebenfalls
Auffaelligkeiten. Der Import-Source-Hardening-Guard prueft die Import-Wrapper,
den BAG-Importer und die Import-Service-/Timer-Quellen auf erwartete Fail-Fast-,
Pfad-, Log-, Rechte-, Checksum-, Docker-, BAG-Feed-, Storage- und DB-Marker,
ohne Imports, Docker, `rsync`, Netzwerkzugriffe, `systemctl` oder `sudo`
aufzurufen. Zusaetzlich werden gespeicherte Antworten und Exporte auf
erwartete Integritaets- und Leak-Schutzmarker geprueft. Das Container-Image-
Inventar und die Image-Pinning-Readiness sind read-only statusbewertet:
`ok` bedeutet vorhandene Referenzen ohne tag-only-/`latest`-/unversionierte Image-
oder Pinning-Kandidaten und ohne Remote-Ausfaelle; `warning` zeigt offene
Kandidaten oder Remote-Ausfaelle; `failed` zeigt eine leere Image-/Referenzbasis.
Die normale Statusausgabe nutzt fuer die Image-Pinning-Readiness die lokale
`--no-remote`-Variante, damit externe Registry-Ausfaelle den Standardstatus nicht
verfaelschen; der remote-aktivierte Check bleibt ein expliziter Opt-in ueber
`status-br-wissen.sh --image-pinning`. Dessen Summary nennt bei Remote-Warnungen
`remote_expected`, `remote_coverage_pct` und digest-gekuerzte
`remote_unavailable_refs`, ohne Registry-Antwortinhalte auszugeben.
Citation-/Export-Safety sowie der Audit-Trail auf bekannte Aktionsklassen und
neue Abdeckungsluecken geprueft. Abschliessend wird die DB-Struktur inklusive
Extension, Tabellen, Spalten und Betriebsindexes validiert. Der Data-Integrity-
Source-Hardening-Guard prueft die Quellen dieser Antwort-/Export-, Audit- und
DB-Schema-Guards statisch auf erwartete metadata-only-, Legacy-, Manifest-,
Index-, Summary- und Verbotsmarker, ohne Docker, DB-Abfragen, Backups, Restores,
Imports oder Regressionen aufzurufen. Der
Backup-Scope-Guard prueft zusaetzlich metadata-only, ob der neueste BR-Wissen-
Restic-Snapshot den erwarteten Host, die erwarteten Tags und den erwarteten
Backup-Pfadumfang fuer App, internen Datenbereich und Projektprotokoll enthaelt,
ohne Backups, Restores, Docker, `systemctl`, Imports, Regressionen oder DB-
Abfragen auszufuehren. Der Backup-Runtime-Policy-Guard prueft zusaetzlich
metadata-only Backup-Env-Datei, Backup-Env-Elternverzeichnis, Restic-Binary und
installierte Backup-Service-Policy, ohne Backup-Env-Inhalte oder Secretwerte zu
lesen und ohne Backups, Restores, Docker, Imports, Regressionen oder DB-Abfragen
auszufuehren. Der Backup-Freshness-Guard prueft zusaetzlich, ob lokale
Dumps/Logs und der neueste Restic-Snapshot aktuell und konsistent sind. Er
validiert ausserdem nachgelagert, dass der neueste Restic-Snapshot den aktuellen
Projektprotokollstand abdeckt (`protocol_snapshot_current=1`), bewusst nicht als
Backup-Preflight. Fuer root-noetige Scans und Restic-Metadaten nutzt der Guard
kuratierte absolute Helferpfade (`/usr/bin/sudo`, `/usr/bin/test`,
`/usr/bin/bash`, einen kuratierten Python-Interpreter sowie `/usr/bin/restic`
oder `/usr/local/bin/restic`) und weist sie in der Summary als
`helper_binaries=<n>`, `python_binary=<pfad>` und `restic_binary=<pfad>` aus.
Ein expliziter `restic check` bleibt bewusst ein manueller bzw.
periodischer Wartungscheck und ist nicht als schwerer ExecStartPre eingebunden,
weil er einen exklusiven Repository-Lock nimmt; letzter dokumentierter Lauf:
`2026-06-06T06:25:14Z`, 48 Snapshots, `no errors were found`. Der leichte
`check-restic-repository-check.py --summary`-Guard startet keinen `restic check`,
nimmt keinen Repository-Lock und prueft nur, ob dieser Nachweis im
Readiness-Dossier frisch und erfolgreich dokumentiert ist. Seine Summary meldet
`restic_repository_check_status=ok`, `documented_success=1` und
`lock_preflight=0`. Der Backup-Source-Hardening-Guard
prueft zusaetzlich die Backup-Wrapper-Quelle auf erwartete Fail-Fast-,
Preflight-, Dump-, kuratierte absolute `RESTIC_BIN`-Auswahl, Restic-, Rechte- und
Retention-Marker, ohne Backups, Restic, Docker oder `systemctl` aufzurufen. Der
Backup-Wrapper nutzt fuer `backup` und `forget` nur `/usr/bin/restic` oder
`/usr/local/bin/restic` und protokolliert `restic_bin=<pfad>`. Der Restore-Source-Hardening-Guard prueft
die Restore-Smoke-Quellen auf erwartete Zielpfad-, Rechte-, Storage-Preflight-,
Restic-Restore-, isolierte DB-Restore-, Cleanup- und Retention-Marker, ohne
Restore, Restic, Docker, `sudo` oder `systemctl` aufzurufen. Der Restore-Runtime-Policy-Guard
prueft metadata-only Restore-Smoke-Service-/Timer-Policy, Restore-
Skriptmodi, Restic-/Docker-Binaries, Backup-Env-Rechte und `/tmp`-Policy, ohne
Restore, Docker, Backups, Imports, Regressionen oder DB-Abfragen auszufuehren. Der
Storage-/Permission-Guard prueft
abschliessend nur Metadaten zu Storage-, Secret-, Dump-, Log- und Exportrechten;
Secret-, Dump- oder Log-Inhalte werden dabei nicht ausgegeben. Der
Storage-/Capacity-Guard prueft freie Bytes, Inodes, `/tmp`, Docker-Root und eine
kompakte Docker-DF-Summary. Der Restore-Freshness-Guard prueft zusaetzlich, ob
der letzte automatisierte Restore-Smoke inklusive isoliertem DB-Restore aktuell,
erfolgreich und artefaktfrei war; bei `snapshot=latest` erwartet er zudem die
konkret aufgeloeste Restic-Snapshot-ID `restore_resolved_snapshot=<id>` im
metadata-only Restore-Smoke-Log und gleicht diese Snapshot-ID metadata-only gegen
Restic-Tags und die erwarteten Backup-Pfade ab. Die Summary meldet dafuer
`restore_resolved_snapshot_present=<0|1>` und
`restore_resolved_snapshot_paths=<n>`. Die Restic-Metadatenabfrage nutzt dabei
nur kuratierte absolute Restic-Pfade (`/usr/bin/restic` oder
`/usr/local/bin/restic`) statt eines unqualifizierten Root-`PATH`; auch
`/usr/bin/sudo`, `/usr/bin/test`, `/usr/bin/bash` und fuer den root-noetigen
JSON-Scan ein kuratierter absoluter Python-Interpreter werden absolut referenziert
und metadata-only auf Datei-/Owner-/Mode-/Symlink-Policy geprueft. Aktuell wird
`/usr/bin/python3.13` gewaehlt; Symlinks wie `/usr/bin/python3` werden nicht
akzeptiert. Die Summary
meldet diese Policy als `helper_binaries=<n>` und den aktuell ausgewaehlten
Python-Pfad als `python_binary=<pfad>`. Zusaetzlich prueft der Guard das
eigene Skript metadata-only auf Symlink-Freiheit, regulaere Datei,
nicht gruppen-/world-writable, Ausfuehrbarkeit und Mindestgroesse; die Summary
meldet dies als `self_script_policy=<0|1>`. Ergaenzend prueft der Guard die
projektbezogenen Parent-Verzeichnisse `/home/chris/web/br.m11h.eu` und
`/home/chris/web/br.m11h.eu/scripts` metadata-only auf Symlink-Freiheit,
Verzeichnistyp, Owner-/Group-Konsistenz zum Skript, nicht gruppen-/world-writable
und Suchbarkeit; die Summary meldet dies als `self_parent_policy=<0|1>`. Der Readiness-Doku-Guard prueft abschliessend,
ob das Readiness-Dossier einen aktuellen Stand-Zeitstempel, zentrale statische
Guard-/Backup-/Restore-Marker sowie kompakte Backup-/Restore-Evidenzwerte
enthaelt, ohne taeglich wechselnde Snapshot-IDs als exakten Dossierinhalt zu
erzwingen. Der Backup-Freshness-Guard bleibt dabei bewusst ausserhalb des
Readiness-Guards, damit frische Doku- oder Protokollnachtraege das naechste
Backup nicht zirkulaer blockieren. Der Regression-Freshness-
Guard prueft die zuletzt vorhandenen Kern-Regressionsantworten und deren Export-
und Citation-Abdeckung, ohne neue Antworten zu erzeugen. Der Regression-Source-
Hardening-Guard prueft zusaetzlich die Regressionsrunner-/Wrapper- und Freshness-
Quellen auf erwartete Kernfall-, Citation-, Export-, Manifest-, Storage- und
Summary-Marker, ohne Regressionen, Docker oder DB-Abfragen auszufuehren.
Die Healthcheck-Unit enthaelt fuer den leichten Restic-Repository-Check-Nachweis
den Preflight
`ExecStartPre=/home/chris/web/br.m11h.eu/scripts/check-restic-repository-check.py --summary`.
Der Freshness-Source-Hardening-Guard prueft die Backup-/Restore-Freshness-
Quellen auf erwartete metadata-only Log-/Dump-/Restic-/Restore-Smoke-/Summary-
Marker, ohne Freshness-Checks, `sudo`, Restic, Docker oder DB-Abfragen
auszufuehren.
Der Storage-Source-Hardening-Guard prueft die Storage-Permission-/Capacity-
Quellen auf erwartete metadata-only Rechte-, Secret-Kandidaten-, Dump-/Log-Mode-,
Filesystem-, Inode- und Docker-Kapazitaetsmarker, ohne Storage-Checks, `sudo`,
Docker oder DB-Abfragen auszufuehren.
Der Meta-Source-Hardening-Guard prueft die Meta-/Governance-Guardquellen fuer
Guard-Coverage, Readiness-Doku, Python-/Shell-Syntax, Systemd-Unit-Sync und
Doku-Source-Hardening auf erwartete Verdrahtungs-, Readiness-, Syntax-,
Unit-Sync-, Dokumentations-, Summary- und Verbotsmarker, ohne die geprueften
Meta-Guards, `systemctl`, Docker, Backups, Restores, Imports, Regressionen oder
DB-Abfragen auszufuehren. Der Doku-Source-Hardening-Guard prueft die
Dokumentationsquellen README, Runbook, systemd-README und Readiness-Dossier auf
erwartete Betriebs-, Guardrail-, Backup-/Restore-, Healthcheck- und Keine-Secrets-
Marker, ohne Statuschecks, Docker, `systemctl`, Backups, Restores, Imports,
Regressionen oder DB-Abfragen auszufuehren. Der Source-Hardening-Coverage-Guard
prueft das `scripts/check-*`-Inventar auf vollstaendige Zuordnung zu Source-
Hardening-Gruppen, Governance-Schichten oder expliziten Legacy-/Hilfs-Ausnahmen,
ohne Guards oder Runtime-Kommandos auszufuehren. Der Summary-Contract-Guard
prueft die `GuardSpec`-Statuskeys und `--summary`-Vertraege in den Guard-
Skriptquellen, ohne die Guards auszufuehren. Der Surface-Registry-Guard prueft,
dass Status-Wrapper, Backup-Preflight und Healthcheck die zentrale Guard-Registry
in Reihenfolge und ohne verdeckte Extra-/Missing-Check-Aufrufe spiegeln, ohne
Guards oder Runtime-Kommandos auszufuehren. Der Guard-Registry-Integrity-Guard
prueft die zentrale GuardSpec-Registry selbst auf Duplikate, fehlende oder nicht
ausfuehrbare Skripte, Statuskey-/Backup-Label-Formen und Argumentvertraege, ohne
Guards oder Runtime-Kommandos auszufuehren. Der Protocol-Integrity-Guard prueft
das Projektprotokoll und dessen Backup-Einbindung auf Struktur-, Guardrail-,
Backup-/Restore-/Healthcheck- und Keine-Secrets-Marker, ohne Guards oder Runtime-
Kommandos auszufuehren. Der Git-Remote-Readiness-Guard prueft Branch `main`,
Remote `git@github.com:scheffe2804/scheffe2804-br.m11h.eu.git`, Tracking auf
`origin/main`, Remote-HEAD-Abgleich und Index-Schutz gegen typische Secret-/Dump-
Artefakte; erwarteter Marker ist `git_remote_readiness_status=ok` fuer das
GitHub-Repo `scheffe2804/scheffe2804-br.m11h.eu`; im Root-Backup-Kontext zeigt
die Summary den genutzten Projektbesitzer als `git_user=`.
Der Container-Source-Hardening-Guard prueft die Container-/Image-Guardquellen auf
metadata-only Docker-Inspect-, Compose-Image-, Dockerfile-`FROM`-, Digest-Pinning-
und Readiness-Summary-Marker, ohne Docker, Compose oder Registry-Lookups
auszufuehren.
Der Core-Source-Hardening-Guard prueft die Basis-Guardquellen auf metadata-only
Host-, Zeit-/NTP-, Compose-Service-, Privilege-Policy-, Artefakt- und Runtime-Log-Marker, ohne die
geprueften Guards oder deren Docker-/Host-Kommandos auszufuehren.

## Installation/Synchronisation nach Aenderungen

```bash
sudo cp /home/chris/web/br.m11h.eu/systemd/br-wissen-healthcheck.* /etc/systemd/system/
sudo cp /home/chris/web/br.m11h.eu/systemd/br-wissen-import-m00h.* /etc/systemd/system/
sudo cp /home/chris/web/br.m11h.eu/systemd/br-wissen-import-bag.* /etc/systemd/system/
sudo cp /home/chris/web/br.m11h.eu/systemd/br-wissen-backup.* /etc/systemd/system/
sudo cp /home/chris/web/br.m11h.eu/systemd/br-wissen-restore-smoke.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now br-wissen-healthcheck.timer
sudo systemctl enable --now br-wissen-import-m00h.timer
sudo systemctl enable --now br-wissen-import-bag.timer
sudo systemctl enable --now br-wissen-backup.timer
sudo systemctl enable --now br-wissen-restore-smoke.timer
```

Vor Aktivierung prüfen:

- SSH-Alias `m00h` funktioniert für User `chris`.
- Importlog unter `/srv/br-wissensdatenbank/logs` wird geschrieben.
- Neue Quellen bleiben `importiert`/`ungeprüft` und werden nicht automatisch freigegeben.
- Backup-Konfiguration unter `/etc/web-backup/` ist vorhanden; Secrets niemals ausgeben oder protokollieren.
