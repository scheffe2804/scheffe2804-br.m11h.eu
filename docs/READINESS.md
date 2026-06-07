# BR-Wissen Readiness-Dossier

Stand: 2026-06-07T12:34:15Z

Dieses Dossier fasst den aktuellen Betriebs-, Sicherheits-, Backup-, Restore- und
Regressionstand fuer `br.m11h.eu` zusammen. Es enthaelt bewusst keine Secretwerte,
Credential-Inhalte, Passwoerter, Tokens oder Dump-Inhalte.

## Betriebsbasis

- Host: `m11h.eu`.
- Hostrolle: `m11h`.
- App/Compose/Code: `/home/chris/web/br.m11h.eu`.
- Sensible Quellen, Texte, Exporte, Dumps und Logs: geschuetzter interner
  Datenbereich unter `/srv/br-wissensdatenbank`.
- Projektprotokoll: `/home/chris/web/diverses/betriebsrat.md`.
- GitHub-Repo: `scheffe2804/scheffe2804-br.m11h.eu`.
- Nachvollziehbarkeit laeuft ueber GitHub-Remote `origin`, Projektprotokoll und
  verschluesselte Backups; Secret-, Dump-, Credential-, Backup- und Runtime-
  Artefakte duerfen nicht versioniert werden.

## Laufender Stack

Aktueller Status laut `scripts/status-br-wissen.sh` vom
2026-06-07:

- `br-wissen-app`: up/healthy.
- `br-wissen-db`: up/healthy.
- `br-wissen-worker`: up.
- `br-wissen-proxy`: up.
- `br-wissen-cloudflared`: up.

Aktive Timer:

- `br-wissen-healthcheck.timer`.
- `br-wissen-import-m00h.timer`.
- `br-wissen-import-bag.timer`.
- `br-wissen-backup.timer`.
- `br-wissen-restore-smoke.timer`.

## Aktueller Healthcheck-Stand

- `health_status=ok`.
- `failures=0`.
- `sources=300`.
- `documents=300`.
- `chunks=15747`.
- `queries=8`.
- `answers=64`.
- `exports_html=55`.
- `exports_pdf=55`.
- `approved_chunkless_sources=0`.
- `repaired_ocr_documents=52`.
- `repaired_ocr_without_chunks=0`.
- `repaired_ocr_missing_text_paths=0`.
- `duplicate_document_sha_groups=7`.
- Quellenintegritaet: keine ungueltigen Status-/Klassenwerte, keine fehlenden
  lokalen Quellen-/Dokumentenpfade, keine Pfade ausserhalb des Storage-Roots,
  keine fehlenden Source-/Document-SHA256-Werte, keine Chunk-Klassen-Mismatches
  und keine neuen GELB-Zitationen in Antworten der letzten 30 Tage.

## Sicherheits- und Guardrail-Stand

Aktive Schutzschichten:

1. Cloudflare Tunnel / Access.
2. Caddy Basic Auth.
3. App-Login.
4. Secure/HttpOnly/SameSite-Strict Session-Cookie.
5. CSRF-Defense-in-Depth fuer geschuetzte POST-/Mutationsrouten.
6. Noindex-/Noarchive-/NoStore-Header.
7. Content-Security-Policy, Permissions-Policy, COOP und CORP.
8. Caddy-Logfilter fuer sensible Request-Header.
9. Host-Kontext-Guard fuer den erwarteten `m11h`-Zielhost vor Status-,
   Healthcheck- und Backup-Laeufen.
10. Time-Sync-Guard fuer NTP-/chrony-Metadaten, die TLS- und Freshness-Checks
    absichern.
11. Compose-Service-Guard fuer erwartete laufende Compose-Services und
    Healthstatus von `app`/`db`.
12. Privilege-Policy-Guard fuer die read-only Sichtbarkeit der effektiven
    sudo-Policy von `chris` als aggregierte Zaehler ohne Ausgabe von sudoers-
    Inhalten oder konkreten Kommandolisten.
13. Privilege-Risk-Review-Guard fuer den read-only Nachweis, dass `broad_sudo=1`
    bewusst akzeptiert, als Least-Privilege-Folgeauftrag dokumentiert und nicht
    automatisch per sudoers-Aenderung behandelt wird.
14. Privilege-Least-Privilege-Plan-Guard fuer den read-only Nachweis eines
    konkreten, faelligen und rollback-/lockout-abgesicherten Least-Privilege-
    Folgeplans ohne automatische sudoers-Aenderung.
15. Privilege-Remediation-Gate-Guard fuer den read-only Nachweis, dass der
    aktuelle accepted-risk-/planned-Stand bei `remediation_allowed=0` und
    `actual_sudoers_change_allowed=0` nicht als echte sudoers-Remediation gilt.
16. Privilege-No-Sudoers-Change-Guard fuer den read-only Nachweis, dass in diesem
    Arbeitsstrang keine sudoers-Aenderungen gewuenscht oder erlaubt sind
    (`sudoers_changes_allowed=0`).
17. Core-Source-Hardening-Guard fuer die read-only Quellenpruefung der
    Host-Kontext-, Time-Sync-, Compose-Service-, Privilege-Policy-,
    Privilege-Risk-Review-, Privilege-Least-Privilege-Plan-,
    Privilege-Remediation-Gate-,
    Privilege-No-Sudoers-Change-,
    Projektartefakt- und Runtime-Log-Marker-Guards inklusive metadata-only-,
    Summary- und Verbotsmarkern.
14. Container-Hardening-Guard fuer Docker-Metadaten wie Privileged, Capabilities,
    Devices, Namespaces, Netzwerke, Port-Bindings und Mount-Modi.
14. Container-Source-Hardening-Guard fuer die read-only Quellenpruefung der
    Container-/Image-Guards inklusive Docker-Inspect-, Compose-Image-,
    Dockerfile-`FROM`-, Digest-Pinning-, lokale-Build-Ausnahme-, Readiness- und
    Summary-Marker.
15. Compose-Source-Hardening-Guard fuer statische, wertfreie Pruefung der
    Compose-Quelle ohne `docker compose config` und ohne Env-Wert-Expansion.
15a. Network-Source-Hardening-Guard fuer die read-only Quellenpruefung der
    Netzwerk-/Exposure-Guards inklusive DNS-, Direct-Origin-, UDP-, Firewall-/nft-
    und Network-Policy-Marker.
14. Network-Exposure-Guard fuer Loopback-only-Proxy, Caddy-/Tunnel-Marker und
    unerwartete Nicht-Loopback-Publikationen.
15. Public-DNS-Exposure-Guard gegen direkte Origin-IP-Exposition im oeffentlichen
    DNS ueber lokale Resolver.
16. Public-DNS-Multiresolver-Guard gegen direkte Origin-IP-Exposition aus
    mehreren externen Resolver-Perspektiven.
17. Public-DNS-Authoritative-Guard gegen direkte Origin-IP-Exposition aus
    autoritativer Nameserver-Sicht.
18. Public-DNS-CAA-Guard fuer CAA-/CA-Ausstellungspfad-Metadaten.
19. Direct-Origin-Bypass-Guard gegen direkte IPv4-/IPv6-Origin- und Tailscale-IP-
    Zugriffe mit `Host: br.m11h.eu` ohne Cloudflare Access.
20. Direct-Origin-Port-Exposure-Guard gegen unerwartete direkte BR-relevante App-,
    Proxy-, Datenbank- oder Admin-Port-Expositionen auf Origin-/Tailscale-Zielen.
21. Host-UDP-/QUIC-Exposure-Guard gegen unerwartete direkte BR-relevante UDP-
    Expositionen, insbesondere UDP/443 QUIC, auf Origin-/Tailscale-Adressen.
22. Host-Firewall-BR-Ports-Guard gegen unerwartete lokale Host-Firewall-/NAT-
    Expositionen BR-relevanter TCP-/UDP-Ports.
23. Host-NFT-BR-Ports-Guard gegen unerwartete lokale nftables-Regeln fuer BR-
    relevante TCP-/UDP-Ports.
24. Network-Policy-Consistency-Guard gegen Drift zwischen Direct-Origin-, Host-
    UDP-, Host-Firewall- und Host-NFT-Port-/Host-Policies.
25. Network-Policy-Runtime-Env-Guard gegen unbemerkte BR-Netzwerkpolicy-
    Environment-Overrides in Guard-Laufzeit, systemd-Units oder Projektquellen.
26. Network-Policy-Runtime-Summary-Guard gegen Drift in aktuellen Summary-
    Zaehlern der Netzwerk-/Exposure-Guards.
27. Runtime-HTTP-Security-Guard fuer unauthentifizierte Basic-Auth-Sperre und
    Security-Header auf Loopback-Proxy-Antworten.
28. External-Access-Surface-Guard fuer den oeffentlichen HTTPS-Pfad mit
    Cloudflare-Access-/Challenge-Markern oder Caddy-Basic-Auth-Fallback.
29. External-Cookie-Security-Guard fuer Attribute oeffentlicher Cloudflare-
    Access-Cookies ohne Wertausgabe.
30. TLS-Certificate-Guard fuer oeffentliche Zertifikats-/TLS-Metadaten von
    `br.m11h.eu:443`.
31. App-Auth-Surface-Guard fuer interne App-Redirects und CSRF-Sperren ohne
    Zugangsdaten.
32. Runtime-Log-Marker-Guard.
33. Projektartefakt-/Secret-Guard.
34. Image-Pinning-Guard fuer externe Digest-Pins und lokale Build-Ausnahmen.
35. Systemd-Unit-Guard fuer Unit-Sync, aktive Timer, fehlgeschlagene
    BR-Wissen-Service-Units, metadata-only Unit-Datei-Policy
    (`unit_policy_failures=0`) und Parent-Directory-Policy
    (`parent_policy_failures=0`) sowie Linux-Dateiattribut-Policy
    (`attr_policy_failures=0`).
36. Systemd-Source-Hardening-Guard fuer erwartete Service-/Timer-Quellenmarker,
    User, WorkingDirectory, ExecStart-/Preflight- und Timer-Policy.
37. Status-Source-Hardening-Guard fuer die read-only Quellenpruefung des
    zentralen Status-Wrappers inklusive read-only Defaults, expliziter Opt-ins,
    Guard-Abschnitte und Summary-Aufrufe.
38. Healthcheck-Source-Hardening-Guard fuer die read-only Quellenpruefung des
    App-Healthchecks und dessen Docker-Wrapper inklusive Summary-, Failure-,
    DB-/Datei-Integritaets- und Wrapper-Markern.
39. Python-Syntax-Guard fuer cache-freie AST-Pruefung der Python-Dateien in
    `app/`, `scripts/` und `worker/`.
40. Shell-Syntax-Guard fuer `bash -n`-Pruefung der Shell-Skripte in `scripts/`.
41. Guard-Coverage-Guard fuer die konsistente Verdrahtung der Guard-Skripte in
    Statuscheck, Backup-Preflight, systemd-Healthcheck und Readiness-Doku.
42. Meta-Source-Hardening-Guard fuer die read-only Quellenpruefung der
    Meta-/Governance-Guards inklusive Guard-Coverage-, Readiness-Doku-, Python-/
    Shell-Syntax-, Systemd-Unit- und Doku-Source-Guardquellen.
42a. Doku-Source-Hardening-Guard fuer die read-only Quellenpruefung der Dokumentationsquellen
    README, Runbook, systemd-README und Readiness-Dossier inklusive Betriebs-,
    Guardrail-, Backup-/Restore-, Healthcheck- und Keine-Secrets-Markern.
42b. Source-Hardening-Coverage-Guard fuer die read-only Inventarpruefung aller
    `scripts/check-*`-Hilfen gegen dokumentierte Source-Hardening-Gruppen,
    Governance-Schichten und explizite Legacy-/Hilfs-Ausnahmen.
42c. Summary-Contract-Guard fuer die read-only Quellenpruefung der in
     `check-guard-coverage.py` deklarierten Statuskey- und `--summary`-Vertraege.
42d. Surface-Registry-Guard fuer die read-only Registry-/Oberflaechenpruefung,
     dass Status-Wrapper, Backup-Preflight und systemd-Healthcheck die zentrale
     GuardSpec-Liste in Reihenfolge und ohne verdeckte Extra-/Missing-Checks
     spiegeln.
42e. Guard-Registry-Integrity fuer die read-only Integritaetspruefung der
     zentralen GuardSpec-Registry auf Duplikate, fehlende/nicht ausfuehrbare
     Check-Skripte, Statuskey-/Backup-Label-Formen und Argumentvertraege.
42f. Protocol-Integrity-Guard fuer die read-only Pruefung des Projektprotokolls
     `/home/chris/web/diverses/betriebsrat.md` auf Struktur, aktuelle Guardrail-,
     Backup-/Restore-/Healthcheck-Marker, Restic-Einbindung und offensichtliche
     Keine-Secrets-/Credential-Marker.
42g. Git-Remote-Readiness fuer die read-only Pruefung von Branch `main`, GitHub-
     Remote `git@github.com:scheffe2804/scheffe2804-br.m11h.eu.git`, Tracking auf
     `origin/main`, Remote-HEAD-Abgleich und Git-Index-Schutz gegen typische
     Secret-/Dump-/Credential-/Backup-/Runtime-Artefakte; im Root-Backup-Kontext
     werden Git-Metadaten als Projektbesitzer gelesen (`git_user=`).
42h. Backup-Scope-Guard fuer die read-only Restic-Snapshot-Metadatenpruefung des
     neuesten BR-Wissen-Backups auf erwarteten Host, erwartete Tags und erwarteten
     Backup-Pfadumfang fuer App, internen Datenbereich und Projektprotokoll.
42h. Backup-Runtime-Policy-Guard fuer die read-only Metadatenpruefung von
     Backup-Env-Datei, Backup-Env-Elternverzeichnis, Restic-Binary und
     installierter Backup-Service-Policy ohne Ausgabe von Secret- oder Env-Werten.
42i. Restore-Runtime-Policy-Guard fuer die read-only Metadatenpruefung von
     Restore-Smoke-Service-/Timer-Policy, Restore-Skripten, Restic-/Docker-
     Binaries, Backup-Env-Rechten und `/tmp`-Policy ohne Restore-Ausfuehrung.
43. Access-Runtime-Source-Hardening-Guard fuer die read-only Quellenpruefung
     der Runtime-HTTP-, External-Access-, External-Cookie-, TLS- und
     App-Auth-Surface-Guards inklusive unauthentifizierter metadata-only
    Header-/Cookie-/TLS-/CSRF-Negativprobe-Marker.
44. Import-Pipeline-Guard fuer Importtimer, Importlog-Alter/-Marker und
    Quellen-/Dokumenten-/Chunk-Invarianten.
45. Import-Source-Hardening-Guard fuer die read-only Quellenpruefung der
    m00h-/BAG-Import-Skripte und Import-Service-/Timer-Quellen inklusive
    Fail-Fast-, Pfad-, Log-, Rechte-, Checksum-, Docker-, BAG-Feed-, Storage- und
    DB-Markern.
46. Antwort-/Export-Safety-Guard fuer Citation-Abdeckung, Exportmarker,
    Pfadleak-/Secretmarker, Exportdatei-Plausibilitaet und technische
    Export-Manifeste.
47. Audit-Trail-Guard fuer bekannte Audit-Aktionsklassen, Pflichtfelder,
    Antwort-/Export-Abdeckung und dokumentierte Legacy-Ausnahmen.
48. DB-Schema-Guard fuer Extension, Tabellen, Spalten und Betriebsindexes.
49. Data-Integrity-Source-Hardening-Guard fuer die read-only Quellenpruefung der
    Antwort-/Export-Safety-, Audit-Trail- und DB-Schema-Guards inklusive
    metadata-only-, Legacy-, Manifest-, Index-, Summary- und Verbotsmarkern.
50. Backup-Source-Hardening-Guard fuer die read-only Quellenpruefung des
     Backup-Wrappers inklusive Fail-Fast-, Preflight-, Dump-, Restic-, Rechte-
     und Retention-Markern.
50a. Restic-Repository-Check-Freshness-Guard fuer den read-only Nachweis, dass
     ein frischer erfolgreicher expliziter `restic check` im Dossier dokumentiert
     ist, ohne selbst `restic check` zu starten oder einen Repository-Lock zu
     nehmen.
51. Restore-Source-Hardening-Guard fuer die read-only Quellenpruefung der
     Restore-Smoke-Skripte inklusive Zielpfad-, Rechte-, Restic-Restore-,
     isolierter DB-Restore-, Cleanup- und Retention-Marker.
52. Freshness-Source-Hardening-Guard fuer die read-only Quellenpruefung der
     Backup- und Restore-Freshness-Guards inklusive metadata-only Log-/Dump-,
     sudo-JSON-, Retention-, Age-, Rechte-, Restic-, Restore-Smoke- und Summary-
     Markern.
53. Storage-Source-Hardening-Guard fuer die read-only Quellenpruefung der
     Storage-Permission- und Storage-Capacity-Guards inklusive metadata-only
     Rechte-, Symlink-, Secret-Kandidaten-, Dump-/Log-Mode-, Filesystem-, Inode-
     und Docker-Kapazitaetsmarkern.
54. Automatisierter Restore-Smoke-Drill fuer Restic-Dateirestore und optionalen
     isolierten DB-Restore.
55. Backup-Freshness-Guard fuer lokale Dump-/Log-Retention und neuesten
     Restic-Snapshot.
56. Storage-/Permission-Guard fuer Metadatenpruefung von Storage-, Secret-,
     Dump-, Log- und Exportrechten.
57. Restore-Freshness-Guard fuer den letzten automatisierten Restore-Smoke-Drill
     inklusive isoliertem DB-Restore.
58. Storage-/Capacity-Guard fuer freie Bytes, Inodes, `/tmp`, Docker-Root und
     Docker-System-DF-Metadaten.
59. Readiness-Doku-Guard fuer Stand-Zeitstempel, statische Guard-Marker,
     nicht-zirkulaere Backup-/Restore-Evidenzwerte und Protokollnachtrag des
     Readiness-Dossiers.
60. Regression-Freshness-Guard fuer die zuletzt vorhandenen Kern-Regressionsantworten
     und deren Export-/Citation-/Quellenabdeckung.
61. Regression-Source-Hardening-Guard fuer die read-only Quellenpruefung von
     Regressionsrunner, Docker-Wrapper und Regression-Freshness-Guard inklusive
     Kernfall-, Citation-, Export-, Manifest-, Storage- und Summary-Markern.
62. Backup-Preflight-Kette inklusive Host-Kontext-Guard, Time-Sync-Guard, Compose-Service-Guard,
    Privilege-Policy-Guard, Privilege-Risk-Review-Guard, Core-Source-Hardening-Guard, Container-Hardening-Guard, Container-Source-Hardening-Guard, Compose-Source-Hardening-Guard, Network-Source-Hardening-Guard, Network-Exposure-Guard, Public-DNS-Exposure-Guard, Public-DNS-Multiresolver-Guard, Public-DNS-Authoritative-Guard, Public-DNS-CAA-Guard, Direct-Origin-Bypass-Guard, Direct-Origin-Port-Exposure-Guard, Host-UDP-Exposure-Guard, Host-Firewall-BR-Ports-Guard, Host-NFT-BR-Ports-Guard, Network-Policy-Consistency-Guard, Network-Policy-Runtime-Env-Guard, Network-Policy-Runtime-Summary-Guard, Access-Runtime-Source-Hardening-Guard, Runtime-HTTP-Security-Guard, External-Access-Surface-Guard, External-Cookie-Security-Guard, TLS-Certificate-Guard, App-Auth-Surface-Guard, Import-Source-Hardening-Guard, Data-Integrity-Source-Hardening-Guard, Systemd-Source-Hardening-Guard, Status-Source-Hardening-Guard, Healthcheck-Source-Hardening-Guard, Backup-Source-Hardening-Guard, Restore-Source-Hardening-Guard, Freshness-Source-Hardening-Guard, Storage-Source-Hardening-Guard, Python-Syntax-Guard, Shell-Syntax-Guard, Guard-Coverage-Guard, Meta-Source-Hardening-Guard, Doku-Source-Hardening-Guard, Source-Hardening-Coverage-Guard, Summary-Contract-Guard, Readiness-Doku-Guard, Regression-Freshness-Guard und
     Regression-Source-Hardening-Guard.
63. Projektprotokoll `/home/chris/web/diverses/betriebsrat.md` als eigener
     Restic-Backup-Pfad mit Restore-Smoke-Pruefung.

Aktueller Guard-Stand laut read-only Status-/Summary-Pruefungen vom 2026-06-06:

- Projektartefakte: `artifact_status=ok checks=8 findings=0`.
- Host-Kontext-Guard: `host_context_status=ok checks=8 findings=0 hostname=m11h.eu host_role=m11h this_server=m11h public_ipv4=31.70.74.139 tailscale_ipv4=100.102.205.121`.
- Time-Sync-Guard: `time_sync_status=ok checks=8 findings=0 ntp=1 system_clock=-1 timezone=Europe/Berlin chrony_stratum=3 system_offset_s=0.000063 rms_offset_s=0.000075 leap_normal=1`.
- Compose-Service-Guard: `compose_service_status=ok checks=9 findings=0 expected=5 running=5 health_required=2 healthy=2 unexpected=0`.
- Privilege-Policy-Guard: `privilege_policy_status=ok checks=5 findings=0 target_user=chris command_entries=2 nopasswd_entries=1 password_entries=1 nopasswd_all=1 unrestricted_all=1 broad_sudo=1`.
- Privilege-Risk-Review-Guard: `privilege_risk_review_status=accepted_risk checks=30 findings=0 target_user=chris critical_privilege_risk=1 broad_sudo=1 nopasswd_all=1 unrestricted_all=1 acceptance=1 least_privilege_followup=1 review_doc=1 review_cadence=monthly review_overdue=0`.
- Privilege-Least-Privilege-Plan-Guard: `privilege_least_privilege_plan_status=planned checks=37 findings=0 target_user=chris plan_ready=1 remediation_complete=0 due_overdue=0 days_until_due=30 lockout_protection=1 rollback_plan=1 command_inventory=1 staged_rollout=1`.
- Privilege-Remediation-Gate-Guard: `privilege_remediation_gate_status=closed checks=43 findings=0 target_user=chris remediation_allowed=0 actual_sudoers_change_allowed=0 remediation_complete=0 accepted_risk_visible=1 critical_privilege_risk=1 broad_sudo=1 plan_status=planned gate_doc=1`.
- Privilege-No-Sudoers-Change-Guard: `privilege_no_sudoers_change_status=active checks=36 findings=0 target_user=chris sudoers_changes_allowed=0 sudoers_remediation_requested=0 actual_sudoers_change_allowed=0 remediation_complete=0 accepted_risk_continues=1 critical_privilege_risk=1 broad_sudo=1 gate_status=closed policy_doc=1`.
- Core-Source-Hardening: `core_source_hardening_status=ok`.
- Container-Hardening: `container_hardening_status=ok checks=108 findings=0 containers=5 privileged=0 cap_add=0 cap_drop_all=4 cap_drop_exceptions=1 expected_users=5 tmpfs_services=5 tmpfs_paths=12 devices=0 host_namespaces=0 unexpected_networks=0 unexpected_port_bindings=0 required_ro_mounts=6 writable_required_mounts=3 readonly_rootfs=5 writable_rootfs=0 apparmor_default=5 no_new_privileges=5 resource_limited=5`.
- Container-Source-Hardening: `container_source_hardening_status=ok`.
- Compose-Source-Hardening: `compose_source_hardening_status=ok checks=83 findings=0 services=5 read_only=5 no_new_privileges=5 cap_drop_all=4 resource_limited=5 tmpfs_services=5 tmpfs_paths=12 expected_port_bindings=1 unexpected_port_bindings=0 expected_ro_volumes=6 writable_required_volumes=3`.
- Network-Source-Hardening: `network_source_hardening_status=ok`.
- Network-Exposure-Guard: `network_exposure_status=ok checks=20 findings=0 published_ports=1 public_binds=0 loopback_listeners=1 non_loopback_listeners=0 nft_nat_redirect_18083=0 tunnel_host=br.m11h.eu`.
- Public-DNS-Exposure-Guard: `public_dns_exposure_status=ok checks=7 findings=0 host=br.m11h.eu a_records=2 aaaa_records=2 forbidden_hits=0 global_records=4 non_public_records=0`.
- Public-DNS-Multiresolver-Guard: `public_dns_multiresolver_status=ok checks=14 findings=0 host=br.m11h.eu resolvers=3 successful_resolvers=3 resolver_errors=0 a_records=6 aaaa_records=6 unique_records=4 forbidden_hits=0 global_records=4 non_public_records=0`.
- Public-DNS-Authoritative-Guard: `public_dns_authoritative_status=ok checks=45 findings=0 host=br.m11h.eu zone=m11h.eu nameservers=2 authority_addresses=12 successful_authorities=12 authority_errors=0 authoritative_responses=24 a_records=24 aaaa_records=24 unique_records=4 forbidden_hits=0 global_records=4 non_public_records=0`.
- Public-DNS-CAA-Guard: `public_dns_caa_status=ok checks=5 findings=0 host=br.m11h.eu zone=m11h.eu qnames=2 successful_lookups=2 lookup_errors=0 caa_records=0 issue=0 issuewild=0 iodef=0 unrestricted=1 letsencrypt_allowed=1 blocked_issue=0 critical_unknown=0`.
- Direct-Origin-Bypass-Guard: `direct_origin_bypass_status=ok checks=85 findings=0 targets=4 ipv4_targets=2 ipv6_targets=2 named_targets=0 paths=8 probes=64 blocked=56 tls_blocked=32 redirects=8 basic_auth=0 valid_https=0 bypass_findings=0 unsafe_http=0`.
- Direct-Origin-Port-Exposure-Guard: `direct_origin_port_exposure_status=ok checks=35 findings=0 targets=4 ipv4_targets=2 ipv6_targets=2 named_targets=0 ports=7 probes=28 open_total=2 allowed_open=2 unexpected_open=0 closed_or_filtered=26 allowed_ports=80:443`.
- Host-UDP-Exposure-Guard: `host_udp_exposure_status=ok checks=8 findings=0 ports=7 direct_hosts=6 relevant_listeners=0 direct_relevant_listeners=0 loopback_relevant_listeners=0 udp_publishers=1 host_udp_published=0 unexpected_host_udp=0 allowed_udp_ports=none`.
- Host-Firewall-BR-Ports-Guard: `host_firewall_br_ports_status=ok checks=313 findings=0 direct_hosts=6 input_accepts=8 unexpected_input_accepts=0 nat_rules=3 expected_loopback_nat=1 unexpected_nat_rules=0 web_accepts=6 docker_bridge_rules=70`.
- Host-NFT-BR-Ports-Guard: `host_nft_br_ports_status=ok checks=313 findings=0 direct_hosts=6 tables=8 chains=101 rules=308 input_accepts=4 unexpected_input_accepts=0 nat_rules=3 expected_loopback_nat=1 unexpected_nat_rules=0 web_exposure_rules=6 docker_bridge_rules=90 xt_nat_rules=7 native_nat_rules=0 unsupported_expr_rules=0 unsupported_jump_rules=0 traversed_jump_rules=0 unresolved_jump_rules=0 chain_traversal_rules=0 chain_traversal_cycles=0 set_objects=1 set_elements=4 expanded_setref_rules=0 expanded_setrefs=0 expanded_anonymous_set_rules=0 expanded_anonymous_sets=0 unresolved_setref_rules=0`.
- Network-Policy-Consistency-Guard: `network_policy_consistency_status=ok checks=26 findings=0 concrete_targets=4 wildcard_hosts=2 tcp_ports=7 udp_ports=7 web_tcp=2 loopback_tcp=1`.
- Network-Policy-Runtime-Env-Guard: `network_policy_runtime_env_status=ok checks=122 findings=0 env_names=24 current_env_overrides=0 unit_overrides=0 project_references=80 installed_unit_references=0`.
- Network-Policy-Runtime-Summary-Guard: `network_policy_runtime_summary_status=ok checks=65 findings=0 summaries=12 ok_summaries=12 failed_summaries=0 origin_targets=4 direct_hosts=6 tcp_ports=7 udp_ports=7 web_tcp=2 loopback_tcp=1`.
- Access-Runtime-Source-Hardening: `access_runtime_source_hardening_status=ok`.
- Runtime-HTTP-Security: `runtime_http_security_status=ok checks=24 findings=0 paths=2 unauthorized=2 header_checks=20 server_header_seen=0`.
- External-Access-Surface: `external_access_surface_status=ok checks=88 findings=0 paths=8 protected=8 cf_access=8 basic_auth=0 redirects=0 cloudflare_server=8 set_cookie_paths=8`.
- External-Cookie-Security: `external_cookie_security_status=ok checks=27 findings=0 paths=3 cookies=3 expected_names=3 secure=3 httponly=3 samesite=3 path_root=3 expiry=3 allowed_domain=3`.
- TLS-Certificate-Guard: `tls_certificate_status=ok checks=7 findings=0 host=br.m11h.eu port=443 tls=TLSv1.3 days_valid=54.9 san_match=1 issuer_present=1 cipher_present=1`.
- App-Auth-Surface: `app_auth_surface_status=ok checks=21 findings=0 protected_gets=9 redirected=9 public_gets=2 public_ok=2 csrf_posts=6 csrf_blocked=6 post_successes=0 post_redirects=0`.
- Runtime-Log-Marker: `runtime_log_marker_status=ok checks=5 markers=5 findings=0`.
- Image-Pinning-Guard: `image_pinning_guard_status=ok refs=6 local_build=2 digest_pinned=4 violations=0`.
- Systemd-Unit-Guard: `systemd_unit_guard_status=ok checks=181 units=10 timers=5 services=5 sync_failures=0 missing_units=0 unit_policy_failures=0 parent_policy_failures=0 attr_policy_failures=0 lsattr_available=1 acl_tool_available=0 xattr_tool_available=0 inactive_timers=0 failed_services=0`.
- Systemd-Source-Hardening: `systemd_source_hardening_status=ok`.
- Status-Source-Hardening: `status_source_hardening_status=ok`.
- Healthcheck-Source-Hardening: `healthcheck_source_hardening_status=ok`.
- Core-Source-Hardening: `core_source_hardening_status=ok`.
- Container-Source-Hardening: `container_source_hardening_status=ok`.
- Network-Source-Hardening: `network_source_hardening_status=ok`.
- Access-Runtime-Source-Hardening: `access_runtime_source_hardening_status=ok`.
- Backup-Source-Hardening: `backup_source_hardening_status=ok`.
- Restore-Source-Hardening: `restore_source_hardening_status=ok`.
- Freshness-Source-Hardening: `freshness_source_hardening_status=ok`.
- Storage-Source-Hardening: `storage_source_hardening_status=ok`.
- Python-Syntax-Guard: `python_syntax_status=ok`.
- Shell-Syntax-Guard: `shell_syntax_status=ok`.
- Guard-Coverage-Guard: `guard_coverage_status=ok`.
- Meta-Source-Hardening: `meta_source_hardening_status=ok`.
- Doku-Source-Hardening: `doc_source_hardening_status=ok`.
- Source-Hardening-Coverage: `source_hardening_coverage_status=ok`.
- Summary-Contract-Guard: `summary_contract_status=ok`.
- Surface-Registry-Guard: `surface_registry_status=ok`.
- Guard-Registry-Integrity: `guard_registry_integrity_status=ok`.
- Protocol-Integrity-Guard: `protocol_integrity_status=ok`.
- Git-Remote-Readiness: `git_remote_readiness_status=ok branch=main tracking=1 dirty=0 remote_head_present=1 sensitive_tracked=0 git_user=chris`.
- Backup-Scope-Guard: `backup_scope_status=ok checks=36 findings=0 snapshots=48 latest_snapshot=c94d3ec9 tags=2 paths=3 expected_paths=3 helper_binaries=4 restic_binary=/usr/bin/restic`.
- Backup-Runtime-Policy-Guard: `backup_runtime_policy_status=ok checks=34 findings=0 backup_env_mode=600 backup_env_parent_mode=700 restic_mode=755 service_mode=644 service_user_root=1 helper_binaries=2 restic_binary=/usr/bin/restic`.
- Restic-Repository-Check-Freshness: `restic_repository_check_status=ok checks=10 findings=0 last_check=2026-06-06T06:25:14Z age_h=27.8 snapshots=48 documented_success=1 max_age_h=720.0 lock_preflight=0`.
- Restore-Runtime-Policy-Guard: `restore_runtime_policy_status=ok checks=74 findings=0 backup_env_mode=600 tmp_mode=1777 restic_mode=755 docker_mode=755 service_mode=644 timer_mode=644 service_user_root=1 timer_persistent=1 helper_binaries=3 restic_binary=/usr/bin/restic docker_binary=/usr/bin/docker`.
- Import-Pipeline-Guard: `import_pipeline_status=ok checks=11 findings=0 m00h_latest_age_h=7.7 bag_latest_age_h=7.3 recent_checked_72h=26`.
- Import-Source-Hardening: `import_source_hardening_status=ok`.
- Data-Integrity-Source-Hardening: `data_integrity_source_hardening_status=ok checks=169 findings=0 answer_export_markers=35 audit_markers=25 db_schema_markers=28 forbidden_markers=75`.
- Antwort-/Export-Safety: `answer_export_safety_status=ok checks=29 findings=0 answers_without_statements=0 statements_without_citation=0 html_checked=55 pdf_checked=55`.
- Audit-Trail: `audit_trail_status=ok checks=11 findings=0 audit_rows=120 answer_create_audit_rows=63 export_audit_rows=49 legacy_export_gaps=8`.
- DB-Schema: `db_schema_status=ok checks=42 findings=0 tables=9 indexes=32 expected_indexes=23`.
- Backup-Freshness: `backup_freshness_status=ok checks=113 findings=0 latest_snapshot=c94d3ec9 restic_latest=c94d3ec9 restic_locks=0 restic_stale_locks=0 backup_env_mode=600 helper_binaries=5 python_binary=/usr/bin/python3.13 restic_binary=/usr/bin/restic latest_log_age_h=0.8 latest_dump_age_h=0.8 restic_age_h=0.8 log_count=50 dump_count=20 protocol_snapshot_current=1`.
- Storage-Permissions: `storage_permission_status=ok checks=20 findings=0 storage_world_writable=0 storage_symlinks=0 project_secret_candidates=0 sensitive_world_readable=0 cloudflared_json=1`.
- Storage-Capacity: `storage_capacity_status=ok checks=6 findings=0 min_free_gib=10.4 max_used_pct=20.4 max_inode_pct=4.0 docker_size_gib=16.6 docker_reclaimable_gib=2.9`.
- Restore-Freshness: `restore_freshness_status=ok checks=83 findings=0 latest_restore_age_h=5.3 log_count=13 restore_snapshot=latest restore_resolved_snapshot=bdc876ca restore_resolved_snapshot_present=1 restore_resolved_snapshot_paths=3 helper_binaries=5 python_binary=/usr/bin/python3.13 self_script_policy=1 self_parent_policy=1 restore_dump=postgres-20260607T025508Z.sql db_restore=ok sql_ready_wait=15 manifests=55`.
- Readiness-Doku: `readiness_doc_status=ok checks=274 findings=0 stand=2026-06-07T12:34:15Z backup_snapshot=c94d3ec9 restore_dump=postgres-20260607T025508Z.sql`.
- Regression-Freshness: `regression_freshness_status=ok checks=52 findings=0 cases=4 exported_cases=4 max_age_h=203.9 min_age_h=203.9`.
- Regression-Source-Hardening: `regression_source_hardening_status=ok`.
- Python-Syntaxcheck: 86 Dateien per AST-Parse geprueft, ohne Bytecode-Artefakte.

Der Artefakt-Guard prueft derzeit unter anderem:

- `*.pyc`.
- `__pycache__`.
- `*.log` im App-Projektbaum.
- `.env` und `*.env`.
- `cloudflared/*.json`.
- `*credential*`.
- `*token*`.

Der Host-Kontext-Guard `scripts/check-host-context.py` ist read-only und prueft
vor Status-, systemd-Healthcheck- und Backup-Laeufen den erwarteten Zielhost:
`hostname=m11h.eu`, `HOST_ROLE=m11h`, `THIS_SERVER=m11h`, Public IPv4
`31.70.74.139`, Tailscale IPv4 `100.102.205.121` und
`M00H_IS_DIFFERENT_SERVER=true`. Er gibt nur nicht-sensitive Hostmetadaten aus
und liest keine Secretwerte, Dump-Inhalte, Log-Inhalte oder Backup-Env-Inhalte.

Der Time-Sync-Guard `scripts/check-time-sync.py` ist read-only und prueft Zeit-
und NTP-Metadaten ueber `timedatectl` und `chronyc tracking`. Er erwartet
`NTPSynchronized=yes`, einen plausiblen chrony-Stratum, niedrige System-/RMS-
Offsets und `Leap status: Normal`. Die optionale `SystemClockSynchronized`-
Property ist auf diesem System nicht verfuegbar und wird deshalb als
`system_clock=-1` informativ ausgegeben, nicht als Fehler, solange chrony sauber
ist. Servernamen, Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte werden
nicht ausgegeben.

Der Compose-Service-Guard `scripts/check-compose-services.py` ist read-only und
prueft nur Docker-Compose-Metadaten. Erwartet werden genau die fuenf Services
`app`, `db`, `worker`, `proxy` und `cloudflared`; alle muessen `running` sein,
und `app`/`db` muessen `healthy` melden. Der Guard liest keine Containerlogs,
Secretwerte, Dump-Inhalte, Antworttexte oder Quelleninhalte und laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.
`cloudflared` ist fuer den Live-Betrieb auf `m11h` trotz Compose-`profile:
tunnel` bewusst Pflicht. Der Parser akzeptiert zeilenweise JSON-Objekte und
JSON-Array-Ausgaben von `docker compose ps --format json`.

Der Privilege-Policy-Guard `scripts/check-privilege-policy.py` ist read-only und
prueft die effektive sudo-Policy fuer `chris` ueber `sudo -n -l -U chris` als
aggregierte Policy-Metadaten. Er gibt keine sudoers-Inhalte, keine vollstaendigen
Kommandolisten, keine Secretwerte, keine Logs, keine Dumps, keine Antworttexte und
keine Quelleninhalte aus. Breite sudo-Rechte werden bewusst sichtbar gemacht, aber
im BR-Wissen-Kontext nicht failend gewertet, damit systemweite sudoers-Rechte
nicht automatisch geaendert werden. Aktueller Stand: `privilege_policy_status=ok`,
`command_entries=2`, `nopasswd_entries=1`, `password_entries=1`,
`nopasswd_all=1`, `unrestricted_all=1`, `broad_sudo=1`. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Privilege-Risk-Review-Guard `scripts/check-privilege-risk-review.py` ist
read-only und verknuepft den aktuellen aggregierten Privilege-Policy-Status mit
der dokumentierten Risikoakzeptanz in `docs/PRIVILEGE-RISK-REVIEW.md`. Bei
`broad_sudo=1` erwartet er `risk_acceptance_status=accepted`,
`least_privilege_followup=required`, `sudoers_auto_change_allowed=0`,
`last_review_date` und ein nicht ueberfaelliges `next_review_due`. Er gibt
keine sudoers-Inhalte, keine vollstaendigen Kommandolisten, keine Secretwerte,
keine Logs, keine Dumps, keine Antworttexte und keine Quelleninhalte aus und
aendert keine sudoers-Konfiguration. Aktueller Stand:
`privilege_risk_review_status=accepted_risk`, `critical_privilege_risk=1`,
`acceptance=1`, `least_privilege_followup=1`, `review_cadence=monthly`,
`review_overdue=0`. Der Guard laeuft im
normalen Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Privilege-Least-Privilege-Plan-Guard
`scripts/check-privilege-least-privilege-plan.py` ist read-only und prueft den
konkreten Folgeplan in `docs/PRIVILEGE-LEAST-PRIVILEGE-PLAN.md`. Erwartet werden
`plan_status=planned`, `target_due`, `requires_lockout_protection=1`,
`requires_rollback_plan=1`, `requires_visudo_validation=1`,
`requires_backup_before_change=1`, `requires_command_inventory=1`,
`requires_staged_rollout=1` und `sudoers_auto_change_allowed=0`. Er gibt keine
sudoers-Inhalte, keine vollstaendigen Kommandolisten, keine Secretwerte, keine
Logs, keine Dumps, keine Antworttexte und keine Quelleninhalte aus und aendert
keine sudoers-Konfiguration. Aktueller Stand:
`privilege_least_privilege_plan_status=planned`, `due_overdue=0`,
`lockout_protection=1`, `rollback_plan=1`, `command_inventory=1`,
`staged_rollout=1`. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Privilege-Remediation-Gate-Guard
`scripts/check-privilege-remediation-gate.py` ist read-only und prueft das
geschlossene Gate in `PRIVILEGE-REMEDIATION-GATE.md` gegen Risk-Review und
Least-Privilege-Plan. Erwartet werden `privilege_remediation_gate_status=closed`,
`remediation_allowed=0`, `actual_sudoers_change_allowed=0`,
`accepted_risk_visible=1`, `critical_privilege_risk=1` und
`remediation_complete=0`. Der Guard trennt den aktuellen accepted-risk-/planned-
Betrieb klar von einer echten sudoers-Remediation. Er gibt keine sudoers-Inhalte,
keine vollstaendigen Kommandolisten, keine Secretwerte, keine Logs, keine Dumps,
keine Antworttexte und keine Quelleninhalte aus und aendert keine
sudoers-Konfiguration. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Privilege-No-Sudoers-Change-Guard
`scripts/check-privilege-no-sudoers-change.py` ist read-only und prueft die aktive
Policy in `PRIVILEGE-NO-SUDOERS-CHANGE-POLICY.md`. Erwartet werden
`privilege_no_sudoers_change_status=active`, `sudoers_changes_allowed=0`,
`sudoers_remediation_requested=0`, `actual_sudoers_change_allowed=0`,
`remediation_complete=0` und `accepted_risk_continues=1`. Damit ist fuer diesen
Arbeitsstrang dokumentiert, dass keine sudoers-Aenderungen gewuenscht oder erlaubt
sind. Er gibt keine sudoers-Inhalte, keine vollstaendigen Kommandolisten, keine
Secretwerte, keine Logs, keine Dumps, keine Antworttexte und keine Quelleninhalte
aus und aendert keine sudoers-Konfiguration. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Container-Hardening-Guard `scripts/check-container-hardening.py` ist read-only
und prueft nur Docker-Inspect-Metadaten fuer die fuenf erwarteten BR-Wissen-
Container. Er validiert unter anderem `Privileged=false`, keine zusaetzlichen
Capabilities, erwartetes `cap_drop: ALL` fuer App/DB/Worker/Cloudflared, die
dokumentierte Proxy-Ausnahme, erwartete Runtime-User, keine Device-Mounts, keine Host-/Sonder-Namespaces, genau das
erwartete interne Netzwerk, nur die erwarteten Port-Bindings, erwartete Mounts
und read-only-Modus fuer Secret-/Konfigurationsmounts. Env-Werte, Logs,
Dateiinhalte, Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen oder
ausgegeben. Aktuell werden read-only RootFS, `no-new-privileges` und
Ressourcenlimits fuer alle fuenf Container erzwungen. App, DB, Worker und
Cloudflared droppen alle Capabilities; der Caddy-Proxy laeuft jetzt als
Nicht-root-User `1001:127`, bleibt aber bei `cap_drop: ALL` bewusst ausgenommen,
weil Caddy damit nicht stabil startete. Caddy-`/data` und `/config` sind tmpfs-
Runtimepfade statt persistenter Volumes. Eine `.dockerignore` schuetzt Build-Kontexte zusaetzlich vor
versehentlichen lokalen Artefakten, Env-Dateien, Credential-/Token-Kandidaten,
Logs und Python-Cache-Dateien.

Der Compose-Source-Hardening-Guard `scripts/check-compose-source-hardening.py`
ist read-only und prueft nur die statische Quelle `docker-compose.yml`. Er ruft
bewusst nicht `docker compose config` auf, damit Env-Dateien nicht expandiert und
keine Secretwerte sichtbar werden. Er validiert unter anderem erwartete Services,
read-only RootFS, `no-new-privileges`, `cap_drop: ALL` fuer App/DB/Worker/
Cloudflared, die dokumentierte Proxy-Ausnahme, tmpfs inklusive Caddy-`/data` und
`/config`, Ressourcenlimits, erwartete Mount-Modi, Port-/Expose-Regeln und
Service-User fuer App/Worker/DB/Proxy.
Env-Werte, Logs, Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen
oder ausgegeben.

Der Network-Exposure-Guard `scripts/check-network-exposure.py` ist read-only und
prueft Docker-/Compose-, Proxy-, Tunnel-, lokale TCP-Listener- und nft-Firewall-
Metadaten. Er
erwartet genau die lokale Proxy-Publikation `127.0.0.1:18083 -> 8080`, meldet
Nicht-Loopback-Publikationen als Fehler und validiert zentrale Caddy-Marker
(`:8080`, Basic Auth, Noindex-/NoStore-Header, `reverse_proxy app:8000`) sowie
Cloudflared-Marker fuer `br.m11h.eu`, `http://proxy:8080`, 404-Fallback und einen
Credential-Pfad unter `/run/br-secrets/cloudflared/`. Credential-Dateien,
Secretwerte, Logs, Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen
oder ausgegeben. Zusaetzlich zaehlt der Guard ueber `nft -j list ruleset`, ob
NAT-/Redirect-Regeln den lokalen BR-Wissen-Port `18083` erwaehnen; Firewall-
Regelinhalte werden nicht ausgegeben. Der Guard laeuft im normalen Statuscheck,
im systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Public-DNS-Exposure-Guard `scripts/check-public-dns-exposure.py` ist read-only
und prueft die oeffentliche DNS-Aufloesung von `br.m11h.eu`. Er erwartet globale
A-/AAAA-Adressen und verbietet direkte Treffer auf die m11h-Origin-IP
`31.70.74.139` sowie die Tailscale-IP `100.102.205.121`. Aktueller Stand:
`a_records=2`, `aaaa_records=2`, `forbidden_hits=0`, also Cloudflare-Ziele ohne
direkte Origin-Exposition. Nicht-globale Records waeren ebenfalls failend.
Die Standard-Forbidden-IP-Liste ist ueber `BR_PUBLIC_DNS_FORBIDDEN_IPS`
ueberschreibbar und muss bei Origin-/Tailscale-IP-Aenderungen mitgepflegt werden.
DNS-Zonen, Cloudflare-Einstellungen, Secrets, Logs, Dumps, Antworttexte oder
Quelleninhalte werden nicht gelesen oder geaendert.

Der Public-DNS-Multiresolver-Guard `scripts/check-public-dns-multiresolver.py`
ist read-only und fragt mehrere externe rekursive Resolver direkt per DNS-UDP
nach A-/AAAA-Metadaten fuer `br.m11h.eu`. Standardresolver sind `1.1.1.1`,
`8.8.8.8` und `9.9.9.9`; mindestens zwei erfolgreiche Resolver sind erforderlich.
Der Guard ergaenzt den lokalen Resolver-Check, damit lokales Caching und
Propagationseffekte eher auffallen. Er erwartet globale Records und verbietet
direkte Treffer auf die m11h-Origin-IP `31.70.74.139` sowie die Tailscale-IP
`100.102.205.121`. Aktueller Stand: `public_dns_multiresolver_status=ok`,
`resolvers=3`, `successful_resolvers=3`, `resolver_errors=0`, `a_records=6`,
`aaaa_records=6`, `unique_records=4`, `forbidden_hits=0`, `global_records=4`,
`non_public_records=0`. DNS-Zonen, Cloudflare-Einstellungen, Secrets, Logs,
Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen oder geaendert.
DNSSEC wird bewusst nicht validiert; die Resolverliste bleibt Teil des Change-
Managements.

Der Public-DNS-Authoritative-Guard `scripts/check-public-dns-authoritative.py`
ist read-only und ermittelt die autoritativen Nameserver der Zone `m11h.eu` ueber
einen Bootstrap-Resolver. Danach fragt er deren Nameserver-Adressen direkt ohne
Recursion-Desired-Flag nach A-/AAAA-Metadaten fuer `br.m11h.eu`. Er ergaenzt die
lokale und rekursive Resolver-Sicht um die autoritative DNS-Sicht. Erwartet
werden autoritative Antworten, globale Records und keine direkten Treffer auf die
m11h-Origin-IP `31.70.74.139` oder die Tailscale-IP `100.102.205.121`. Aktueller
Stand: `public_dns_authoritative_status=ok`, `nameservers=2`,
`authority_addresses=12`, `successful_authorities=12`, `authority_errors=0`,
`authoritative_responses=24`, `a_records=24`, `aaaa_records=24`,
`unique_records=4`, `forbidden_hits=0`, `global_records=4`,
`non_public_records=0`. DNS-Zonen, Cloudflare-Einstellungen, Secrets, Logs,
Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen oder geaendert.
DNSSEC wird bewusst nicht validiert; Bootstrap-Resolver und Nameserverliste
bleiben Teil des Change-Managements.

Der Public-DNS-CAA-Guard `scripts/check-public-dns-caa.py` ist read-only und fragt
CAA-Metadaten fuer `br.m11h.eu` und `m11h.eu` ueber einen oeffentlichen Resolver
ab. Er prueft, ob vorhandene CAA-Records den aktuellen Let's-Encrypt-
Zertifikatspfad erlauben und ob unbekannte kritische CAA-Properties auftauchen.
Aktueller Stand: `public_dns_caa_status=ok`, `caa_records=0`, `issue=0`,
`issuewild=0`, `unrestricted=1`, `letsencrypt_allowed=1`, `blocked_issue=0`,
`critical_unknown=0`. DNS-Zonen, Cloudflare-Einstellungen, TLS-Konfiguration,
Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen oder
geaendert. DNSSEC wird bewusst nicht validiert; Resolverwahl und CAA-Policy
bleiben Teil des Change-Managements.

Der Direct-Origin-Bypass-Guard `scripts/check-direct-origin-bypass.py` ist
read-only und sendet `HEAD`-Anfragen mit `Host: br.m11h.eu` an bekannte IPv4-/
IPv6-Origin- und Tailscale-Ziele (`31.70.74.139`, `2a01:239:4ba:bf00::1`,
`100.102.205.121`, `fd7a:115c:a1e0::f233:cd79`) auf HTTP/HTTPS fuer `/`,
`/healthz`, `/login`, `/queries`, `/sources`, `/answers`, `/search` und
`/validation`. Er liest keine Antwortkoerper und wertet nur Verbindungsstatus,
HTTP-Status und Header-Metadaten aus. Host/Header- und Pfadwerte werden gegen
CR/LF-Injection und nicht absolute Pfade geprueft. Erwartet wird, dass direkte
Pfade ohne Cloudflare Access entweder geblockt sind, per TLS/Transport nicht
nutzbar sind, Basic Auth verlangen oder nur auf `https://br.m11h.eu/...`
redirecten. Aktueller Stand: `direct_origin_bypass_status=ok`, `targets=4`,
`ipv4_targets=2`, `ipv6_targets=2`, `named_targets=0`, `paths=8`, `probes=64`,
`blocked=56`, `tls_blocked=32`, `redirects=8`, `basic_auth=0`, `valid_https=0`,
`bypass_findings=0`, `unsafe_http=0`. Die Targetliste ist bewusst IP-basiert;
benannte Ziele werden als Konfigurationsfehler abgelehnt. HTTPS-Probes nutzen
normale Zertifikatsvalidierung fuer `br.m11h.eu`; jede direkt gueltig nutzbare
HTTPS-Antwort am Origin waere failend. Firewall-, DNS-, Caddy- oder App-
Konfiguration, Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte werden
nicht gelesen oder geaendert.

Der Direct-Origin-Port-Exposure-Guard
`scripts/check-direct-origin-port-exposure.py` ist read-only und fuehrt TCP-
Connect-Probes ohne Anwendungsdaten gegen dieselben direkten IPv4-/IPv6-Origin-
und Tailscale-Ziele aus. Der kuratierte BR-relevante Portsatz ist `80`, `443`,
`8000`, `8080`, `18083`, `5432` und `2019`. Nur `80` und `443` sind als offene
Webports erlaubt; deren Inhalts-/Access-Semantik prueft der Direct-Origin-
Bypass-Guard. Aktueller Stand: `direct_origin_port_exposure_status=ok`,
`targets=4`, `ipv4_targets=2`, `ipv6_targets=2`, `ports=7`, `probes=28`,
`open_total=2`, `allowed_open=2`, `unexpected_open=0`, `closed_or_filtered=26`,
`allowed_ports=80:443`. Dies ist bewusst kein Voll-Portscan; weitere Ports,
externe Scanstandorte oder automatische Listener-Erkennung bleiben eigene
Change-Management-Bloecke. Firewall-, DNS-, Caddy- oder App-Konfiguration,
Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen oder
geaendert.

Der Host-UDP-/QUIC-Exposure-Guard `scripts/check-host-udp-exposure.py` ist
read-only und prueft lokale Host-/Compose-Metadaten fuer BR-relevante UDP-Ports,
insbesondere UDP `443`/QUIC. Er sendet keine UDP-Pakete und ist kein externer UDP-
Portscan. Standardmaessig sind auf direkten Origin-/Tailscale-Adressen keine BR-
relevanten UDP-Ports erlaubt; `PUBLIC_IPV4` und `TAILSCALE_IPV4` werden
zusaetzlich aus `/etc/opencode-host-context` ergaenzt. Aktueller Stand:
`host_udp_exposure_status=ok`, `checks=8`, `ports=7`, `direct_hosts=6`,
`relevant_listeners=0`, `direct_relevant_listeners=0`,
`loopback_relevant_listeners=0`, `udp_publishers=1`, `host_udp_published=0`,
`unexpected_host_udp=0`, `allowed_udp_ports=none`. Firewall-, DNS-, Caddy- oder
App-Konfiguration, Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte werden
nicht gelesen oder geaendert.

Der Host-Firewall-BR-Ports-Guard `scripts/check-host-firewall-br-ports.py` ist
read-only und prueft lokale `iptables-save`-/`ip6tables-save`-Metadaten auf
unerwartete direkte INPUT-ACCEPTs oder DNAT-/REDIRECT-Regeln fuer BR-relevante
TCP-/UDP-Ports. Er aendert keine Firewall-Regeln, sendet keine Pakete und gibt
keine Regeltexte aus. Web-TCP `80`/`443` wird als erlaubte Web-Exposition
gezaehlt und inhaltlich separat vom Direct-Origin-Bypass-Guard validiert. Die
erwartete Loopback-NAT-Regel `127.0.0.1:18083` ist erlaubt; Docker-interne
Bridge-Regeln werden gezaehlt, aber nicht als direkte Origin-Exposition gewertet.
Aktueller Stand: `host_firewall_br_ports_status=ok`, `checks=313`, `findings=0`,
`direct_hosts=6`, `input_accepts=8`, `unexpected_input_accepts=0`, `nat_rules=3`,
`expected_loopback_nat=1`, `unexpected_nat_rules=0`, `web_accepts=6`,
`docker_bridge_rules=70`. Firewall-, DNS-, Caddy- oder App-Konfiguration,
Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen oder
geaendert.

Der Host-NFT-BR-Ports-Guard `scripts/check-host-nft-br-ports.py` ist read-only und
prueft die native nftables-Sicht ueber `sudo -n nft -j list ruleset`. Er wertet
nur strukturierte JSON-Metadaten aus, gibt keine Firewall-Regeltexte aus, aendert
keine Firewall-Regeln und sendet keine Pakete. Er ergaenzt den iptables-/
ip6tables-kompatiblen Guard und erkennt sowohl native nft NAT-Ausdruecke als auch
iptables-kompatible `xt:DNAT`-/`xt:REDIRECT`-Ausdruecke. Web-TCP `80`/`443`, die
erwartete Loopback-NAT-Regel `127.0.0.1:18083` und Docker-interne Bridge-Regeln
werden analog behandelt. Aktueller Stand: `host_nft_br_ports_status=ok`,
`checks=313`, `findings=0`, `direct_hosts=6`, `tables=8`, `chains=101`,
`rules=308`, `input_accepts=4`, `unexpected_input_accepts=0`, `nat_rules=3`,
`expected_loopback_nat=1`, `unexpected_nat_rules=0`, `web_exposure_rules=6`,
`docker_bridge_rules=90`, `xt_nat_rules=7`, `native_nat_rules=0`,
`unsupported_expr_rules=0`, `unsupported_jump_rules=0`, `traversed_jump_rules=0`,
`unresolved_jump_rules=0`, `chain_traversal_rules=0`,
`chain_traversal_cycles=0`, `set_objects=1`, `set_elements=4`,
`expanded_setref_rules=0`, `expanded_setrefs=0`,
`expanded_anonymous_set_rules=0`, `expanded_anonymous_sets=0`,
`unresolved_setref_rules=0`. Relevante BR-Input- oder NAT-Regeln
mit nicht vollstaendig aufgeloesten nft-Konstrukten wie `lookup`, `map`, `vmap`,
`dynset`, `objref`, `flow` oder Set-Referenzen werden failend als unsupported
gemeldet, soweit sie nicht einfache benannte oder anonyme Sets sind, die aus der
JSON-Sicht read-only expandiert werden koennen. Nicht aufloesbare Set-Referenzen
in relevanten Regeln sind failend. BR-relevante Input-/NAT-Regeln mit
dport-gebundenem `jump` oder `goto`
werden read-only in Zielketten hinein verfolgt; nicht aufloesbare oder zyklische
Zielketten sind failend.
Firewall-, DNS-, Caddy- oder App-Konfiguration, Secrets, Logs, Dumps, Antworttexte
oder Quelleninhalte werden nicht gelesen oder geaendert.
Der integrierte synthetische Self-Test prueft bekannte gute und schlechte nft-
JSON-Policy-Faelle ohne echte Firewall-Aenderung: `nft_selftest_status=ok cases=19
failed=0`.

Der Network-Policy-Consistency-Guard `scripts/check-network-policy-consistency.py`
ist read-only und vergleicht die nicht-sensitiven Policy-Defaults der Direct-
Origin-, Host-UDP-, Host-Firewall- und Host-NFT-Guards. Er prueft direkte Origin-/
Tailscale-Ziele, Wildcard-Hosts, BR-relevante TCP-/UDP-Ports, erlaubte Web-TCP-
Ports und die erwartete Loopback-NAT-Regel `127.0.0.1:18083`. Aktueller Stand:
`network_policy_consistency_status=ok`, `checks=26`, `findings=0`,
`concrete_targets=4`, `wildcard_hosts=2`, `tcp_ports=7`, `udp_ports=7`,
`web_tcp=2`, `loopback_tcp=1`. Es werden keine Pakete gesendet, keine Firewall-
Regeln geaendert und keine Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte
gelesen. Der Guard prueft Source-/Default-Konsistenz und Host-Kontextwerte, nicht
die aktive Runtime-Netzwerk-/Firewall-Konfiguration; Laufzeit-Drift bleibt Aufgabe
der spezialisierten Runtime-, Direct-Origin-, UDP-, iptables- und nftables-Guards.

Der Network-Policy-Runtime-Env-Guard `scripts/check-network-policy-runtime-env.py`
ist read-only und prueft, ob BR-Netzwerkpolicy-Environment-Variablen in der
aktuellen Guard-Umgebung, in installierten BR-systemd-Units oder in Projektquellen
ausserhalb erlaubter Guard-/Doku-Dateien gesetzt werden. Er gibt nur
Variablennamen und Zaehler aus, nie Werte. Aktueller Stand:
`network_policy_runtime_env_status=ok`, `checks=122`, `findings=0`,
`env_names=24`, `current_env_overrides=0`, `unit_overrides=0`,
`project_references=80`, `installed_unit_references=0`. Es werden keine Pakete
gesendet, keine Firewall-Regeln geaendert und keine Secrets, Logs, Dumps,
Antworttexte oder Quelleninhalte gelesen.

Der Network-Policy-Runtime-Summary-Guard
`scripts/check-network-policy-runtime-summary.py` ist read-only und fuehrt die
Summary-Laeufe der relevanten Netzwerk- und Exposure-Guards aus. Er prueft nur
Status-/Zaehler-Invarianten, z. B. keine direkten DNS-Origin-Treffer, keine
unerwarteten direkten Port-/NAT-/UDP-Expositionen, keine Runtime-Env-Overrides und
keine Host-NFT-Runtime-Findings fuer Traversal-/Set-Auswertung. Aktueller Stand:
`network_policy_runtime_summary_status=ok`, `checks=65`, `findings=0`,
`summaries=12`, `ok_summaries=12`, `failed_summaries=0`, `origin_targets=4`,
`direct_hosts=6`, `tcp_ports=7`, `udp_ports=7`, `web_tcp=2`, `loopback_tcp=1`.
Regeltexte, DNS-Antwortinhalte, Headerwerte, Secrets, Logs, Dumps, Antworttexte
oder Quelleninhalte werden nicht ausgegeben oder geaendert.

Container-Image-Inventar:

- `container_image_status=ok`.
- Aktuelle eindeutige Images inkl. laufender Projektcontainer: 5.
- Lokale Builds: `brm11heu-app`, `brm11heu-worker`.
- Digest-gepinnte externe Images: `caddy:2.8-alpine@sha256:...`,
  `pgvector/pgvector:pg16@sha256:...`,
  `cloudflare/cloudflared:latest@sha256:...`.
- Aktuelle Summary nach Rollout: `images=5`, `local_build=2`,
  `tag_pinned=0`, `digest_pinned=3`, `latest=0`, `unversioned=0`.
- App-/Worker-Basis ist ebenfalls digest-gepinnt:
  `python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203`.

Image-Pinning-Readiness:

- `image_pinning_readiness_status=ok`.
- Erfasste Referenzen inkl. Dockerfile-`FROM`: 6.
- Lokale Builds: 2.
- Bereits digest-gepinnt: 4.
- Pinning-Kandidaten mit Tag: 0.
- `latest`-Pinning-Kandidaten: 0.
- Unversionierte Pinning-Kandidaten: 0.
- Der Rollout auf Digests wurde mit Preflight-Backup, Rebuild, Container-Recreate,
  Healthcheck, Guards und frischen Regressionen validiert.
- Die normale Statusausgabe nutzt die lokale/offline Variante mit `--no-remote`,
  damit externe Registry-Ausfaelle nicht als Standardstatus-Warning erscheinen.
  Der remote-aktivierte Check bleibt per `scripts/status-br-wissen.sh
  --image-pinning` explizit abrufbar; `remote_unavailable>0` ist dann eine
  Registry-Verfuegbarkeitswarnung, kein lokaler Pinning-Verstoss. Zur Einordnung
  meldet die Summary `remote_expected`, `remote_coverage_pct` und digest-gekuerzte
  `remote_unavailable_refs`.

Image-Pinning-Guard:

- Skript: `scripts/check-image-pinning-guard.sh`.
- Laeuft lokal/offline ohne Registry-Abfrage.
- Erlaubt lokale Build-Images `brm11heu-*` und digest-gepinnte Referenzen.
- Meldet tag-only-, `latest`-ohne-Digest- und unversionierte externe Referenzen
  als Verstoß und beendet dann mit Fehlercode.
- Integriert in normalen Statuscheck, systemd-Healthcheck-Preflight und
  Backup-Preflight.

Systemd-Unit-Guard:

- Skript: `scripts/check-systemd-units.sh`.
- Prueft 10 BR-Wissen-Service-/Timer-Dateien auf Synchronitaet zwischen
  Projektquelle unter `systemd/` und `/etc/systemd/system/`.
- Prueft metadata-only, dass Unit-Quellen keine Symlinks oder irregulaeren Dateien
  sind, dass installierte Units nicht group-/world-writable sind und dass keine
  Projekt- oder installierte Unit world-writable ist (`unit_policy_failures=0`).
- Prueft metadata-only die Parent-Verzeichnisse `systemd/`, `/etc/systemd` und
  `/etc/systemd/system` auf Symlink-Freiheit, Verzeichnistyp, keine world-
  writable Rechte und fuer installierte Parents `root:root` ohne group-/world-
  writable Rechte (`parent_policy_failures=0`).
- Begrenzt die `root:root`-Parent-Anforderung auf installierte `/etc/systemd*`-
  Parents; das Projekt-`systemd/` folgt dem Projektbaum-Owner. Vendor-Units unter
  `/usr/lib/systemd`, Runtime-Units unter `/run/systemd` und User-Units sind nicht
  Teil dieses BR-Wissen-Direct-Unit-Guards.
- Prueft installierte Units auf `root:root` und Projekt-Units auf denselben Owner
  und dieselbe Group wie das Projekt-`systemd/`-Verzeichnis.
- Prueft mit dem vorhandenen `lsattr` metadata-only Linux-Dateiattribute der
  direkten BR-Wissen-Unit-Dateien und der geprueften Parent-Verzeichnisse. Das
  normale Extents-Flag `e` ist erlaubt; andere sichtbare Attribute gelten als
  Drift (`attr_policy_failures=0`, `lsattr_available=1`).
- ACL-/xattr-Tools sind auf diesem Host nicht installiert und werden deshalb
  nicht nachinstalliert oder erzwungen; die Summary macht diesen Blindspot
  transparent als `acl_tool_available=0` und `xattr_tool_available=0` sichtbar.
- Begrenzt den Symlink-/Dateipolicy-Scope auf die direkten BR-Wissen-Unit-Dateien
  aus der festen `br-wissen-*`-Liste; normale systemd-Enablement-Symlinks unter
  `*.wants/` werden nicht inspiziert.
- Prueft die 5 erwarteten Timer auf `active`.
- Prueft die 5 erwarteten BR-Wissen-Service-Units auf systemd-Zustand `failed`;
  abgeschlossene oneshot-Services im Zustand `inactive` sind erwartbar und kein
  Fehler.
- Integriert in normalen Statuscheck, systemd-Healthcheck-Preflight und
  Backup-Preflight.

Der Runtime-HTTP-Security-Guard `scripts/check-runtime-http-security.py` ist
read-only und sendet unauthentifizierte Loopback-GET-Anfragen an `/` und
`/healthz`. Er erwartet `401 Unauthorized`, `WWW-Authenticate: Basic`, Noindex,
NoStore, Content-Security-Policy, Referrer-Policy, X-Frame-Options,
X-Content-Type-Options, Permissions-Policy, COOP, CORP und keinen `Server`-
Header. Antwortkoerper, Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte
werden nicht gelesen oder ausgegeben. Damit auch Caddy-eigene Basic-Auth-401-
Antworten diese Header erhalten, setzt `proxy/Caddyfile` die Header zusaetzlich
im `handle_errors`-Block.

Der External-Access-Surface-Guard `scripts/check-external-access-surface.py` ist
read-only und sendet unauthentifizierte HTTPS-GET-Anfragen an zentrale Pfade unter
`https://br.m11h.eu`, darunter `/`, `/healthz`, `/login`, `/queries`, `/sources`,
`/answers`, `/search` und `/validation`. Er liest keine Antwortkoerper und gibt nur Status-/Header-
Metadaten als Zaehler aus. Er akzeptiert den aktuellen Cloudflare-Access-
Schutzpfad mit `cf-access-domain=br.m11h.eu` und Cloudflare-Metadaten oder, falls
Cloudflare spaeter bis Caddy durchreicht, den Caddy-Basic-Auth-401-Pfad. Im
aktuellen Live-Stand ist `cf_access=8` und `basic_auth=0`; Caddy-Basic-Auth wird
weiterhin lokal ueber den Runtime-HTTP-Security-Guard validiert. Cookie-Inhalte,
Zugangsdaten, Secretwerte, Logs, Dumps, Antworttexte oder Quelleninhalte werden
nicht gelesen oder ausgegeben.

Der External-Cookie-Security-Guard `scripts/check-external-cookie-security.py` ist
read-only und prueft unauthentifizierte HTTPS-Antworten fuer `/`, `/healthz` und
`/login` nur auf `Set-Cookie`-Attribute. Cookie-Werte werden nie ausgegeben.
Erwartet werden Cloudflare-Access-Cookies mit `Secure`, `HttpOnly`, gueltigem
`SameSite`, `Path=/`, Ablauf (`Expires` oder `Max-Age`) und fehlender oder
erwarteter Domain (`br.m11h.eu`, `.br.m11h.eu` oder `.m11h.eu`). `SameSite=None`
ist in Kombination mit `Secure` fuer Cloudflare Access als gueltige Syntax-/
Kompatibilitaetsvariante akzeptiert. Aktueller Stand: `cookies=3`, `secure=3`,
`httponly=3`, `samesite=3`, `path_root=3`, `expiry=3`, `allowed_domain=3`.
Zugangsdaten, Secrets, Logs, Dumps, Antworttexte oder Quelleninhalte werden nicht
gelesen oder ausgegeben.

Der TLS-Certificate-Guard `scripts/check-tls-certificate.py` ist read-only und
baut eine normale TLS-Verbindung zu `br.m11h.eu:443` auf. Er nutzt die
Standard-CA-/Hostname-Pruefung und prueft danach nur Metadaten: TLS-Version
`TLSv1.2` oder `TLSv1.3`, SAN-/Wildcard-Match fuer `br.m11h.eu`, vorhandenen
Issuer, Cipher-Marker und mindestens 14 Tage Restlaufzeit. Aktueller Stand:
`TLSv1.3`, erwarteter moderner TLS-1.3-Cipher, SAN-Match ueber `*.m11h.eu`,
Issuer vorhanden und ca. 54,9 Tage Restlaufzeit. HTTP-Antwortkoerper, Cookies, Zugangsdaten, Secretwerte, Logs,
Dumps, Antworttexte oder Quelleninhalte werden nicht gelesen oder ausgegeben.

Der App-Auth-Surface-Guard `scripts/check-app-auth-surface.py` ist read-only und
fuehrt im App-Container interne HTTP-Metadatenchecks gegen `127.0.0.1:8000` aus.
Er folgt keinen Redirects, liest keine Antwortkoerper und sendet keine
Zugangsdaten. Geprueft wird, dass geschuetzte GET-Routen unauthentifiziert per
`303` nach `/login` umleiten, `/healthz` und `/login` erreichbar sind und
unauthentifizierte POST-/Mutationsrouten ohne CSRF-Token mit `403` blockieren.
Unerwartete POST-Erfolge und POST-Redirects werden als `post_successes` und
`post_redirects` explizit gezaehlt. Secretwerte, Logs, Dumps, Antworttexte oder
Quelleninhalte werden nicht gelesen oder ausgegeben.

Der Runtime-Log-Marker-Guard prueft Containerlogs nur auf Marker und gibt keine
Logzeilen oder Werte aus. Gepruefte Marker sind unter anderem
`Authorization`, `Cf-Access-Jwt-Assertion`, `Proxy-Authorization`,
`X-Auth-Token` und `X-Api-Key`.

Der Import-Pipeline-Guard ist read-only und gibt nur Status, Zaehler und
Log-Alter aus. Er ist in Statuscheck, systemd-Healthcheck-Preflight und
Backup-Preflight integriert.

Der Import-Source-Hardening-Guard `scripts/check-import-source-hardening.py` ist
read-only und validiert die Quellen der m00h-/BAG-Importkette:
`scripts/import-m00h-betriebsrat.sh`, `scripts/import-bag-feed-docker.sh`,
`scripts/import-bag-feed.py` sowie die zugehoerigen Import-Service-/Timer-Quellen
unter `systemd/`. Er prueft erwartete Fail-Fast-, Pfad-, Log-, Rechte-, Checksum-,
Docker-, BAG-Feed-, Storage- und DB-Marker, ohne importierte Quelleninhalte, Logs,
Dumps, Backup-Env-Inhalte, Credentials, Antworten oder Dokumente zu lesen und ohne
Imports, Docker, `rsync`, Netzwerkzugriffe, `systemctl` oder `sudo` aufzurufen.
Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

Der Antwort-/Export-Safety-Guard ist read-only und prueft Antworten/Exporte nur
auf Zaehler, Marker und Dateiplausibilitaet. Antworttexte, Quelleninhalte,
Secretwerte oder Headerwerte werden nicht ausgegeben. Seit der Manifest-Haertung
muessen erzeugte Exporte zusaetzlich ein `manifest.json` mit Version,
Antwort-/Query-Metadaten, Policyflags, Citation-Metadaten ohne Klartextzitate
sowie HTML/PDF-Hash und Dateigroesse besitzen.
Die strukturierten Antwortgeneratoren speichern Antwort, Statements, Citations und
Audit-Eintrag inzwischen atomar in einer gemeinsamen Transaktion. Ein paralleler
Safety-Guard-Loop waehrend frischer Regressionen blieb fehlerfrei; es wurden keine
transienten Antworten ohne Statements mehr beobachtet.

Der Audit-Trail-Guard ist read-only und prueft nur Zaehler und bekannte
Aktionsklassen. Audit-Details, Antworttexte, Quelleninhalte oder Secretwerte
werden nicht ausgegeben. Acht historische Export-Auditluecken und eine fruehe
Antwort-Erzeugungsluecke sind als Legacy-Ausnahmen dokumentiert; neue Luecken
fuehren zum Fehler.

Der DB-Schema-Guard ist read-only und prueft nur Strukturmetadaten. Er validiert
die `vector`-Extension, die erwarteten Tabellen/Spalten und die Betriebsindexes
fuer Quellen, Dokumente, Chunks, Antworten, Citations und Audit-Log. Dateninhalte,
Antworttexte, Quelleninhalte oder Secretwerte werden nicht ausgegeben.

Der Data-Integrity-Source-Hardening-Guard
`scripts/check-data-integrity-source-hardening.py` ist read-only und validiert die
Quellen der Antwort-/Export-Safety-, Audit-Trail- und DB-Schema-Guards. Er prueft
metadata-only Antwort-/Export-Marker, Audit-Zaehler und bekannte Legacy-
Ausnahmen, DB-Extension-/Tabellen-/Spalten-/Index-Erwartungen, Export-Manifest-
Marker, kompakte Summary-Ausgaben und verbotene mutierende bzw. inhaltslesende
Marker. Er liest keine Secrets, Dumps, Logs, Antworttexte, Exporte oder
Quelleninhalte und ruft kein Docker, keine DB-Abfragen, keine Backups, Restores,
Imports oder Regressionen auf. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Restore-Smoke-Drill `scripts/restore-smoke-br-wissen.sh` stellt Snapshots nur
in isolierte `/tmp/br-wissen-restore-*`-Pfade wieder her, prueft Struktur,
Artefaktfreiheit, Export-/Manifestzaehler, Dump-Marker und das separat gesicherte
Projektprotokoll. Mit `--db` kann er den neuesten Dump in einem `--network none`-
Container ohne Ports testen. Secretwerte, Credential-Dateien und Dump-Inhalte
werden nicht ausgegeben.

Der automatisierte Restore-Smoke-Drill laeuft ueber
`br-wissen-restore-smoke.timer` und `scripts/run-restore-smoke-drill.sh`. Der
Wrapper erzeugt restriktive Logs unter
`/srv/br-wissensdatenbank/logs/restore-smoke-*.log`, rotiert standardmaessig auf
20 Restore-Smoke-Logs und fuehrt den Restore-Smoke mit isoliertem DB-Restore aus.
Der DB-Restore wartet nach `pg_isready` zusaetzlich auf eine SQL-Antwort per
`SELECT 1`; die Wartezeit ist ueber `BR_RESTORE_SQL_READY_WAIT` konfigurierbar
und betraegt standardmaessig 15 Sekunden.
Der Restore-Freshness-Guard `scripts/check-restore-freshness.py` prueft den
letzten Restore-Smoke nur ueber Metadaten/Marker, inklusive
`restore_sql_ready_wait`, und laeuft im Statuscheck sowie im
systemd-Healthcheck-Preflight. Root-Scans laufen ueber `--scan-json`, damit
Journald keine grossen Inline-Skripte protokolliert.

Dabei erwartet der Backup-Freshness-Guard im neuesten Backup-Log auch die Marker
`host_context_status=ok`, `time_sync_status=ok`, `network_exposure_status=ok`,
`public_dns_exposure_status=ok`, `public_dns_multiresolver_status=ok`,
`public_dns_authoritative_status=ok`, `public_dns_caa_status=ok`,
`direct_origin_bypass_status=ok`, `external_access_surface_status=ok`,
`external_cookie_security_status=ok`, `tls_certificate_status=ok`,
`import_pipeline_status=ok`, `import_source_hardening_status=ok`,
`data_integrity_source_hardening_status=ok`, `backup_source_hardening_status=ok`
und `restore_source_hardening_status=ok`,
damit das jeweils letzte Backup den Zielhost-, Time-Sync-, Netzwerk-Exposure-,
externen DNS-/HTTPS-Access-/Cookie-, TLS-Zertifikats-, Import- und Quellenhaertungs-
Preflight dokumentiert.

Der Backup-Freshness-Guard ist read-only und prueft lokale Backup-Logs, lokale
Dumps, Retention-Zaehler, Erfolgs-/Preflightmarker im neuesten Backup-Log, den
neuesten Restic-Snapshot und vorhandene Restic-Repository-Locks als reinen
Zaehler. Nur stale Locks sind failend; aktive Locks werden nur gezaehlt.
Die Lock-Abfrage setzt `LC_ALL=C`, damit der `stale`-Marker moeglichst stabil
erkannt wird; `no locks`-Statuszeilen werden nicht als Lock gezaehlt.
Zusaetzlich prueft der Guard die Restic-Env-Datei metadata-only auf Existenz,
regulaere Datei, Symlink-Freiheit, `root:root` und Modus `600`.
Die Summary zeigt den geprueften Modus als `backup_env_mode=600`.
Backup-Secretwerte, Dump-Inhalte, Lock-IDs und Log-Inhalte werden nicht
ausgegeben. Der Guard laeuft im Statuscheck und systemd-Healthcheck, aber bewusst
nicht als Backup-Preflight. Der root-noetige Scan laeuft ebenfalls ueber
`--scan-json`; der Guard erwartet im neuesten Backup-Log auch den
Time-Sync-, Compose-Service-, Container-Hardening-, Network-Exposure-, Public-DNS-Exposure-, Public-DNS-Multiresolver-, Public-DNS-Authoritative-, Public-DNS-CAA-, Direct-Origin-Bypass-, Runtime-HTTP-Security-, External-Access-Surface-, External-Cookie-Security-, TLS-Certificate-, App-Auth-Surface-, Storage-/Permission-,
Storage-/Capacity-, Readiness-Doku- und Regression-Freshness-Preflight sowie den Marker
`protocol_file_status=included`. Zusaetzlich prueft er nachgelagert, dass der
neueste Restic-Snapshot den Projektprotokollpfad enthaelt und nicht aelter als der
aktuelle Protokollstand ist; die Summary meldet dies als
`protocol_snapshot_current=1`. Diese Pruefung ist bewusst nicht Teil des Backup-
Preflights, damit ein neuer Protokollnachtrag das erforderliche Folgebackup nicht
blockiert.

Der Backup-Scope-Guard `scripts/check-backup-scope.py` nutzt fuer die root-
noetige Restic-Snapshot-Metadatenabfrage ebenfalls kuratierte absolute Helferpfade
statt eines unqualifizierten Root-`PATH`: `/usr/bin/sudo`, `/usr/bin/test`,
`/usr/bin/bash` und einen erlaubten Restic-Pfad aus `/usr/bin/restic` oder
`/usr/local/bin/restic`. Diese Helfer werden metadata-only auf Existenz,
Symlink-Freiheit, regulaere Datei, `root:root`, Modus, Ausfuehrbarkeit und
unerwartete Sonderbits geprueft. Die Summary weist diesen Scope als
`helper_binaries=4` und aktuell `restic_binary=/usr/bin/restic` aus.

Der Restore-Smoke protokolliert bei `snapshot=latest` zusaetzlich die konkret
aufgeloeste Restic-Snapshot-ID als `restore_resolved_snapshot=<id>`. Der
Restore-Freshness-Guard erwartet diesen Marker und zeigt ihn in der Summary, damit
der tatsaechlich gepruefte Snapshot nachvollziehbar ist, ohne Restore-Inhalte,
Dump-Inhalte, Secretwerte oder Antworttexte auszugeben. Zusaetzlich gleicht er
die aufgeloeste Snapshot-ID metadata-only gegen Restic ab: vorhanden,
Tags `br-wissen` und `includes-internal-sources`, sowie erwartete Pfade
`/home/chris/web/br.m11h.eu`, `/srv/br-wissensdatenbank` und
`/home/chris/web/diverses/betriebsrat.md`. Die Summary zeigt den Abgleich als
`restore_resolved_snapshot_present=1` und `restore_resolved_snapshot_paths=3`.
Die Restic-Metadatenabfrage nutzt keinen unqualifizierten Root-`PATH`, sondern
nur einen kuratierten ausfuehrbaren Restic-Pfad aus `/usr/bin/restic` oder
`/usr/local/bin/restic`. Auch die noetigen Helfer werden absolut referenziert:
`/usr/bin/sudo`, `/usr/bin/test`, `/usr/bin/bash` und fuer den root-noetigen
JSON-Scan ein kuratierter absoluter Python-Interpreter statt der Skript-Shebang.
Aktuell wird `/usr/bin/python3.13` gewaehlt, weil es eine regulaere root-owned
Datei ist; Symlinks wie `/usr/bin/python3` werden nicht akzeptiert. Der Guard
prueft diese Helfer sowie die ausgewaehlten Python-/Restic-Pfade metadata-only auf Existenz,
Symlink-Freiheit, regulaere Datei, `root:root`, nicht gruppen-/world-writable,
Ausfuehrbarkeit und erwartete Sonderbits; aktuell `helper_binaries=5` und
`python_binary=/usr/bin/python3.13`.
Zusaetzlich prueft der Guard sein eigenes Skript metadata-only auf Existenz,
Symlink-Freiheit, regulaere Datei, nicht gruppen-/world-writable,
Ausfuehrbarkeit und Mindestgroesse; die Guard-Datei ist auf Modus `755`
gehaertet und die Summary meldet aktuell `self_script_policy=1`. Ergaenzend
prueft der Guard die projektbezogenen Parent-Verzeichnisse
`/home/chris/web/br.m11h.eu` und `/home/chris/web/br.m11h.eu/scripts`
metadata-only auf Existenz, Symlink-Freiheit, Verzeichnistyp, Owner-/Group-
Konsistenz zum Skript, nicht gruppen-/world-writable und Suchbarkeit; beide
Verzeichnisse sind auf Modus `755` gehaertet und die Summary meldet aktuell
`self_parent_policy=1`.

Der Storage-/Permission-Guard ist metadata-only und prueft Modi, Owner, Symlinks
und Kandidatenzaehler fuer `/srv/br-wissensdatenbank`, Secret-Unterbaeume,
Cloudflared-Credentials, lokale Dumps, Backup-Logs, Exporte und den
App-Projektbaum. Secretwerte, Log-Inhalte, Dump-Inhalte und Export-Inhalte werden
nicht ausgegeben. Der root-noetige Scan laeuft ueber `--scan-json`, damit
Journald keine grossen Inline-Skripte protokolliert. Ein entdeckter Fail-Fast-
Randfall wurde behoben: Backup-Logs werden nun vor den Preflights mit Modus
`640` angelegt, sodass auch abgebrochene Backups keine world-readable Logs
zuruecklassen.

Der Storage-/Capacity-Guard ist read-only und prueft freie Bytes,
Belegungsprozent, Inode-Belegung und Docker-System-DF-Metadaten fuer Root,
App-Pfad, `/srv/br-wissensdatenbank`, `/tmp` und `/var/lib/docker`. Standard-
Mindestreserve: 10 GiB fuer Root/App/Storage/Docker, 2 GiB fuer `/tmp`, maximal
90 Prozent Byte- und Inode-Belegung. Der Guard laeuft im Statuscheck, im
systemd-Healthcheck, im Backup-Preflight und vor automatisierten Restore-Smoke-
Drills.

Der Readiness-Doku-Guard `scripts/check-readiness-doc.py` ist read-only und
prueft das Dossier `docs/READINESS.md` gegen Metadaten aus bestehenden
Summary-Guards. Er validiert Stand-Zeitstempel, Pflichtmarker, statische
Backup-/Restore-/Import-/Storage-Statusmarker, Erreichbarkeit nicht-zirkulaerer
Summary-Guards, den Protokollnachtrag sowie kompakte Backup-/Restore-
Evidenzwerte. Die Summary loest `backup_snapshot=<id>` aus dem Backup-Scope-Guard
und `restore_dump=<dump>` aus dem Restore-Freshness-Guard auf. Der Guard ruft
bewusst weiterhin nicht den Backup-Freshness-Guard auf, damit frische Doku- oder
Protokollnachtraege das naechste Backup nicht durch einen Kreisschluss blockieren.
Dynamische Snapshot-IDs und Dumpnamen werden nicht als exakter Dossierinhalt
erzwungen, damit der Guard nach regulaeren Nachtbackups nicht unnoetig rot wird.
Er gibt keine Secretwerte, Dump-Inhalte, Log-Inhalte oder Credential-Inhalte aus.
Der Guard laeuft im normalen Statuscheck und als systemd-Healthcheck-Preflight.

Der Guard-Coverage-Guard `scripts/check-guard-coverage.py` ist read-only und
prueft die Verdrahtung der Guard-Skripte selbst: vorhandene und executable
Skripte, Aufrufe im normalen Statuscheck, Backup-Preflight, Projekt- und
installierter systemd-Healthcheck-Unit sowie zentrale Marker im Readiness-Dossier.
Er liest nur Projektquellen, Doku und Unit-Text; Secretwerte, Dump-Inhalte, Logs,
Antworttexte oder Quelleninhalte werden nicht gelesen oder ausgegeben.

Der Meta-Source-Hardening-Guard `scripts/check-meta-source-hardening.py` ist
read-only und prueft die Meta-/Governance-Guardquellen fuer Guard-Coverage,
Readiness-Doku, Python-/Shell-Syntax und Systemd-Unit-Sync auf erwartete
Verdrahtungs-, Readiness-, Syntax-, Unit-Sync-, Summary- und Verbotsmarker. Er
liest nur Projektquellen, ruft keine Meta-Guards, kein `systemctl`, kein Docker,
keine Backups, Restores, Imports, Regressionen oder DB-Abfragen auf und gibt keine
Secretwerte, Dump-Inhalte, Log-Inhalte, Antworttexte, Exporte oder Quelleninhalte
aus.


Der Doku-Source-Hardening-Guard `scripts/check-doc-source-hardening.py` ist
read-only und prueft die Dokumentationsquellen `README.md`, `docs/RUNBOOK.md`,
`systemd/README.md` und `docs/READINESS.md` auf erwartete Betriebs-, Guardrail-,
Backup-/Restore-, Healthcheck-, Readiness-, Protokoll- und Keine-Secrets-Marker.
Er ruft keine Statuschecks, kein Docker, kein `systemctl`, keine Backups,
Restores, Imports, Regressionen oder DB-Abfragen auf und liest keine Secretwerte,
Dump-Inhalte, Log-Inhalte, Antworttexte oder Quelleninhalte.

Der Source-Hardening-Coverage-Guard `scripts/check-source-hardening-coverage.py`
ist read-only und prueft das `scripts/check-*`-Inventar gegen die dokumentierten
Source-Hardening-Gruppen, Governance-Schichten und expliziten Legacy-/Hilfs-
Ausnahmen. Neue oder verschobene Check-Skripte ohne Quellenhaertung werden damit
fail-closed sichtbar. Er ruft keine Guards, kein Docker, kein `systemctl`, keine
Backups, Restores, Imports, Regressionen oder DB-Abfragen auf und liest keine
Secretwerte, Dump-Inhalte, Log-Inhalte, Antworttexte, Exporte oder Quelleninhalte.

Der Summary-Contract-Guard `scripts/check-summary-contracts.py` ist read-only und
prueft die zentrale `GuardSpec`-Liste gegen die jeweiligen Guard-Skriptquellen.
Er stellt sicher, dass deklarierte Statuskeys in den Quellen vorkommen und dass
`--summary`-integrierte Guards einen Summary-Vertrag abbilden. Er ruft keine
Guards, kein Docker, kein `systemctl`, keine Backups, Restores, Imports,
Regressionen oder DB-Abfragen auf und liest keine Secretwerte, Dump-Inhalte,
Log-Inhalte, Antworttexte, Exporte oder Quelleninhalte.

Der Surface-Registry-Guard `scripts/check-surface-registry.py` ist read-only und
prueft die zentrale `GuardSpec`-Registry gegen Status-Wrapper, Backup-Preflight
und systemd-Healthcheck-Preflights. Er stellt sicher, dass die operationalen
Oberflaechen die Registry in Reihenfolge und ohne verdeckte Extra-/Missing-
Check-Aufrufe spiegeln; explizite Status-only-Hilfen bleiben dokumentierte
Ausnahmen. Er ruft keine Guards, kein Docker, kein `systemctl`, keine Backups,
Restores, Imports, Regressionen oder DB-Abfragen auf und liest keine Secretwerte,
Dump-Inhalte, Log-Inhalte, Antworttexte, Exporte oder Quelleninhalte.

Der Guard-Registry-Integrity-Guard `scripts/check-guard-registry-integrity.py` ist
read-only und prueft die zentrale `GuardSpec`-Registry selbst auf Duplikate bei
Labels, Skripten, Statuskeys und Backup-Labels, fehlende oder nicht ausfuehrbare
Check-Skripte, erwartete Statuskey-/Backup-Label-Formen und erlaubte
Argumentvertraege. Er ruft keine Guards, kein Docker, kein `systemctl`, keine
Backups, Restores, Imports, Regressionen oder DB-Abfragen auf und liest keine
Secretwerte, Dump-Inhalte, Log-Inhalte, Antworttexte, Exporte oder Quelleninhalte.

Der Protocol-Integrity-Guard `scripts/check-protocol-integrity.py` ist read-only
und prueft das Projektprotokoll `/home/chris/web/diverses/betriebsrat.md` sowie
die Backup-Wrapper-Quelle fuer dessen Restic-Einbindung. Er validiert erwartete
Struktur-, Guardrail-, Backup-/Restore-/Healthcheck- und Keine-Secrets-Marker und
meldet offensichtliche Credential-/Header-Leak-Marker. Er ruft keine Guards, kein
Docker, kein `systemctl`, keine Backups, Restores, Imports, Regressionen oder
DB-Abfragen auf und liest keine Secretwerte, Dump-Inhalte, Log-Inhalte,
Antworttexte, Exporte oder Quelleninhalte.

Der Python-Syntax-Guard `scripts/check-python-syntax.sh` ist read-only und prueft
alle Python-Dateien in `app/`, `scripts/` und `worker/` per `ast.parse`. Er
erzeugt keine `__pycache__`-Verzeichnisse und keine `*.pyc`-Dateien, liest keine
Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und gibt nur Dateipfade
bzw. kompakte Zaehler aus. Der Guard laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Shell-Syntax-Guard `scripts/check-shell-syntax.sh` ist read-only und prueft
Shell-Skripte in `scripts/` per `bash -n`, ohne die Skripte auszufuehren. Er
liest keine Secrets, Dumps, Logs, Antworttexte oder Quelleninhalte und gibt nur
Dateipfade bzw. kompakte Zaehler aus. Der Guard laeuft im normalen Statuscheck,
im systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Systemd-Source-Hardening-Guard
`scripts/check-systemd-source-hardening.py` ist read-only und validiert die
Projektquellen der BR-Wissen-Service- und Timer-Units. Er prueft erwartete
Description-, Wants-/After-, Type-, User-, WorkingDirectory-, ExecStart-,
ExecStartPre-, OnCalendar-, Persistent-, RandomizedDelaySec- und WantedBy-Marker,
ohne `systemctl` aufzurufen oder installierte Units zu veraendern. Secretwerte,
Dump-Inhalte, Logs, Antworttexte oder Quelleninhalte werden nicht gelesen oder
ausgegeben. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-
Preflight und im Backup-Preflight.

Der Status-Source-Hardening-Guard
`scripts/check-status-source-hardening.py` ist read-only und validiert die Quelle
des zentralen Status-Wrappers `scripts/status-br-wissen.sh`. Er prueft erwartete
read-only Defaults, erlaubte Kommandozeilenoptionen, explizite Opt-ins fuer
Regressionen, Duplikatbericht und Image-Pinning-Readiness, die vollstaendige
Guard-Abschnittskette sowie kompakte Summary-Aufrufe. Er liest keine Secrets,
Dumps, Logs, Antworten, Importe oder Quelleninhalte und ruft keine Statuschecks,
kein Docker, kein `systemctl`, keine Imports, Backups, Restores oder Regressionen
auf. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight
und im Backup-Preflight.

Der Backup-Source-Hardening-Guard
`scripts/check-backup-source-hardening.py` ist read-only und validiert die Quelle
des Backup-Wrappers `scripts/backup-br-wissen.sh`. Er prueft erwartete Fail-Fast-,
Backup-Env-, Protokoll-, Preflight-, Dump-, Restic-, Rechte- und
Retention-Marker, ohne Backup-Env-Inhalte, Dumps, Logs, Antworttexte oder
Quelleninhalte zu lesen und ohne Backups, Restic, Docker oder `systemctl`
aufzurufen. Der Guard laeuft im normalen Statuscheck, im systemd-Healthcheck-
Preflight und im Backup-Preflight.
Der Backup-Wrapper nutzt fuer `restic backup` und `restic forget` keinen
unqualifizierten Root-`PATH`, sondern waehlt `RESTIC_BIN` aus `/usr/bin/restic`
oder `/usr/local/bin/restic`; das Backup-Log enthaelt nur den gewaehlten Pfad als
`restic_bin=<pfad>`.

Der Restore-Source-Hardening-Guard
`scripts/check-restore-source-hardening.py` ist read-only und validiert die
Quellen der Restore-Smoke-Skripte `scripts/run-restore-smoke-drill.sh` und
`scripts/restore-smoke-br-wissen.sh`. Er prueft erwartete Fail-Fast-,
Zielpfad-, Rechte-, Storage-Preflight-, Restic-Restore-, erforderliche
Restore-Datei-, Dump-Marker-, isolierte DB-Restore-, Cleanup- und
Retention-Marker, ohne Backup-Env-Inhalte, Dumps, Logs, Antworttexte,
wiederhergestellte Dateien oder Quelleninhalte zu lesen und ohne Restore, Restic,
Docker, `sudo` oder `systemctl` aufzurufen. Der Guard laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Backup-Scope-Guard `scripts/check-backup-scope.py` ist read-only und prueft
ausschliesslich Restic-Snapshot-Metadaten des neuesten BR-Wissen-Backups. Erwartet
werden der Zielhost `m11h`, die kuratierten BR-Wissen-Tags und genau der
dokumentierte Backup-Pfadumfang fuer App, internen Datenbereich und
Projektprotokoll. Die root-only Backup-Env wird nur fuer die Snapshot-
Metadatenabfrage genutzt; Backup-Secretwerte, Dump-Inhalte, Log-Inhalte,
Antworttexte, Exporte oder Quelleninhalte werden nicht ausgegeben. Der Guard
startet keine Backups oder Restores, ruft kein Docker, kein `systemctl`, keine
Imports, Regressionen oder DB-Abfragen auf und laeuft im normalen Statuscheck, im
systemd-Healthcheck-Preflight und im Backup-Preflight.

Der Backup-Runtime-Policy-Guard `scripts/check-backup-runtime-policy.py` ist
read-only und prueft metadata-only das Backup-Ausfuehrungsumfeld. Erwartet werden
root-only Backup-Env-Datei mit Modus `600`, root-only Elternverzeichnis mit Modus
`700`, ein nicht setuid/setgid gesetztes Restic-Binary und eine installierte
Backup-Service-Policy mit `User=root`, erwarteter `ExecStart` und erwartetem
`WorkingDirectory`. Der Guard nutzt einen root-only JSON-Hilfsmodus fuer
Metadaten ueber `/usr/bin/sudo`, waehlt Restic nur aus `/usr/bin/restic` oder
`/usr/local/bin/restic` und prueft diese Helfer metadata-only auf Symlink-Freiheit,
regulaere Datei, `root:root`, Modus, Ausfuehrbarkeit und unerwartete Sonderbits.
Die Summary meldet `helper_binaries=2` und aktuell `restic_binary=/usr/bin/restic`.
Er gibt aber keine Backup-Env-Inhalte, Secretwerte, Dumps, Logs,
Antworttexte, Exporte oder Quelleninhalte aus und startet keine Backups,
Restores, Docker, Imports, Regressionen oder DB-Abfragen. Er laeuft im normalen
Statuscheck, im systemd-Healthcheck-Preflight und im Backup-Preflight.
Der Backup-Wrapper verwendet denselben kuratierten Restic-Pfadumfang
(`/usr/bin/restic` oder `/usr/local/bin/restic`) fuer die produktiven Backup- und
Retention-Aufrufe.

Der Restore-Runtime-Policy-Guard `scripts/check-restore-runtime-policy.py` ist
read-only und prueft metadata-only das Restore-Smoke-Ausfuehrungsumfeld. Erwartet
werden restriktive Backup-Env-Rechte, nicht gruppenschreibbare Restore-Skripte,
kuratierte Restic-/Docker-Systempfade, keine setuid/setgid-Binaries, `/tmp` mit
Sticky-Bit-Modus `1777`, eine installierte Restore-Smoke-Service-Policy mit
`User=root`, erwarteter `ExecStart` und erwartetem `WorkingDirectory` sowie die
dokumentierte persistente Wochenplanung des Timers. Der Guard nutzt einen
root-only JSON-Hilfsmodus ueber `/usr/bin/sudo`, waehlt Restic/Docker nur aus
`/usr/bin/restic`, `/usr/local/bin/restic`, `/usr/bin/docker` oder
`/usr/local/bin/docker` und prueft diese Helfer metadata-only auf Symlink-Freiheit,
regulaere Datei, `root:root`, Modus, Ausfuehrbarkeit und unerwartete Sonderbits.
Die Summary meldet `helper_binaries=3`, aktuell `restic_binary=/usr/bin/restic`
und `docker_binary=/usr/bin/docker`. Er gibt aber keine Backup-Env-Inhalte,
Secretwerte, Dumps, Logs, Antworttexte, Exporte oder Quelleninhalte aus und
startet keine Backups, Restores, Docker, Imports, Regressionen oder DB-Abfragen.
Er laeuft im normalen Statuscheck, im systemd-Healthcheck-Preflight und im
Backup-Preflight.

Der Regression-Freshness-Guard `scripts/check-regression-freshness.py` ist
read-only und erzeugt keine neuen Antworten oder Exporte. Er prueft fuer die vier
Kernfaelle die jeweils zuletzt vorhandene Antwort auf Alter, Statements,
direkte Citations, erlaubte/erforderliche Quellenklassen, erforderliche Quellen,
doppelte Chunk-IDs, gemischte Duplicate-Dokument-SHA-Gruppen sowie vorhandene
HTML-/PDF-/Manifest-Exporte. Er gibt keine Antworttexte, Quelleninhalte,
Secretwerte, Dump-Inhalte oder Log-Inhalte aus. Der Guard laeuft im normalen
Statuscheck und als systemd-Healthcheck-Preflight. Frische Regressionen werden
weiterhin nur mit `scripts/status-br-wissen.sh --with-regressions` bzw.
`scripts/run-regressions-docker.sh` erzeugt.

## Backup-Stand

Verschluesseltes Restic-Backup laut Backup-Freshness-Guard beim Doku-Abgleich vom
2026-06-07:

- Beim Doku-Abgleich dokumentierter Snapshot: `2908e56d`.
- Beim Doku-Abgleich dokumentierter Restic-Latest: `2908e56d`.
- Letzter expliziter Restic-Repository-Integritaetscheck: `2026-06-06T06:25:14Z`,
  `restic check`, 48 Snapshots geprueft, Ergebnis `no errors were found`.
  Dieser Check ist wegen exklusivem Repository-Lock bewusst manueller bzw.
  periodischer Wartungscheck und kein Backup-Preflight.
- Leichter Restic-Repository-Check-Freshness-Guard: `restic_repository_check_status=ok checks=10 findings=0 last_check=2026-06-06T06:25:14Z snapshots=48 documented_success=1 max_age_h=720.0 lock_preflight=0`. Dieser Guard startet keinen `restic check` und nimmt keinen Repository-Lock.
- Lokale Backup-Logs: 50.
- Lokale PostgreSQL-Dumps: 20.
- Alter des neuesten Backup-Logs/Dumps/Restic-Snapshots beim Doku-Abgleich: ca. 0.0 Stunden.
- Letzter Host-Kontext-Preflight: `host_context_status=ok checks=8 findings=0`.
- Letzter Time-Sync-Preflight: `time_sync_status=ok checks=8 findings=0 ntp=1 system_clock=-1 timezone=Europe/Berlin chrony_stratum=3 system_offset_s=0.000007 rms_offset_s=0.000023 leap_normal=1`.
- Letzter Compose-Service-Preflight: `compose_service_status=ok checks=9 findings=0 expected=5 running=5 health_required=2 healthy=2 unexpected=0`.
- Letzter Privilege-Policy-Preflight: `privilege_policy_status=ok checks=5 findings=0 target_user=chris command_entries=2 nopasswd_entries=1 password_entries=1 nopasswd_all=1 unrestricted_all=1 broad_sudo=1`.
- Letzter Container-Hardening-Preflight: `container_hardening_status=ok checks=108 findings=0 containers=5 privileged=0 cap_add=0 cap_drop_all=4 cap_drop_exceptions=1 expected_users=5 tmpfs_services=5 tmpfs_paths=12 devices=0 host_namespaces=0 unexpected_networks=0 unexpected_port_bindings=0 required_ro_mounts=6 writable_required_mounts=3 readonly_rootfs=5 writable_rootfs=0 apparmor_default=5 no_new_privileges=5 resource_limited=5`.
- Letzter Network-Exposure-Preflight: `network_exposure_status=ok checks=20 findings=0 published_ports=1 public_binds=0 loopback_listeners=1 non_loopback_listeners=0 nft_nat_redirect_18083=0 tunnel_host=br.m11h.eu`.
- Letzter Public-DNS-Exposure-Preflight: `public_dns_exposure_status=ok checks=7 findings=0 host=br.m11h.eu a_records=2 aaaa_records=2 forbidden_hits=0 global_records=4 non_public_records=0`.
- Letzter Public-DNS-Multiresolver-Preflight: `public_dns_multiresolver_status=ok checks=14 findings=0 host=br.m11h.eu resolvers=3 successful_resolvers=3 resolver_errors=0 a_records=6 aaaa_records=6 unique_records=4 forbidden_hits=0 global_records=4 non_public_records=0`.
- Letzter Public-DNS-Authoritative-Preflight: `public_dns_authoritative_status=ok checks=45 findings=0 host=br.m11h.eu zone=m11h.eu nameservers=2 authority_addresses=12 successful_authorities=12 authority_errors=0 authoritative_responses=24 a_records=24 aaaa_records=24 unique_records=4 forbidden_hits=0 global_records=4 non_public_records=0`.
- Letzter Public-DNS-CAA-Preflight: `public_dns_caa_status=ok checks=5 findings=0 host=br.m11h.eu zone=m11h.eu qnames=2 successful_lookups=2 lookup_errors=0 caa_records=0 issue=0 issuewild=0 iodef=0 unrestricted=1 letsencrypt_allowed=1 blocked_issue=0 critical_unknown=0`.
- Letzter Direct-Origin-Bypass-Preflight: `direct_origin_bypass_status=ok checks=85 findings=0 targets=4 ipv4_targets=2 ipv6_targets=2 named_targets=0 paths=8 probes=64 blocked=56 tls_blocked=32 redirects=8 basic_auth=0 valid_https=0 bypass_findings=0 unsafe_http=0`.
- Letzter Direct-Origin-Port-Exposure-Preflight: `direct_origin_port_exposure_status=ok checks=35 findings=0 targets=4 ipv4_targets=2 ipv6_targets=2 named_targets=0 ports=7 probes=28 open_total=2 allowed_open=2 unexpected_open=0 closed_or_filtered=26 allowed_ports=80:443`.
- Letzter Host-UDP-Exposure-Preflight: `host_udp_exposure_status=ok checks=8 findings=0 ports=7 direct_hosts=6 relevant_listeners=0 direct_relevant_listeners=0 loopback_relevant_listeners=0 udp_publishers=1 host_udp_published=0 unexpected_host_udp=0 allowed_udp_ports=none`.
- Letzter Host-Firewall-BR-Ports-Preflight: `host_firewall_br_ports_status=ok checks=313 findings=0 direct_hosts=6 input_accepts=8 unexpected_input_accepts=0 nat_rules=3 expected_loopback_nat=1 unexpected_nat_rules=0 web_accepts=6 docker_bridge_rules=70`.
- Letzter Host-NFT-BR-Ports-Preflight: `host_nft_br_ports_status=ok checks=313 findings=0 direct_hosts=6 tables=8 chains=101 rules=308 input_accepts=4 unexpected_input_accepts=0 nat_rules=3 expected_loopback_nat=1 unexpected_nat_rules=0 web_exposure_rules=6 docker_bridge_rules=90 xt_nat_rules=7 native_nat_rules=0`.
- Letzter Network-Policy-Consistency-Preflight: `network_policy_consistency_status=ok checks=26 findings=0 concrete_targets=4 wildcard_hosts=2 tcp_ports=7 udp_ports=7 web_tcp=2 loopback_tcp=1`.
- Letzter Network-Policy-Runtime-Env-Preflight: `network_policy_runtime_env_status=ok checks=158 findings=0 env_names=24 current_env_overrides=0 unit_overrides=0 project_references=93 installed_unit_references=0`.
- Letzter Runtime-HTTP-Security-Preflight: `runtime_http_security_status=ok checks=24 findings=0 paths=2 unauthorized=2 header_checks=20 server_header_seen=0`.
- Letzter External-Access-Surface-Preflight: `external_access_surface_status=ok checks=88 findings=0 paths=8 protected=8 cf_access=8 basic_auth=0 redirects=0 cloudflare_server=8 set_cookie_paths=8`.
- Letzter External-Cookie-Security-Preflight: `external_cookie_security_status=ok checks=27 findings=0 paths=3 cookies=3 expected_names=3 secure=3 httponly=3 samesite=3 path_root=3 expiry=3 allowed_domain=3`.
- Letzter App-Auth-Surface-Preflight: `app_auth_surface_status=ok checks=21 findings=0 protected_gets=9 redirected=9 public_gets=2 public_ok=2 csrf_posts=6 csrf_blocked=6 post_successes=0 post_redirects=0`.
- Letzter Backup-Preflight: `artifact_status=ok checks=8 findings=0`.
- Letzter Image-Pinning-Preflight: `image_pinning_guard_status=ok refs=6 local_build=2 digest_pinned=4 violations=0`.
- Letzter Systemd-Unit-Preflight: `systemd_unit_guard_status=ok checks=181 units=10 timers=5 services=5 sync_failures=0 missing_units=0 unit_policy_failures=0 parent_policy_failures=0 attr_policy_failures=0 lsattr_available=1 acl_tool_available=0 xattr_tool_available=0 inactive_timers=0 failed_services=0`.
- Letzter Systemd-Source-Hardening-Preflight: `systemd_source_hardening_status=ok`.
- Letzter Backup-Source-Hardening-Preflight: `backup_source_hardening_status=ok`.
- Letzter Restore-Source-Hardening-Preflight: `restore_source_hardening_status=ok`.
- Letzter Python-Syntax-Preflight: `python_syntax_status=ok`.
- Letzter Shell-Syntax-Preflight: `shell_syntax_status=ok`.
- Letzter Guard-Coverage-Preflight: `guard_coverage_status=ok`.
- Letzter Meta-Source-Hardening-Preflight: `meta_source_hardening_status=ok checks=617 findings=0 coverage_markers=26 readiness_markers=24 python_syntax_markers=13 shell_syntax_markers=11 systemd_unit_markers=19 doc_source_markers=14 source_coverage_markers=18 summary_contract_markers=12 surface_registry_markers=21 guard_registry_integrity_markers=16 protocol_integrity_markers=12 backup_scope_markers=11 forbidden_markers=396`.
- Letzter Import-Pipeline-Preflight: `import_pipeline_status=ok checks=11 findings=0`.
- Letzter Antwort-/Export-Safety-Preflight: `answer_export_safety_status=ok checks=29 findings=0 answers_without_statements=0 statements_without_citation=0 html_checked=55 pdf_checked=55`.
- Letzter Data-Integrity-Source-Hardening-Preflight: `data_integrity_source_hardening_status=ok checks=169 findings=0 answer_export_markers=35 audit_markers=25 db_schema_markers=28 forbidden_markers=75`.
- Letzter Audit-Trail-Preflight: `audit_trail_status=ok checks=11 findings=0 audit_rows=120 answer_create_audit_rows=63 export_audit_rows=49 legacy_export_gaps=8`.
- Letzter DB-Schema-Preflight: `db_schema_status=ok checks=42 findings=0 tables=9 indexes=32 expected_indexes=23`.
- Letzter Storage-/Permission-Preflight: `storage_permission_status=ok checks=20 findings=0 storage_world_writable=0 storage_symlinks=0 project_secret_candidates=0 sensitive_world_readable=0 cloudflared_json=1`.
- Letzter Storage-/Capacity-Preflight: `storage_capacity_status=ok checks=6 findings=0 min_free_gib=10.4 max_used_pct=20.4 max_inode_pct=4.0 docker_size_gib=16.6 docker_reclaimable_gib=2.9`.
- Letzter Restore-Freshness-Check: `restore_freshness_status=ok checks=83 findings=0 latest_restore_age_h=5.3 log_count=13 restore_snapshot=latest restore_resolved_snapshot=bdc876ca restore_resolved_snapshot_present=1 restore_resolved_snapshot_paths=3 helper_binaries=5 python_binary=/usr/bin/python3.13 self_script_policy=1 self_parent_policy=1 restore_dump=postgres-20260607T025508Z.sql db_restore=ok sql_ready_wait=15 manifests=55`.
- Letzter Readiness-Doku-Check: `readiness_doc_status=ok checks=250 findings=0 stand=2026-06-07T10:01:54Z stand_age_h=0.0 backup_snapshot=2908e56d restore_dump=postgres-20260607T025508Z.sql`.
- Letzter Regression-Freshness-Check: `regression_freshness_status=ok checks=52 findings=0 cases=4 exported_cases=4 max_age_h=203.9 min_age_h=203.9`.
- Projektprotokoll im Backupumfang: `/home/chris/web/diverses/betriebsrat.md`.
- Letzter Backup-Freshness-Check: `backup_freshness_status=ok checks=112 findings=0 latest_snapshot=2908e56d restic_latest=2908e56d restic_locks=0 restic_stale_locks=0 backup_env_mode=600 helper_binaries=5 python_binary=/usr/bin/python3.13 restic_binary=/usr/bin/restic latest_log_age_h=0.0 latest_dump_age_h=0.0 restic_age_h=0.0 log_count=50 dump_count=20 protocol_snapshot_current=1`.
- Letzter Restic-Repository-Check-Freshness-Check: `restic_repository_check_status=ok checks=10 findings=0 last_check=2026-06-06T06:25:14Z snapshots=48 documented_success=1 lock_preflight=0`.

Lokale Retention:

- PostgreSQL-Dumps: 20 Dateien, ca. 466M.
- Backup-Logs: 50 Dateien, ca. 856K.

Restic-Retention:

- `--keep-last 20`.
- `--keep-daily 14`.
- `--keep-weekly 8`.
- `--keep-monthly 6`.
- `--prune`.

Restic-Repository-Check:

- Manueller/periodischer Befehl:
  `sudo -n bash -lc 'set -euo pipefail; set -a; source /etc/web-backup/repos.d/m11h-br-wissen.env; set +a; restic check'`.
- Letzter dokumentierter Lauf: `2026-06-06T06:25:14Z`, 48 Snapshots geprueft,
  Ergebnis `no errors were found`.
- Bewusst nicht im Backup-Preflight oder Standard-Healthcheck, weil `restic check`
  einen exklusiven Repository-Lock nimmt und je nach Repository-Groesse laenger
  laufen kann.
- Der leichte Guard `scripts/check-restic-repository-check.py --summary` prueft
  nur diesen dokumentierten Nachweis und laeuft ohne Repository-Lock in Status,
  systemd-Healthcheck-Preflight und Backup-Preflight.

## Restore-Readiness

Restore-Tests duerfen weiterhin nur in isolierte temporaere Pfade erfolgen, nie
direkt in Produktivpfade.

Aktueller Restore-Freshness-Stand vom 2026-06-07 nach isoliertem Restore-Smoke:

- `restore_freshness_status=ok checks=83 findings=0 latest_restore_age_h=5.3 log_count=13 restore_snapshot=latest restore_resolved_snapshot=bdc876ca restore_resolved_snapshot_present=1 restore_resolved_snapshot_paths=3 helper_binaries=5 python_binary=/usr/bin/python3.13 self_script_policy=1 self_parent_policy=1 restore_dump=postgres-20260607T025508Z.sql db_restore=ok sql_ready_wait=15 manifests=55`.
- Der letzte automatisierte Restore-Smoke hat einen isolierten DB-Restore bestaetigt.
- Aktueller isolierter Restore-Smoke fuer `snapshot=latest`, konkret aufgeloest zu `restore_resolved_snapshot=bdc876ca`: neuester Dump `postgres-20260607T025508Z.sql`, DB-Restore in temporaerem Container mit `restore_network_mode=none` und `restore_ports={}` erfolgreich; der Restore-Freshness-Guard bestaetigte zusaetzlich `restore_resolved_snapshot_present=1` und `restore_resolved_snapshot_paths=3` fuer den metadata-only Restic-Metadatenabgleich.
- DB-Restore-Zaehler bleiben ueber den Restore-Freshness-Guard technisch gruen; Detailwerte werden im laufenden Dossier nicht erneut aus Dump- oder Log-Inhalten extrahiert.
- Restore-Smoke-Cleanup: keine temporären Restore-Smoke-Container und keine temporären Restore-Smoke-Volumes verblieben.
- Die nachfolgenden Restore-Abschnitte sind historische Nachweise frueherer
  Haertungsbloecke; sie bleiben zur Nachvollziehbarkeit erhalten und ersetzen
  nicht den jeweils aktuellen Restore-Freshness-Guard.

Aktueller Restore-Test nach Import-/Healthcheck-Haertung:

- Getesteter Snapshot: `cda02650`.
- Restore-Ziel: isolierter temporaerer Pfad unter `/tmp`.
- Ergebnis: 1349 Dateien/Verzeichnisse, 1.256 GiB wiederhergestellt.
- App- und Datenverzeichnis im Restore vorhanden.
- Neue/angepasste Guard-Dateien im Restore vorhanden:
  `scripts/check-import-pipeline.py`, `scripts/healthcheck-br-wissen.py`,
  `scripts/status-br-wissen.sh`, `scripts/backup-br-wissen.sh` und
  `systemd/br-wissen-healthcheck.service`.
- Keine `.env`-/`*.env`, `*.log`, `*.pyc`-/`__pycache__`-Artefakte und keine
  `cloudflared/*.json` im App-Projektbaum des Restores.
- Lokale Dumps im Restore: 20; neuster gepruefter Dump
  `postgres-20260529T202311Z.sql`, ca. 24.4 MB, mit PostgreSQL-Dump-Header,
  `CREATE TABLE`, `COPY` sowie Tabellenmarkern fuer `public.sources` und
  `public.answers`.
- Healthcheck-Unit und Backup-Skript enthalten den Import-Pipeline-Guard.
- Temporärer Restore-Pfad wurde nach der Pruefung entfernt.

Aktueller Restore-Smoke nach Antwort-/Export-Safety-Haertung:

- Getesteter Snapshot: `f709fe9d`.
- Restore-Ziel: isolierter temporaerer Pfad unter `/tmp`.
- Ergebnis: 1362 Dateien/Verzeichnisse, 1.256 GiB wiederhergestellt.
- App- und Datenverzeichnis im Restore vorhanden.
- Neue/angepasste Dateien im Restore vorhanden:
  `scripts/check-answer-export-safety.py`, `scripts/run-regressions.py`,
  `scripts/backup-br-wissen.sh`, `scripts/status-br-wissen.sh`,
  `systemd/br-wissen-healthcheck.service` und `docs/READINESS.md`.
- Keine `.env`-/`*.env`, `*.log`, `*.pyc`-/`__pycache__`-Artefakte und keine
  `cloudflared/*.json` im App-Projektbaum des Restores.
- Lokale Dumps im Restore: 20; neuster gepruefter Dump
  `postgres-20260529T205137Z.sql`, ca. 24.4 MB, mit PostgreSQL-Dump-Header,
  `CREATE TABLE`, `COPY` sowie Tabellenmarkern fuer `public.answers` und
  `public.answer_citations`.
- Healthcheck-Unit und Backup-Skript enthalten den Antwort-/Export-Safety-Guard.
- Temporärer Restore-Pfad wurde nach der Pruefung entfernt.

Aktueller Restore-Smoke nach Export-Manifest-Haertung:

- Getesteter Snapshot: `bf2c7533`.
- Restore-Ziel: isolierter temporaerer Pfad unter `/tmp`.
- Ergebnis: 1419 Dateien/Verzeichnisse, 1.257 GiB wiederhergestellt.
- App- und Datenverzeichnis im Restore vorhanden.
- Neue/angepasste Dateien im Restore vorhanden:
  `app/export_manifest.py`, `scripts/backfill-export-manifests.py`,
  `scripts/check-answer-export-safety.py`, `scripts/run-regressions.py` und
  `scripts/export-answer.py`.
- Keine `.env`-/`*.env`, `*.log`, `*.pyc`-/`__pycache__`-Artefakte und keine
  `cloudflared/*.json` im App-Projektbaum des Restores.
- Exportverzeichnisse im Restore: 43; `manifest.json`: 43.
- Lokale Dumps im Restore: 20; neuster gepruefter Dump
  `postgres-20260529T205945Z.sql`, ca. 24.5 MB, mit PostgreSQL-Dump-Header,
  `CREATE TABLE`, `COPY` sowie Tabellenmarkern fuer `public.answers` und
  `public.answer_citations`.
- Temporärer Restore-Pfad wurde nach der Pruefung entfernt.

Aktueller Restore-Smoke nach Audit-Trail-Haertung:

- Getesteter Snapshot: `51e3f0be`.
- Restore-Ziel: isolierter temporaerer Pfad unter `/tmp`.
- Ergebnis: 1436 Dateien/Verzeichnisse, 1.257 GiB wiederhergestellt.
- App- und Datenverzeichnis im Restore vorhanden.
- Neue/angepasste Dateien im Restore vorhanden:
  `scripts/check-audit-trail.py`, `scripts/backup-br-wissen.sh`,
  `scripts/status-br-wissen.sh`, `systemd/br-wissen-healthcheck.service`,
  `app/main.py`, `scripts/export-answer.py` und
  `scripts/backfill-export-manifests.py`.
- Keine `.env`-/`*.env`, `*.log`, `*.pyc`-/`__pycache__`-Artefakte und keine
  `cloudflared/*.json` im App-Projektbaum des Restores.
- Exportverzeichnisse im Restore: 47; `manifest.json`: 47.
- Lokale Dumps im Restore: 20; neuster gepruefter Dump
  `postgres-20260529T214250Z.sql`, ca. 24.5 MB, mit PostgreSQL-Dump-Header,
  `CREATE TABLE`, `COPY` sowie Tabellenmarkern fuer `public.audit_log`,
  `public.answers` und `public.answer_citations`.
- Healthcheck-Unit und Backup-Skript enthalten den Audit-Trail-Guard.
- Temporärer Restore-Pfad wurde nach der Pruefung entfernt.

Aktueller Restore-Smoke nach DB-Schema-/Index-Haertung:

- Getesteter Snapshot: `76a76b62`.
- Restore-Ziel: isolierter temporaerer Pfad unter `/tmp`.
- Ergebnis: 1454 Dateien/Verzeichnisse, 1.257 GiB wiederhergestellt.
- App- und Datenverzeichnis im Restore vorhanden.
- Neue/angepasste Dateien im Restore vorhanden:
  `scripts/check-db-schema.py`, `db/init/001_schema.sql`,
  `db/init/002_operational_indexes.sql`, `scripts/backup-br-wissen.sh`,
  `scripts/status-br-wissen.sh`, `systemd/br-wissen-healthcheck.service` und
  `docs/READINESS.md`.
- Keine `.env`-/`*.env`, `*.log`, `*.pyc`-/`__pycache__`-Artefakte und keine
  `cloudflared/*.json` im App-Projektbaum des Restores.
- Exportverzeichnisse im Restore: 51; `manifest.json`: 51.
- Lokale Dumps im Restore: 20; neuster gepruefter Dump
  `postgres-20260529T215526Z.sql`, ca. 24.5 MB, mit PostgreSQL-Dump-Header,
  `CREATE TABLE`, `COPY`, Tabellenmarkern fuer `public.audit_log`,
  `public.answers` und `public.answer_citations` sowie Indexmarkern fuer
  `idx_audit_log_action_created`, `idx_answer_citations_statement` und
  `idx_sources_citation_status`.
- Healthcheck-Unit, Backup-Skript und Statusskript enthalten je eine Referenz auf
  `check-db-schema.py`.
- Temporärer Restore-Pfad wurde nach der DB-Restore-Pruefung entfernt.

Aktueller Restore-Smoke nach Antwort-Atomisierung:

- Getesteter Snapshot: `19ea9c7b`.
- Restore-Ziel: isolierter temporaerer Pfad unter `/tmp`.
- Ergebnis: 1470 Dateien/Verzeichnisse, 1.257 GiB wiederhergestellt.
- App- und Datenverzeichnis im Restore vorhanden.
- Neue/angepasste Dateien im Restore vorhanden:
  `app/main.py`, `scripts/check-answer-export-safety.py`,
  `scripts/run-regressions.py`, `scripts/backup-br-wissen.sh`,
  `scripts/status-br-wissen.sh` und `docs/READINESS.md`.
- Keine `.env`-/`*.env`, `*.log`, `*.pyc`-/`__pycache__`-Artefakte und keine
  `cloudflared/*.json` im App-Projektbaum des Restores.
- Exportverzeichnisse im Restore: 55; `manifest.json`: 55.
- Lokale Dumps im Restore: 20; neuster gepruefter Dump
  `postgres-20260529T220843Z.sql`, ca. 24.5 MB, mit PostgreSQL-Dump-Header,
  `CREATE TABLE`, `COPY` sowie Tabellenmarkern fuer `public.audit_log`,
  `public.answers`, `public.answer_statements` und `public.answer_citations`.
- `app/main.py` im Restore enthaelt den atomaren Helper
  `create_cited_answer_record`; der Safety-Guard enthaelt die neue
  `NOT EXISTS`-Gesamtzaehlung fuer Antworten ohne Statements.
- Temporärer Restore-Pfad wurde nach der DB-Restore-Pruefung entfernt.

Aktueller automatisierter Restore-Smoke nach Restore-Smoke-Automatisierung:

- Skript: `scripts/restore-smoke-br-wissen.sh`.
- Getesteter Snapshot: `df708ffe`.
- Restore-Ziel: automatisch erzeugter isolierter temporaerer Pfad unter `/tmp`.
- App- und Datenverzeichnis im Restore vorhanden.
- `restore_file_count=1293`.
- `restore_required_missing=0`.
- `restore_artifact_findings=0`.
- `restore_export_dirs=55`.
- `restore_manifest_json=55`.
- Neuster gepruefter Dump: `postgres-20260530T052803Z.sql`, Groesse
  `24572092` Bytes, mit Markern fuer PostgreSQL-Dump, `CREATE TABLE`, `COPY`,
  `public.audit_log`, `public.answers`, `public.answer_statements` und
  `public.answer_citations`.
- Code-/Guard-Marker im Restore: `restore_atomic_helper_refs=4`,
  `restore_guard_not_exists_refs=1`, `restore_db_schema_refs=3`.
- DB-Restore im isolierten Container erfolgreich: `restore_network_mode=none`,
  `restore_ports={}`, `db_restore_status=ok`.
- Restore-Cleanup: temporaerer Restore-Pfad, Testcontainer, Testvolume und
  DB-Restore-Log wurden automatisch entfernt.

Aktueller automatisierter Restore-Smoke fuer neuesten Abschluss-Snapshot:

- Skript: `scripts/restore-smoke-br-wissen.sh`.
- Getesteter Snapshot: `16ad8c63`.
- Ausgefuehrt mit `scripts/restore-smoke-br-wissen.sh --snapshot 16ad8c63 --db`.
- Restore-Ziel: automatisch erzeugter isolierter temporaerer Pfad unter `/tmp`.
- App- und Datenverzeichnis im Restore vorhanden.
- `restore_file_count=1295`.
- `restore_required_missing=0`.
- `restore_artifact_findings=0`.
- `restore_export_dirs=55`.
- `restore_manifest_json=55`.
- Neuster gepruefter Dump: `postgres-20260530T065927Z.sql`, Groesse
  `24572092` Bytes, mit Markern fuer PostgreSQL-Dump, `CREATE TABLE`, `COPY`,
  `public.audit_log`, `public.answers`, `public.answer_statements` und
  `public.answer_citations`.
- Code-/Guard-Marker im Restore: `restore_atomic_helper_refs=4`,
  `restore_guard_not_exists_refs=1`, `restore_db_schema_refs=3`.
- DB-Restore im isolierten Container erfolgreich: `restore_network_mode=none`,
  `restore_ports={}`, `db_restore_status=ok`.
- Restore-Cleanup: temporaerer Restore-Pfad, Testcontainer, Testvolume und
  DB-Restore-Log wurden automatisch entfernt.

## Regression-Stand

Beim Doku-Abgleich am 2026-06-02 wurden keine neuen Regressionen erzeugt; der
Statuscheck meldete `skipped=true` mit Hinweis auf `--with-regressions`. Die
folgenden Regressionen sind die zuletzt dokumentierten frischen Regressionslaeufe
aus den vorherigen Haertungsbloecken.

Aktuelle Regression nach Import-/Healthcheck-Haertung: `status=ok`.

Aktuelle Regression nach Antwort-/Export-Safety-Haertung: `status=ok`.

Aktuelle Regression nach Export-Manifest-Haertung: `status=ok`.

Aktuelle Regression nach Audit-Trail-Haertung: `status=ok`.

Aktuelle Regression nach DB-Schema-/Index-Haertung: `status=ok`.

Aktuelle Regression nach Antwort-Atomisierung: `status=ok`.

Aktuelle Atomisierungs-Regressionsantworten:

- `a-tariff-20260529220711-62717a0c`.
- `a-struct-20260529220712-6623ee2d`.
- `a-struct-20260529220712-24be707b`.
- `a-tariff-20260529220713-42a357e1`.

Alle vier Atomisierungs-Regressionsfaelle hatten direkte Citations,
`statements_without_citation=0`, HTML/PDF-Export, `safety_markers_ok=true` und
`manifest_ok=true`. Parallel dazu lief ein Safety-Guard-Loop ohne Fehler:
`guard_loop_failures=0`, `guard_loop_failed_lines=0`,
`guard_loop_nonzero_answers_without_statements=0`.

Aktuelle DB-Schema-Regressionsantworten:

- `a-tariff-20260529215348-7462d34a`.
- `a-struct-20260529215349-a4d109a4`.
- `a-struct-20260529215349-301267de`.
- `a-tariff-20260529215350-b477a8fa`.

Alle vier DB-Schema-Regressionsfaelle hatten direkte Citations,
`statements_without_citation=0`, HTML/PDF-Export, `safety_markers_ok=true` und
`manifest_ok=true`.

Aktuelle Audit-Regressionsantworten:

- `a-tariff-20260529214128-6960213c`.
- `a-struct-20260529214129-1356bf05`.
- `a-struct-20260529214130-8896b4cc`.
- `a-tariff-20260529214131-90d551fe`.

Alle vier Audit-Regressionsfaelle hatten direkte Citations,
`statements_without_citation=0`, HTML/PDF-Export, `safety_markers_ok=true`,
`manifest_ok=true` und neue Audit-Eintraege fuer Antworterzeugung/Export.

Aktuelle Manifest-Regressionsantworten:

- `a-tariff-20260529205834-0d044d17`.
- `a-struct-20260529205835-cebf0f9c`.
- `a-struct-20260529205836-333dcabe`.
- `a-tariff-20260529205837-ebd1eefe`.

Alle vier Manifest-Regressionsfaelle hatten direkte Citations,
`statements_without_citation=0`, HTML/PDF-Export, `safety_markers_ok=true` und
`manifest_ok=true`.

Aktuelle Safety-Regressionsantworten:

- `a-tariff-20260529204955-144b4e6d`.
- `a-struct-20260529204956-844c26d5`.
- `a-struct-20260529204957-cb141388`.
- `a-tariff-20260529204958-e8daafd7`.

Alle vier aktuellen Safety-Regressionsfaelle hatten direkte Citations,
`statements_without_citation=0`, HTML/PDF-Exporte, keine doppelten Chunk-IDs,
keine gemischten Duplicate-Dokument-SHA-Quellen und `safety_markers_ok=true`.

Aktuelle Antwort-IDs:

- `a-tariff-20260529202257-37fe29d9`.
- `a-struct-20260529202258-d631ec39`.
- `a-struct-20260529202258-16897b83`.
- `a-tariff-20260529202259-d8e05255`.

Alle vier aktuellen Faelle hatten direkte Citations, keine Aussagen ohne
Citation, HTML/PDF-Exporte, keine doppelten Chunk-IDs und keine gemischten
Duplicate-Dokument-SHA-Quellen.

Gepruefte Kernfaelle:

1. `ocr_tariff_jobservice_corona`.
2. `bag_tarifkollision_green_only`.
3. `dsgvo_bdsg_green_only`.
4. `tariff_demografietv_dedupe`.

## Bekannte Restrisiken und bewusst offene Punkte

- Projekt ist kein Git-Repo; Code-/Doku-Historie wird aktuell ueber Protokoll und
  verschluesselte Backups nachvollzogen.
- `duplicate_document_sha_groups=7` ist bekannt und wird durch Regressionen
  ueber Dedupe-Pruefungen kontrolliert; es wurde nichts automatisch zusammengefuehrt.
- Laufende externe Container-Images und App-/Worker-Basis sind digest-gepinnt;
  kuenftige Image-Wechsel bleiben geplante Wartungsbloecke mit Backup,
  Rollback-Notiz, Rebuild/Rollout und Validierung.
- Restore-Readiness wurde strukturell/dateibasiert und zusaetzlich mit einem
  isolierten DB-Restore-Test in eine temporaere Testdatenbank geprueft.
- Der explizite Restic-Repository-Integritaetscheck (`restic check`) ist aktuell
  ein manueller bzw. periodischer Wartungscheck, kein dauerhaft verdrahteter
  Preflight. Grund: exklusiver Repository-Lock und moegliche Laufzeitwirkung.
- Backup-Freshness-Restic- und Root-Scan-Pfade sind metadata-only gehaertet und
  werden als `helper_binaries=<n>`, `python_binary=<pfad>` und
  `restic_binary=<pfad>` ausgewiesen; die erlaubten Pfade bleiben statisch zu
  pflegen, falls sich Systempfade kuenftig aendern.
- Import-Pipeline-Guard prueft Log-Aktualitaet und technische Invarianten, ersetzt
  aber keine fachliche Quellenfreigabe oder manuelle Bewertung neu importierter
  Inhalte.
- Fachliche Antworten bleiben strikt quellengebunden; freie KI-Rechtsberatung ist
  weiterhin nicht Bestandteil des Systems.
- Das Readiness-Dossier wurde am 2026-06-05 auf den finalen Backup-/Restore-
  Nachlauf nach Restic-Retention, den aktuellen `python_binary`-Restore-
  Freshness-Summary-Stand und die aktuellen Guard-/Backup-/Restore-Freshness-
  Werte abgeglichen; produktive Container wurden dafuer nicht neu gestartet.

## Standardbefehle fuer Betriebskontrolle

```bash
cd /home/chris/web/br.m11h.eu
scripts/status-br-wissen.sh
scripts/status-br-wissen.sh --image-pinning
scripts/check-project-artifacts.sh --summary
scripts/check-runtime-log-markers.sh
scripts/check-import-pipeline.py --summary
scripts/check-db-schema.py --summary
scripts/check-backup-freshness.py --summary
scripts/check-storage-permissions.py --summary
scripts/check-storage-capacity.py --summary
scripts/check-restore-freshness.py --summary
scripts/check-readiness-doc.py --summary
scripts/check-regression-freshness.py --summary
scripts/check-host-firewall-br-ports.py --summary
scripts/check-host-nft-br-ports.py --summary
scripts/check-network-policy-consistency.py --summary
scripts/check-network-policy-runtime-env.py --summary
scripts/check-python-syntax.sh
```

Manueller systemd-Healthcheck:

```bash
sudo systemctl start br-wissen-healthcheck.service
sudo systemctl status br-wissen-healthcheck.service --no-pager
```

Manuelles Backup:

```bash
sudo systemctl start br-wissen-backup.service
sudo systemctl status br-wissen-backup.service --no-pager
```

## Kurzbewertung

Der aktuelle Stand vom 2026-06-05 ist betriebsbereit fuer den geschuetzten internen Betrieb ueber
die vorgesehenen Schutzschichten. Backup, Restore-Readiness, Regressionen,
Healthcheck, Artefakt-Guard, Container-Hardening-Guard, Network-Exposure-Guard, Runtime-HTTP-Security-Guard,
App-Auth-Surface-Guard, Runtime-Log-Guard, Systemd-Unit-Guard, Image-Pinning-Guard, Import-Pipeline-Guard, Antwort-/Export-Safety-Guard,
Data-Integrity-Source-Hardening-Guard, Audit-Trail-Guard, DB-Schema-Guard, Backup-Freshness-Guard,
Storage-/Permission-Guard, Storage-/Capacity-Guard, Restore-Freshness-Guard,
Readiness-Doku-Guard, Guard-Coverage-Guard, Meta-Source-Hardening-Guard, Regression-Freshness-Guard, Host-Firewall-BR-Ports-Guard, Host-NFT-BR-Ports-Guard, Network-Policy-Consistency-Guard, Network-Policy-Runtime-Env-Guard und automatisierter
Restore-Smoke-Drill sind geprueft und dokumentiert.

## DB-Restore-Test

Aktueller automatisierter Restore-Freshness-Stand vom 2026-06-02:

- `restore_freshness_status=ok checks=20 findings=0 latest_restore_age_h=59.9 log_count=4 restore_snapshot=latest restore_dump=postgres-20260531T030249Z.sql db_restore=ok manifests=55`.
- Die folgenden DB-Restore-Abschnitte sind historische Detailnachweise; der
  aktuelle Regelbetrieb wird ueber den automatisierten Restore-Smoke-Drill und den
  Restore-Freshness-Guard ueberwacht.

Aktueller DB-Restore-Test nach Import-/Healthcheck-Haertung:

- Quelle: `postgres-20260529T202311Z.sql` aus Snapshot-/Backup-Stand
  `cda02650`.
- Ziel: temporaerer Container `br-wissen-restore-import-health-test-db` auf Basis
  `pgvector/pgvector:pg16@sha256:00ba258a66dac104fd5171074a0084462a64a1369d8513f3d0a634e2f24d15bc`.
- Isolation: `--network none`, keine publizierten Ports (`{}`).
- Container und Volume wurden nach der Pruefung entfernt.

Plausibilitaetszaehler:

- `restore_sources=298`.
- `restore_documents=298`.
- `restore_chunks=15663`.
- `restore_queries=8`.
- `restore_answers=44`.
- `restore_answer_statements=180`.
- `restore_answer_citations=180`.
- `restore_exports=35`.
- `restore_vector_extension=1`.
- `restore_recent_gelb_answer_citations=0`.
- `restore_chunk_class_mismatches=0`.

Bewertung: Der aktuelle Dump ist in eine isolierte Testdatenbank einspielbar und
liefert die erwarteten Kernzaehler. Keine Dump-Inhalte oder Secretwerte wurden
ausgegeben.

Aktueller DB-Restore-Test nach DB-Schema-/Index-Haertung:

- Quelle: `postgres-20260529T215526Z.sql` aus Snapshot-/Backup-Stand
  `76a76b62`.
- Ziel: temporaerer Container `br-wissen-restore-schema-test-db` auf Basis
  `pgvector/pgvector:pg16@sha256:00ba258a66dac104fd5171074a0084462a64a1369d8513f3d0a634e2f24d15bc`.
- Isolation: `--network none`, keine publizierten Ports (`{}`).
- Container und Volume wurden nach der Pruefung entfernt.

Plausibilitaetszaehler:

- `restore_sources=298`.
- `restore_documents=298`.
- `restore_chunks=15663`.
- `restore_queries=8`.
- `restore_answers=60`.
- `restore_answer_statements=240`.
- `restore_answer_citations=240`.
- `restore_exports=51`.
- `restore_audit_rows=112`.
- `restore_vector_extension=1`.
- `restore_expected_indexes=14`.

Bewertung: Der aktuelle Dump ist in eine isolierte Testdatenbank einspielbar und
enthält die erwartete `vector`-Extension sowie die 14 neu ergaenzten
Betriebsindexes. Keine Dump-Inhalte oder Secretwerte wurden ausgegeben.

Aktueller DB-Restore-Test nach Antwort-Atomisierung:

- Quelle: `postgres-20260529T220843Z.sql` aus Snapshot-/Backup-Stand
  `19ea9c7b`.
- Ziel: temporaerer Container `br-wissen-restore-atomic-test-db` auf Basis
  `pgvector/pgvector:pg16@sha256:00ba258a66dac104fd5171074a0084462a64a1369d8513f3d0a634e2f24d15bc`.
- Isolation: `--network none`, keine publizierten Ports (`{}`).
- Container und Volume wurden nach der Pruefung entfernt.

Plausibilitaetszaehler:

- `restore_sources=298`.
- `restore_documents=298`.
- `restore_chunks=15663`.
- `restore_queries=8`.
- `restore_answers=64`.
- `restore_answer_statements=255`.
- `restore_answer_citations=255`.
- `restore_exports=55`.
- `restore_audit_rows=120`.
- `restore_answers_without_statements=0`.
- `restore_statements_without_citation=0`.
- `restore_vector_extension=1`.

Bewertung: Der aktuelle Dump ist in eine isolierte Testdatenbank einspielbar und
enthaelt keine Antworten ohne Statements und keine Statements ohne Citation.
Keine Dump-Inhalte oder Secretwerte wurden ausgegeben.

Aktueller automatisierter DB-Restore-Test nach Restore-Smoke-Automatisierung:

- Quelle: `postgres-20260530T052803Z.sql` aus Snapshot-/Backup-Stand
  `df708ffe`.
- Ausgefuehrt mit `scripts/restore-smoke-br-wissen.sh --snapshot df708ffe --db`.
- Ziel: automatisch benannter temporaerer Container auf Basis
  `pgvector/pgvector:pg16@sha256:00ba258a66dac104fd5171074a0084462a64a1369d8513f3d0a634e2f24d15bc`.
- Isolation: `--network none`, keine publizierten Ports (`{}`).
- Container, Volume, Restore-Pfad und temporaeres DB-Log wurden automatisch
  entfernt.

Plausibilitaetszaehler:

- `restore_sources=299`.
- `restore_documents=299`.
- `restore_chunks=15708`.
- `restore_queries=8`.
- `restore_answers=64`.
- `restore_answer_statements=255`.
- `restore_answer_citations=255`.
- `restore_exports=55`.
- `restore_audit_rows=120`.
- `restore_answers_without_statements=0`.
- `restore_statements_without_citation=0`.
- `restore_vector_extension=1`.
- `restore_operational_indexes=14`.

Bewertung: Der automatisierte Restore-Smoke ersetzt die vorher fehleranfaellige
manuelle Heredoc-Pruefung und validiert Datei-/Dump-/DB-Restore reproduzierbar,
ohne Secretwerte oder Dump-Inhalte auszugeben.

Aktueller automatisierter DB-Restore-Test fuer neuesten Abschluss-Snapshot:

- Quelle: `postgres-20260530T065927Z.sql` aus Snapshot-/Backup-Stand
  `16ad8c63`.
- Ausgefuehrt mit `scripts/restore-smoke-br-wissen.sh --snapshot 16ad8c63 --db`.
- Ziel: automatisch benannter temporaerer Container auf Basis
  `pgvector/pgvector:pg16@sha256:00ba258a66dac104fd5171074a0084462a64a1369d8513f3d0a634e2f24d15bc`.
- Isolation: `--network none`, keine publizierten Ports (`{}`).
- Container, Volume, Restore-Pfad und temporaeres DB-Log wurden automatisch
  entfernt.

Plausibilitaetszaehler:

- `restore_sources=299`.
- `restore_documents=299`.
- `restore_chunks=15708`.
- `restore_queries=8`.
- `restore_answers=64`.
- `restore_answer_statements=255`.
- `restore_answer_citations=255`.
- `restore_exports=55`.
- `restore_audit_rows=120`.
- `restore_answers_without_statements=0`.
- `restore_statements_without_citation=0`.
- `restore_vector_extension=1`.
- `restore_operational_indexes=14`.

Bewertung: Auch der neueste Abschluss-Snapshot ist dateibasiert und per
isoliertem DB-Restore reproduzierbar wiederherstellbar. Keine Dump-Inhalte oder
Secretwerte wurden ausgegeben.
