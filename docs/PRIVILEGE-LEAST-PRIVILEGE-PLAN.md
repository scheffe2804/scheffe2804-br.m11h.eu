# Privilege Least-Privilege Plan

Stand: 2026-06-06T12:45:00Z

scope=br-wissen
target_user=chris
plan_status=planned
plan_owner=chris
plan_created=2026-06-06
target_due=2026-07-06
remediation_complete=0
sudoers_auto_change_allowed=0
requires_explicit_approval=1
requires_lockout_protection=1
requires_rollback_plan=1
requires_visudo_validation=1
requires_active_root_session=1
requires_secondary_ssh_session=1
requires_backup_before_change=1
requires_restore_path_awareness=1
requires_command_inventory=1
requires_staged_rollout=1
no_sudoers_contents

## Zweck

Dieses Dokument macht den Folgeauftrag fuer die Reduktion der breiten sudo-Rechte
des BR-Wissen-Betriebsnutzers `chris` konkret pruefbar. Es ist kein sudoers-
Change und enthaelt bewusst keine sudoers-Dateiinhalte, keine vollstaendigen
sudo-Kommandolisten, keine Secrets, keine Env-Werte, keine Dump-Inhalte, keine
Log-Inhalte, keine Antworttexte und keine Quelleninhalte.

## Geplanter Least-Privilege-Block

Ziel ist ein separater, explizit freizugebender Server-Haertungsblock. Vor einer
produktiven sudoers-Aenderung muessen mindestens diese Schutzpunkte vorliegen:

1. Aktueller Host-/Zielsystem-Kontext ist bestaetigt.
2. Aktive privilegierte Rettungssession oder alternativer Root-/Admin-Zugang ist
   verfuegbar.
3. Zweite SSH-Session bleibt offen, bis `sudo -n -l -U chris` und die relevanten
   Betriebsbefehle nach der Aenderung getestet sind.
4. Vorheriges BR-Wissen-Backup ist frisch und Restore-Pfad ist bekannt.
5. Benoetigte Betriebsbefehle fuer Backup, Restore-Smoke, systemd-Healthcheck,
   Docker/Compose und Guard-Laeufe sind inventarisiert.
6. Neue sudoers-Regeln werden nur in einer separaten Drop-in-Datei geplant und
   immer mit `visudo -cf` validiert.
7. Rollback-Pfad ist dokumentiert, bevor restriktive Regeln aktiviert werden.
8. Rollout erfolgt stufenweise: erst Test-Policy, dann Guard-/Backup-/Healthcheck-
   Validierung, erst danach dauerhafte Uebernahme.

## Nicht Teil dieses Blocks

- Keine automatische sudoers-Aenderung.
- Kein Entfernen bestehender sudoers-Rechte.
- Keine Ausgabe von sudoers-Inhalten oder vollstaendigen Kommandolisten.
- Keine Aenderung an Docker-, DNS-, Firewall-, TLS-, Cloudflare- oder App-
  Konfiguration.

## Faelligkeit

Der Plan wurde am `2026-06-06` angelegt und ist bis spaetestens `2026-07-06` als
eigener Least-Privilege-Haertungsblock zu reviewen oder umzusetzen. Wenn die
Faelligkeit ueberschritten wird, muss der Plan-Guard failen, damit die
Risikoakzeptanz nicht stillschweigend dauerhaft bleibt.
