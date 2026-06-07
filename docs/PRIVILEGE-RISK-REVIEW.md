# Privilege Risk Review

Stand: 2026-06-06T11:24:00Z

scope=br-wissen
target_user=chris
risk_acceptance_status=accepted
review_cadence=monthly
last_review_date=2026-06-06
next_review_due=2026-07-06
least_privilege_followup=required
sudoers_auto_change_allowed=0
no_sudoers_contents

## Zweck

Dieses Dokument haelt die bewusste, vorlaeufige Risikoakzeptanz fuer breite
sudo-Rechte des BR-Wissen-Betriebsnutzers `chris` fest. Es enthaelt bewusst keine
sudoers-Dateiinhalte, keine vollstaendigen sudo-Kommandolisten, keine Secrets,
keine Env-Werte, keine Dump-Inhalte, keine Log-Inhalte, keine Antworttexte und
keine Quelleninhalte.

## Aktueller Risikomarker

- `broad_sudo=1` ist aktuell bekannt und wird durch den Privilege-Policy-Guard
  sichtbar gemacht.
- `nopasswd_all=1` und `unrestricted_all=1` sind als aggregierte Risiko-Marker
  bekannt.
- Diese Marker werden im BR-Wissen-Kontext nicht failend gewertet, weil eine
  automatische Einschraenkung der globalen sudoers-Konfiguration ein eigenes
  Lockout-/Workflow-Risiko haette.

## Akzeptanz und Folgeauftrag

- Die Risikoakzeptanz gilt nur fuer den aktuellen BR-Wissen-Guardrail-Kontext.
- Eine echte Least-Privilege-Umstellung der sudoers-Konfiguration bleibt ein
  separater, explizit freizugebender Server-Haertungsblock.
- Bei diesem Folgeblock muessen Lockout-Schutz, Rollback-Pfad, benoetigte
  Betriebsbefehle, Backup-/Restore-Pfade und SSH-/sudo-Zugriff separat geplant
  werden.
- Bis dahin muss der Zustand regelmaessig erneut geprueft und im Projektprotokoll
  nachvollziehbar bleiben.
- Der aktuelle Review ist am `2026-06-06` dokumentiert; der naechste Review ist
  spaetestens am `2026-07-06` faellig.

## Keine automatische sudoers-Aenderung

Der BR-Wissen-Guardrail-Lauf darf die globale sudoers-Konfiguration nicht
automatisch aendern. Der Review-Guard prueft nur Marker und aggregierte
Statuswerte; er schreibt keine sudoers-Dateien, ruft keine mutierenden
Systembefehle auf und gibt keine sensiblen Inhalte aus.
