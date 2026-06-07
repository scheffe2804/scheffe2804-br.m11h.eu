# Privilege Remediation Gate

scope=br-wissen
target_user=chris
gate_status=closed
remediation_gate=closed
remediation_allowed=0
actual_sudoers_change_allowed=0
sudoers_auto_change_allowed=0
remediation_complete_required_before_claim=1
accepted_risk_must_remain_visible=1
plan_status_must_remain_planned_until_change=1
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

Dieses Dokument ist ein read-only Gate zwischen der akzeptierten aktuellen
Privilege-Risikolage und einer spaeteren echten Least-Privilege-Remediation.

Der aktuelle Betriebsstand darf nicht als abgeschlossene sudoers-Haertung
interpretiert werden. Solange `gate_status=closed`, `remediation_allowed=0` und
`actual_sudoers_change_allowed=0` gelten, duerfen keine sudoers-Aenderungen aus
Routine-Guards, Backups, Healthchecks oder Doku-Nachlaeufen abgeleitet werden.

## Abgrenzung

- Das bestehende Risiko bleibt sichtbar und akzeptiert, aber nicht behoben.
- Der Least-Privilege-Plan bleibt ein Folgeplan, keine Remediation.
- Eine echte sudoers-Aenderung braucht einen separaten expliziten
  Server-Haertungsblock mit Lockout-Schutz, Rollback, visudo-Validierung,
  aktiver Root-Sitzung, zweiter SSH-Sitzung, Backup und gestaffeltem Rollout.
- Dieses Gate enthaelt und erwartet keine sudoers-Inhalte oder vollstaendigen
  sudo-Kommandolisten.
