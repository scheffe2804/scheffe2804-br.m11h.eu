# Privilege No-Sudoers-Change Policy

scope=br-wissen
target_user=chris
policy_status=active
sudoers_change_policy=forbidden
sudoers_changes_allowed=0
sudoers_remediation_requested=0
sudoers_auto_change_allowed=0
actual_sudoers_change_allowed=0
remediation_complete=0
accepted_risk_continues=1
least_privilege_planning_only=1
requires_new_explicit_user_request_before_sudoers_change=1
no_sudoers_contents

## Zweck

Dieses Dokument haelt die Nutzerentscheidung fest: Fuer BR-Wissen sollen keine
sudoers-Aenderungen vorgenommen werden. Die bestehenden breiten sudo-Rechte werden
weiter als bewusst akzeptiertes Risiko sichtbar gemacht, aber nicht durch diesen
Arbeitsstrang geaendert.

## Wirkung

- Keine Drop-in-Dateien unter `/etc/sudoers.d/` fuer diesen Arbeitsstrang.
- Kein Entfernen oder Einschraenken bestehender sudoers-Rechte.
- Kein `visudo`-Rollout und keine Aktivierung einer Candidate-Policy.
- Weitere Arbeiten bleiben auf read-only Guards, Dokumentation, Backup/Restore,
  Healthchecks, Sichtbarkeit und Betriebsstabilitaet begrenzt.
- Eine spaetere sudoers-Aenderung waere nur nach neuer, ausdruecklicher,
  anderslautender Nutzerentscheidung ausserhalb dieser Policy zulaessig.
