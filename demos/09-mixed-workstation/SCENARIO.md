# 09 — Mixed shared workstation (severity triage)

**Where the data came from.** A shared lab workstation. The `users` table shows
a `kiosk` account with `password_status='empty'` (someone set up auto-login the
lazy way), and a vendor application created a world-writable spool directory
owned by root. Two findings at two different severities — a good example for
practising `--fail-on` thresholds.

**What to expect.**

- `Account allows blank password` — **VERY_HIGH** — NIST `IA-5`, STIG `V-242418`,
  ATT&CK `T1078` (Valid Accounts)
- `World-writable file owned by root` — **HIGH** — NIST `AC-3`, STIG `V-238382`,
  ATT&CK `T1222.002`

**Run it — watch the gate behave by threshold.**

```bash
# Blocks (a VERY_HIGH is present):
comint-osquery demos/09-mixed-workstation/ --fail-on very_high && echo PASS || echo BLOCKED
# Also blocks (HIGH band includes VERY_HIGH):
comint-osquery demos/09-mixed-workstation/ --fail-on high && echo PASS || echo BLOCKED
# Console view of both findings:
comint-osquery demos/09-mixed-workstation/ --format console
```

**How to act.** Set a password (or disable) the `kiosk` account immediately;
tighten the spool dir to the vendor service account with `0775`/`0770`. The
blank-password account is the must-fix-now item.
