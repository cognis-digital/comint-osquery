# 06 — Audit accountability gap (auditd down)

**Where the data came from.** A long-lived bastion host where `auditd` was
stopped during a noisy log-storage incident and never re-enabled. Everything
else on the box still passes, but with the audit daemon down the system has lost
its accountability record — a standalone AU-family failure that auditors treat
as serious on its own.

**What to expect.** A single **VERY_HIGH** finding (`audit_daemon_not_running`,
NIST `AU-3`, STIG `V-238201`, ATT&CK `T1562.001`).

**Run it.**

```bash
comint-osquery demos/06-no-auditd/ --classification "CUI//SP-PRVCY" --format markdown
```

Note the operator-supplied banner flows through to the report header verbatim —
the tool never interprets or validates the marking.

**How to act.** `systemctl enable --now auditd`, confirm rules reload
(`auditctl -l`), and check for a gap in the audit timeline that needs to be
documented in the system's POA&M.
