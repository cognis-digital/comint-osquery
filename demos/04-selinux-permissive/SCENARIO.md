# 04 — Defenses impaired: SELinux permissive + auditd flapping

**Where the data came from.** An app team set SELinux to `permissive` "to get
the deployment working" and, in the same change window, the `auditd` process
crashed and was not restarted. This is the classic *defense-evasion combo*: the
mandatory-access-control enforcement is off **and** the audit trail is gone, so
neither prevention nor detection is in place.

> Note on the `audit_daemon_not_running` row: in the comint demo shape, a
> populated row for this query represents the *failing* condition (the watcher
> reported auditd absent from the expected running set).

**What to expect.** Two findings, both tied to ATT&CK `T1562.001` (Impair
Defenses: Disable or Modify Tools):

- `auditd not running` — **VERY_HIGH** — NIST `AU-3`, STIG `V-238201`
- `SELinux not in enforcing mode` — **HIGH** — NIST `AC-6`, STIG `V-238311`

**Run it.**

```bash
comint-osquery demos/04-selinux-permissive/ --format console
# See the shared ATT&CK technique surface in the CSV export:
comint-osquery demos/04-selinux-permissive/ --format csv
```

**How to act.** `setenforce 1` and persist `SELINUX=enforcing` in
`/etc/selinux/config`; `systemctl enable --now auditd`. Then hunt: a host that
sat permissive with no audit log is a candidate for retrospective compromise
review.
