# 07 — Authentication weakened: CAC/PIV off + SSH root login

**Where the data came from.** A jump host where a contractor disabled
`pam_pkcs11` to use password auth during a smartcard-middleware outage, and
`PermitRootLogin yes` was left in `sshd_config` from an earlier break-glass.
Together these collapse the identity assurance the system is supposed to
enforce: no PIV/CAC, and a directly reachable root account.

**What to expect.** Two **HIGH** findings:

- `PIV/CAC not required for authentication` — NIST `IA-2(11)`, STIG `V-238219`,
  CCI `CCI-000765`, ATT&CK `T1556` (Modify Authentication Process)
- `SSH root login permitted` — NIST `AC-6(2)`, STIG `V-238213`,
  CCI `CCI-000206`, ATT&CK `T1021.004` (Remote Services: SSH)

**Run it.**

```bash
comint-osquery demos/07-smartcard-bypass/ --format sarif --out /tmp/jump.sarif
comint-osquery demos/07-smartcard-bypass/ --fail-on high && echo PASS || echo "BLOCKED (expected)"
```

**How to act.** Restore `pam_pkcs11` enforcement, set `PermitRootLogin no`,
restart `sshd`, and review auth logs for any password-based root logins during
the window the controls were down.
