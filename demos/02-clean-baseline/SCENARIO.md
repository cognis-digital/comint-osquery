# 02 — Hardened RHEL 9 baseline (clean)

**Where the data came from.** A freshly imaged RHEL 9 host built from the
DISA-aligned hardening role (CAC/PIV enforced, FIPS on, SELinux enforcing,
auditd running). The `osqueryi` snapshot ran the full comint STIG pack; every
query returned **zero rows**, which is the *passing* condition for each check.

```json
{ "fips_not_enforced": [], "selinux_not_enforcing": [], ... }
```

An empty array means "no failing rows were found" — i.e. the control is
satisfied. This is the shape your CI baseline should produce on a clean build.

**What to expect.** No findings, composite score `0.0`, risk level `Very Low`.

**Run it.**

```bash
comint-osquery demos/02-clean-baseline/ --format console
# Gate a build pipeline — exit 0 because nothing fails:
comint-osquery demos/02-clean-baseline/ --fail-on high
```

**How to act.** Promote the image. Use this directory as the golden-baseline
regression fixture: if a future scan of the same image starts producing
findings, configuration drift has occurred.
