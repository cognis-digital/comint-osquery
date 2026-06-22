# 12 — Fleet correlation: a systemic finding (broken golden image)

**Where the data came from.** Three edge nodes (`edge01`, `edge02`, `edge03`)
provisioned from the *same* golden image / Ansible role were snapshotted by the
nightly osquery collector. The image shipped with FIPS 140 mode disabled.

**The point of this scenario.** The default scan flattens these three files into
one composite score and you would see "FIPS disabled" three times in a flat list
— easy to read as three independent tickets. The **fleet** subcommand instead
*correlates across hosts*: because `fips_not_enforced` fails on **every** scanned
host, it is flagged `systemic`. That is the tell of a broken golden image / GPO /
config-management role — you fix it **once at the source**, not three times in
the field.

The host-specific extras (`edge01` permits SSH root login; `edge02` has auditd
down) are flagged `isolated` — those are genuine per-host tickets.

**Run it.**

```bash
# Correlate: separate systemic from isolated.
comint-osquery fleet demos/12-fleet-systemic/

# Machine-readable for a dashboard / continuous-monitoring pipe:
comint-osquery fleet demos/12-fleet-systemic/ --format json

# Turn the fleet into an eMASS-importable POA&M workbook:
comint-osquery poam demos/12-fleet-systemic/ --office "J6/CYBER" --format csv
```

**What to expect.** `SC-13` (Cryptographic Protection) reported as **systemic**
across all three hosts; `AC-6(2)` and `AU-3` reported as **isolated**. The POA&M
emits one row per (control, host): five rows total, each CAT-leveled with a
severity-driven scheduled-completion date.

**How to act.** Re-bake the golden image with FIPS enabled and the systemic line
disappears fleet-wide on the next snapshot. Open isolated POA&M items for the
two field-specific weaknesses.
