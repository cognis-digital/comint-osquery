# 08 — Fleet roll-up: three hosts in one scan

**Where the data came from.** A nightly osquery snapshot collector dropped one
JSON file per host into a shared directory: `host-web01.json`, `host-db02.json`,
`host-app03.json`. comint-osquery globs every `*.json` in the target directory,
so pointing it at the folder rolls the whole fleet into a single assessment.

Each finding's `location` carries the source filename, so you can tell which
host failed which check:

- **web01** — SSH root login permitted (HIGH) + world-writable root file (HIGH)
- **db02** — FIPS disabled (VERY_HIGH) + auditd down (VERY_HIGH)
- **app03** — clean

**What to expect.** `items_scanned: 3`, four findings total (two VERY_HIGH from
db02, two HIGH from web01), composite score ~51 (**Moderate** band).

**Run it.**

```bash
comint-osquery demos/08-fleet-rollup/ --format markdown
# Per-host attribution is in the CSV `location` column — ready for a tracker:
comint-osquery demos/08-fleet-rollup/ --format csv
```

**How to act.** Open POA&M items per host. db02 is the priority (crypto + audit
both down); web01's world-writable path under a webroot is an exposure worth
checking for web-shell drop. Re-scan after remediation and confirm
`items_scanned` stays at 3 with zero findings.
