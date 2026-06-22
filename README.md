# comint-osquery — STIG-aligned host telemetry on osquery

[![CI](https://github.com/cognis-digital/comint-osquery/workflows/CI/badge.svg)](https://github.com/cognis-digital/comint-osquery/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> DISA STIG query pack + RMF mapper. Cognis additions sit on top of unmodified osquery.

## Usage — step by step

1. **Install** the shared library once for the ecosystem, then this tool's `comint-osquery` command:
   ```bash
   pip install cognis-mil      # shared library (once)
   pip install -e .            # this tool
   ```
2. **Run a scan** of STIG-aligned host telemetry — the positional `target` is a path (defaults to `.`):
   ```bash
   comint-osquery .
   ```
3. **Set the classification banner** (operator-supplied PLACEHOLDER; the tool does not interpret it) and choose an output format (`console`, `json`, `markdown`, `sarif`, `oscal`, `csv`):
   ```bash
   comint-osquery . --classification "UNCLASSIFIED//FOR PUBLIC RELEASE" --format json
   ```
4. **Write the report to a file** for review or evidence:
   ```bash
   comint-osquery . --format oscal --out comint.oscal.json
   ```
5. **Gate CI / RMF pipelines** with `--fail-on` (`very_high|high|moderate|low|none`), which exits `1` when a finding meets that severity:
   ```yaml
   - run: pip install cognis-mil && pip install -e .
   - run: comint-osquery . --fail-on high --format sarif --out comint.sarif
   ```

## Upstream

Forks / wraps **https://github.com/osquery/osquery**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- 8 (and growing) DISA STIG queries as an osquery pack
- Result mapper translates raw osquery rows → NIST/STIG/ATT&CK findings
- OSCAL Assessment Results emitter for eMASS/Xacta import

## Install

```bash
# Shared library (only once for the whole ecosystem):
pip install -e ../../shared

# This tool:
pip install -e .
```

## Demos — real-use-case library

Each `demos/<NN-name>/` holds osquery snapshot JSON in the tool's real input
shape (`{query_name: [failing rows…]}`) plus a `SCENARIO.md` that explains where
the data came from, the exact run command, and how to act on the result.

| Demo | Scenario | Outcome |
|------|----------|---------|
| `01-failing-host` | Un-hardened Ubuntu host | 4 findings, mixed severity |
| `02-clean-baseline` | Hardened RHEL 9 golden image | 0 findings — CI baseline |
| `03-fips-violation` | FIPS 140 disabled after kernel update | 1 VERY_HIGH (crypto) |
| `04-selinux-permissive` | SELinux permissive + auditd down | 2 findings, both `T1562.001` |
| `05-unsigned-kmod` | Unsigned DKMS modules on Secure Boot | 1 HIGH (`T1547.006`) |
| `06-no-auditd` | Audit accountability gap | 1 VERY_HIGH (`AU-3`) |
| `07-smartcard-bypass` | CAC/PIV off + SSH root login | 2 HIGH auth findings |
| `08-fleet-rollup` | 3 hosts, one folder, one scan | 4 findings, per-host attribution |
| `09-mixed-workstation` | Blank-password kiosk + world-writable dir | severity-triage / `--fail-on` |
| `10-parse-error` | Truncated snapshot | graceful LOW `CO-PARSE`, no crash |

```bash
comint-osquery demos/01-failing-host/
comint-osquery demos/08-fleet-rollup/ --format markdown   # roll a fleet up
```

Outputs are available in **six** formats — all respect an operator-supplied
classification banner (passed via `--classification`):

```bash
comint-osquery <target> --format=console     # default
comint-osquery <target> --format=json
comint-osquery <target> --format=sarif       # for code-scanning pipelines
comint-osquery <target> --format=markdown    # for PRs / briefings
comint-osquery <target> --format=oscal       # OSCAL 1.1.2 Assessment Results
comint-osquery <target> --format=csv         # flat POA&M / spreadsheet import
```

## Classification banner

All output is wrapped with an operator-supplied classification banner.
**Default**: `UNCLASSIFIED//FOR PUBLIC RELEASE`.

> ⚠️ This tool **does not** generate or validate the *content* of higher
> classifications. Operators on cleared systems supply real markings at runtime.
> See [`../shared/cognis_mil/classmark.py`](../../shared/cognis_mil/classmark.py).

## Compliance crosswalks (built in)

Every finding can carry references to:
- **NIST 800-53 Rev 5** controls (e.g. `AC-2(1)`)
- **DISA STIG** rule IDs (e.g. `V-242414`)
- **MITRE ATT&CK** technique IDs (e.g. `T1078`)
- **CCI** (Control Correlation Identifier)

Every query in the STIG pack now ships a published **MITRE ATT&CK Enterprise**
technique describing the adversary behaviour the failing configuration would
enable (e.g. SSH root login → `T1021.004`, FIPS disabled → `T1600`, auditd/SELinux
off → `T1562.001`) for blue-team detection-engineering and RMF crosswalks.

These are emitted in JSON, SARIF, CSV, and the OSCAL Assessment Results.

## CI / RMF integration

```yaml
- name: comint-osquery scan
  run: |
    pip install cognis-comint-osquery
    comint-osquery . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).

## Interoperability

`comint-osquery` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `comint-osquery`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.
