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
3. **Set the classification banner** (operator-supplied PLACEHOLDER; the tool does not interpret it) and choose an output format (`console`, `json`, `markdown`, `sarif`, `oscal`):
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

## Demo

```bash
comint-osquery demos/01-failing-host/
```

Outputs are available in five formats — all respect an operator-supplied
classification banner (passed via `--classification`):

```bash
comint-osquery <target> --format=console     # default
comint-osquery <target> --format=json
comint-osquery <target> --format=sarif       # for code-scanning pipelines
comint-osquery <target> --format=markdown    # for PRs / briefings
comint-osquery <target> --format=oscal       # OSCAL Assessment Results skeleton
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

These are emitted in JSON, SARIF, and the OSCAL skeleton.

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
