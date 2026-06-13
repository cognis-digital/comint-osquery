# comint-osquery — STIG-aligned host telemetry on osquery

[![CI](https://github.com/cognis-digital/comint-osquery/workflows/CI/badge.svg)](https://github.com/cognis-digital/comint-osquery/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> DISA STIG query pack + RMF mapper. Cognis additions sit on top of unmodified osquery.

<!-- cognis:layman:start -->
## What is this?

comint-osquery is a command-line tool that checks a Linux server or workstation for common security misconfigurations required by the U.S. Department of Defense. It reads the results produced by osquery — a free host-monitoring agent — and flags problems like disabled FIPS encryption, SSH root login being allowed, or the audit daemon not running. The tool produces reports in plain text, JSON, or machine-readable formats (SARIF, OSCAL) that can feed directly into compliance tracking systems like eMASS or Xacta. It is intended for system administrators and security engineers working in military or government environments who need to verify DISA STIG compliance quickly and automatically.
<!-- cognis:layman:end -->

## Upstream

Forks / wraps **https://github.com/osquery/osquery**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- 8 (and growing) DISA STIG queries as an osquery pack
- Result mapper translates raw osquery rows → NIST/STIG/ATT&CK findings
- OSCAL Assessment Results emitter for eMASS/Xacta import

<!-- cognis:install:start -->
## Install

`comint-osquery` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/comint-osquery/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/comint-osquery/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/comint-osquery.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/comint-osquery.git"  # uv
pip install "git+https://github.com/cognis-digital/comint-osquery.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/comint-osquery.git
cd comint-osquery && pip install .
```

Then run:
```sh
comint-osquery --help
```
<!-- cognis:install:end -->

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
    pip install "git+https://github.com/cognis-digital/comint-osquery.git"
    comint-osquery . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).
