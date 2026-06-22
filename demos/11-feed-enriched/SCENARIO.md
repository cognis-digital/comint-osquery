# Demo 11 — feed-enriched findings (offline)

Takes the `01-failing-host` osquery results and enriches each STIG finding with
**authoritative public feed data**, served entirely from the committed offline
cache (no network):

- **NIST SP 800-53 rev5 OSCAL catalog** — resolves each finding's bare control
  id to its official NIST title (e.g. `SC-13` -> "Cryptographic Protection",
  `IA-5` -> "Authenticator Management").
- **CTID ATT&CK <-> NIST 800-53 mappings** — expands each finding's single
  STIG-mapped ATT&CK technique into the full set of countermeasure controls the
  Center for Threat-Informed Defense recommends (defense-in-depth coverage for
  an RMF package).

## Reproduce (offline)

```bash
export COGNIS_FEEDS_CACHE="$PWD/tests/fixtures/feeds-cache"   # committed sample cache
comint-osquery feeds enrich demos/01-failing-host --offline
```

Output is captured in [`enriched.json`](enriched.json). Each finding gains a
real `control_title` and an `attack_countermeasures` control list — both sourced
from the live feeds, cached for air-gapped operation.

## Live refresh

```bash
comint-osquery feeds update          # fetch both feeds -> cache
comint-osquery feeds snapshot-export feeds.tar.gz   # sneakernet to the air gap
```
