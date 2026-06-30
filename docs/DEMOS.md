# Demos

The `demos/` directory bundles two things:

* **Fixture scenarios** — `demos/<NN-name>/` directories holding osquery snapshot
  JSON in the tool's real input shape (`{query_name: [failing rows…]}`) plus a
  `SCENARIO.md`. These are the offline data the runnable demos feed in.
* **Runnable scenarios** — `demos/NN_name.py` scripts that drive the **real**
  `comint_osquery` / `cognis_mil` API over those fixtures, with narrated output.
  No network, no fabricated functions, every scenario exits 0.

```bash
python demos/run_all.py            # all five, narrated, offline
python demos/03_sysadmin_fleet.py  # or just one
```

Each runnable scenario is independent and self-contained: `demos/_common.py`
points `COGNIS_FEEDS_CACHE` at the committed `tests/fixtures/feeds-cache`, so
feed enrichment works fully offline. Run with `PYTHONUTF8=1` on Windows so the
report glyphs render. The scenarios double as smoke tests —
`tests/test_demo_scenarios.py` executes every one under `pytest`.

## Audience map

| # | Scenario | Audience | What it shows | Real API |
|---|----------|----------|---------------|----------|
| 1 | `01_isso_assessment.py` | **ISSO / ISSM** | Scan a host → composite risk + full RMF crosswalk (NIST/STIG/CCI/ATT&CK) → OSCAL 1.1.2 Assessment Results for eMASS | `core.scan`, `cognis_mil.to_oscal_skeleton` |
| 2 | `02_soc_detection.py` | **SOC / endpoint detection engineering** | Emit the scheduled osquery STIG pack; map every query to the ATT&CK technique the weak config enables | `core.emit_query_pack`, `core.STIG_PACK` |
| 3 | `03_sysadmin_fleet.py` | **Sysadmins / DevSecOps** | Correlate a 3-host fleet into systemic vs isolated; auto-pick a golden baseline; report per-host drift | `fleet.scan_fleet`, `fleet.fleet_summary`, `fleet.pick_baseline`, `fleet.baseline_drift` |
| 4 | `04_auditor_poam.py` | **Auditors / assessors** | Build an eMASS POA&M workbook (CAT level, STIG/CCI, scheduled completion); make the assessment tamper-evident and prove the chain catches an edit | `fleet.poam_items`, `fleet.poam_to_csv`, `cognis_mil.AuditLog` |
| 5 | `05_airgap_enrichment.py` | **Edge / air-gap operators** | Resolve official NIST control titles and expand ATT&CK → CTID countermeasure controls, fully offline from the cached feed snapshot | `feeds.enrich_result` (`offline=True`) |

## 1. ISSO / ISSM — *posture, not a setting*
The ISSO question is "what is my control posture and can I hand the AO an
artifact?" The demo scores an un-hardened host, prints the RMF crosswalk each
finding already carries, and renders an OSCAL SAR with deterministic UUIDs.

## 2. SOC / endpoint — *schedule it, map it to ATT&CK*
A SOC wants the pack loaded into the fleet agent so weak configs surface
continuously, and every query landing on the right ATT&CK technique. The demo
emits the real YAML pack and prints the technique coverage from the pack
metadata.

## 3. Sysadmins / DevSecOps — *fix the image, not the host*
One host failing is a ticket; the same control failing on every host is a broken
golden image. The demo correlates a fleet, flags the **systemic** finding,
auto-selects the cleanest baseline, and reports per-host regressions.

## 4. Auditors / assessors — *the workbook and the proof*
The artifact an auditor lives by is the POA&M. The demo builds the eMASS columns
one row per (weakness, asset), then hash-chains the assessment and tampers with
one row to show `verify()` catching the edit.

## 5. Edge / air-gap — *enrichment without a network*
On disconnected gear, findings still resolve to official NIST titles and expand
into CTID countermeasure sets — served from a cached feed snapshot carried across
the air gap, never the network.
