# Demos

The `demos/` directory bundles two things:

* **Fixture scenarios** — `demos/<NN-name>/` directories holding osquery snapshot
  JSON in the tool's real input shape (`{query_name: [failing rows…]}`) plus a
  `SCENARIO.md`. These are the offline data the runnable demos feed in.
* **Runnable scenarios** — `demos/NN_name.py` scripts that drive the **real**
  `comint_osquery` / `cognis_mil` API over those fixtures, with narrated output.
  No network, no fabricated functions, every scenario exits 0.

```bash
python demos/run_all.py            # all twenty, narrated, offline
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
| 6 | `06_multiformat_export.py` | **GRC engineer** | One scan rendered in all six exporters (JSON/SARIF/Markdown/CSV/OSCAL/console); each proven well-formed | `core.scan`, all `cognis_mil.exporters` |
| 7 | `07_parse_error_handling.py` | **Reliability engineer** | Truncated/empty/bare-list osquery files are surfaced as explicit diagnostics, never a silent clean pass | `core.scan`, `fleet.scan_host` |
| 8 | `08_pack_deployment.py` | **Fleet engineer** | Emit the osquery STIG pack to disk and validate every query/interval/snapshot survived the round-trip | `core.emit_query_pack` |
| 9 | `09_fleet_json_export.py` | **ConMon pipeline** | Fleet summary + drift serialised as machine JSON; pull out the systemic/drift/coverage signals a pipeline gates on | `fleet.fleet_summary`, `fleet.baseline_drift` |
| 10 | `10_poam_json.py` | **Assessor** | POA&M as JSON with per-asset item numbering (`web01-001`, `db02-001`) | `fleet.poam_items`, `fleet.poam_to_json` |
| 11 | `11_classification_banner.py` | **Security officer** | Build/validate CAPCO-shape banners; validator rejects impossible markings (all placeholders) | `cognis_mil.ClassificationBanner` |
| 12 | `12_airgap_snapshot.py` | **Air-gap logistics** | Export the feed cache to a tarball, import into a fresh cache, resolve a title offline — the sneakernet round-trip | `datafeeds.snapshot_export/import` |
| 13 | `13_countermeasure_expansion.py` | **Detection engineer** | Expand each finding's single STIG control into the full CTID countermeasure set (defense-in-depth) | `feeds.enrich_result` |
| 14 | `14_audit_chain.py` | **IG / oversight** | Hash-chained audit trail catches three distinct tampers (edit/delete/reorder) | `cognis_mil.AuditLog` |
| 15 | `15_fail_on_gating.py` | **CI/CD gate** | Exit-code matrix per (target, `--fail-on` threshold) — which findings break the build | `core.scan`, `Severity` |
| 16 | `16_control_titles.py` | **RMF author** | Resolve bare control ids (incl. enhancement notation) to official NIST 800-53 titles from the OSCAL catalog | `feeds.control_titles`, `feeds.resolve_control_title` |
| 17 | `17_drift_regression.py` | **Config management** | Separate regressions (worse than golden) from improvements (ahead of golden) across a synthetic fleet | `fleet.baseline_drift` |
| 18 | `18_full_rmf_workflow.py` | **End-to-end** | scan → correlate → enrich → POA&M → hash-chained audit, in one offline run | full API |
| 19 | `19_attack_coverage_matrix.py` | **Purple team** | Map the STIG pack onto the ATT&CK matrix; count distinct techniques/sub-techniques covered | `core.STIG_PACK` |
| 20 | `20_connect_emit.py` | **SOC integration** | Forward findings to STIX/Sigma via the `cognis-connect` bridge (dry run; degrades gracefully if extra absent) | `comint_osquery.connect` |

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

## 6–20. Extended scenarios

Scenarios 6–20 go deeper on each surface of the tool: every export format
(6), malformed-input hardening (7), pack deployment (8), machine-JSON fleet
posture for a ConMon pipeline (9), JSON POA&M with per-asset numbering (10),
CAPCO-shape banner validation (11), the air-gap snapshot round-trip (12),
ATT&CK→CTID countermeasure expansion (13), a three-tamper audit-chain proof
(14), a CI/CD `--fail-on` gating matrix (15), official NIST title resolution
(16), baseline-drift regressions vs improvements (17), the full end-to-end RMF
workflow (18), an ATT&CK coverage matrix (19), and the downstream
`cognis-connect` emit bridge (20). All are offline, exit 0, and double as smoke
tests via `tests/test_demo_scenarios.py` and `tests/test_demo_output.py`.
