"""Scenario 18 - end-to-end: telemetry -> posture -> enrich -> POA&M -> audit.

The whole pipeline in one run, using only the REAL API, fully offline:

  1. scan a fleet of host snapshots            (core / fleet)
  2. correlate systemic vs isolated failures   (fleet.fleet_summary)
  3. enrich findings with official NIST titles  (feeds, offline)
  4. emit the eMASS POA&M workbook              (fleet.poam_items/_to_csv)
  5. hash-chain the whole run into an audit log (cognis_mil.AuditLog)

Offline: reads bundled fixtures + the committed feed cache.
"""
import csv
import io
import tempfile
from pathlib import Path

from _common import fixture, rule, section
from comint_osquery.core import scan
from comint_osquery import fleet as fl, feeds
from cognis_mil import AuditLog


def main() -> None:
    rule("END-TO-END RMF  -  telemetry -> posture -> enrich -> POA&M -> audit")

    log = AuditLog(Path(tempfile.mkdtemp(prefix="comint_e2e_")) / "run.log")

    section("1. Scan the fleet")
    target = fixture("12-fleet-systemic")
    hosts = fl.scan_fleet(target)
    flat = scan(target)
    log.append({"step": "scan", "hosts": len(hosts), "findings": flat.total_findings()})
    print(f"  {len(hosts)} host(s), {flat.total_findings()} finding(s), "
          f"risk {flat.composite_score}/100 ({flat.risk_level})")

    section("2. Correlate blast radius")
    summ = fl.fleet_summary(hosts)
    log.append({"step": "correlate", "systemic": summ["systemic_findings"]})
    print(f"  systemic: {summ['systemic_findings']}   isolated: {summ['isolated_findings']}")

    section("3. Enrich findings (official NIST titles, offline)")
    enrich = feeds.enrich_result(flat, offline=True)
    resolved = sum(1 for i in enrich.values() if i["control_title"])
    log.append({"step": "enrich", "resolved_titles": resolved})
    print(f"  resolved {resolved}/{len(enrich)} official control titles from the OSCAL catalog")

    section("4. Emit the eMASS POA&M")
    items = fl.poam_items(hosts, office="J6 / Cyber", assessed_at=0)
    csv_text = fl.poam_to_csv(items)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    log.append({"step": "poam", "items": len(items)})
    print(f"  {len(rows)} POA&M row(s), {len(fl.POAM_COLUMNS)} eMASS columns, RFC 4180")

    section("5. Prove the run is tamper-evident")
    ok, msg = log.verify()
    print(f"  audit chain over the whole workflow: intact={ok} ({msg})")

    print("\n  One offline run produced a scored posture, an enriched crosswalk,")
    print("  an eMASS-ready POA&M, and a provable audit trail.")


if __name__ == "__main__":
    main()
