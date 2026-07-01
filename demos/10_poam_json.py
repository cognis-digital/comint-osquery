"""Scenario 10 - assessor: POA&M as JSON, per-host item numbering.

Some GRC tools ingest the POA&M as JSON rather than the eMASS CSV. This demo
builds the REAL ``fleet.poam_items`` for a multi-host fleet, serialises with
``fleet.poam_to_json``, and highlights that item IDs are numbered *per asset*
(``web01-001``, ``db02-001``) — the numbering an eMASS reviewer expects, and the
behaviour a recent fix corrected (a global counter used to make the first item
on a second host read ``-003``).

Offline: reads the bundled ``demos/08-fleet-rollup`` snapshots.
"""
import json
from collections import defaultdict

from _common import fixture, rule, section
from comint_osquery import fleet as fl


def main() -> None:
    rule("ASSESSOR  -  POA&M as JSON with per-asset item numbering")

    hosts = fl.scan_fleet(fixture("08-fleet-rollup"))
    items = fl.poam_items(hosts, office="J6 / Cyber", assessed_at=0)

    blob = fl.poam_to_json(items)
    data = json.loads(blob)
    print(f"\n  {data['count']} POA&M item(s) serialised as JSON")

    section("Item IDs reset per affected asset")
    by_asset = defaultdict(list)
    for it in data["poam_items"]:
        by_asset[it["Affected Asset"]].append(it["POA&M Item ID"])
    for asset in sorted(by_asset):
        print(f"  {asset:<8} -> {by_asset[asset]}")

    section("CAT level + scheduled completion derive from severity")
    for it in data["poam_items"]:
        print(f"  {it['POA&M Item ID']:<10} {it['Raw Severity']:<7} "
              f"{it['Security Control Number (NC/NA)']:<9} "
              f"due {it['Scheduled Completion Date']}")

    print("\n  CAT I (very-high) gets the shortest remediation window; every row")
    print("  is one (weakness, asset) pair, ready for eMASS import.")


if __name__ == "__main__":
    main()
