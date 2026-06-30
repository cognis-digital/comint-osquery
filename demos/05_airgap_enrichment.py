"""Scenario 5 - edge / air-gap operators: enrich findings fully offline.

On disconnected gear you still want a finding's bare control id resolved to its
*official* NIST 800-53 title, and its single STIG-mapped ATT&CK technique
expanded into the full CTID-recommended countermeasure control set
(defense-in-depth for the RMF package). This demo runs the REAL
``comint_osquery.feeds`` enrichment with ``offline=True`` against the committed
fixture feed cache — exactly the sneakernet workflow: the cache was carried
across the air gap, and nothing here touches the network.

Offline: ``_common`` points ``COGNIS_FEEDS_CACHE`` at ``tests/fixtures/feeds-cache``
(trimmed OSCAL 800-53 rev5 catalog + CTID ATT&CK<->800-53 crosswalk).
"""
from _common import fixture, rule, section
from comint_osquery.core import scan
from comint_osquery import feeds


def main() -> None:
    rule("EDGE / AIR-GAP  -  offline feed enrichment (official titles + countermeasures)")

    print("\n  Feed cache served offline (no network) — the sneakernet posture.")

    result = scan(fixture("01-failing-host"))
    print(f"  scanned demos/01-failing-host/ -> {result.total_findings()} finding(s)\n")

    section("Enrich each finding from the authoritative feeds")
    summary = feeds.enrich_result(result, offline=True)
    for fid, info in summary.items():
        title = info["control_title"] or "(unresolved)"
        cms = info["attack_countermeasures"]
        print(f"  {fid}")
        print(f"      NIST {info['nist_800_53']:<8} -> {title}")
        if info["mitre_attack"]:
            head = ", ".join(cms[:6]) + (f"  (+{len(cms) - 6} more)" if len(cms) > 6 else "")
            print(f"      ATT&CK {info['mitre_attack']:<10} -> {len(cms)} countermeasure control(s): {head}")

    resolved = sum(1 for i in summary.values() if i["control_title"])
    print(f"\n  {resolved}/{len(summary)} control titles resolved from the OSCAL catalog, offline.")
    print("  Every finding now carries its official NIST title and a defense-in-depth set.")


if __name__ == "__main__":
    main()
