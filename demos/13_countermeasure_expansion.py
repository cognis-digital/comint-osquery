"""Scenario 13 - detection engineer: expand one STIG control into defense-in-depth.

Each STIG finding maps to a single NIST control, but the ATT&CK technique the
weak config enables usually has a *set* of CTID-recommended countermeasure
controls. This demo runs the REAL ``feeds`` layer offline to turn every
finding's single ATT&CK technique into the full CTID control set — the
defense-in-depth coverage an RMF package should reflect, not just the one STIG
line.

Offline: served from the committed fixture feed cache.
"""
from _common import fixture, rule, section
from comint_osquery.core import scan
from comint_osquery import feeds


def main() -> None:
    rule("DETECTION ENGINEER  -  one STIG control -> CTID countermeasure set")

    result = scan(fixture("01-failing-host"))
    summary = feeds.enrich_result(result, offline=True)

    section("STIG control (1) vs CTID countermeasure controls (N) per finding")
    print(f"  {'Finding':<28} {'STIG ctrl':<10} {'ATT&CK':<11} #CTID controls")
    total_stig, total_cms = 0, 0
    for fid, info in summary.items():
        n = len(info["attack_countermeasures"])
        total_stig += 1
        total_cms += n
        print(f"  {fid:<28} {info['nist_800_53']:<10} "
              f"{(info['mitre_attack'] or '-'):<11} {n}")

    section("Defense-in-depth delta")
    print(f"  STIG controls flagged directly       : {total_stig}")
    print(f"  CTID countermeasure controls (total) : {total_cms}")
    print(f"  expansion factor                     : "
          f"{(total_cms / total_stig):.1f}x" if total_stig else "  n/a")

    # show the biggest expansion in detail
    biggest = max(summary.items(), key=lambda kv: len(kv[1]["attack_countermeasures"]))
    fid, info = biggest
    print(f"\n  e.g. {fid} ({info['mitre_attack']}) ->")
    print(f"       {', '.join(info['attack_countermeasures'])}")

    print("\n  The RMF package should reflect the full set, not just the one STIG line.")


if __name__ == "__main__":
    main()
