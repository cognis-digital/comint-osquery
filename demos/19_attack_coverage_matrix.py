"""Scenario 19 - purple team: map the STIG pack onto the ATT&CK matrix.

The SOC wants to know which adversary behaviours the STIG pack actually covers.
This demo reads the REAL ``core.STIG_PACK`` metadata and builds an ATT&CK
coverage matrix: technique -> the weak configs that enable it -> the NIST/STIG
controls -> severity, then lists the distinct tactics/techniques the pack lands
detections on. No fabricated techniques — every id comes from the shipped pack.

Offline: pure metadata, no fixtures.
"""
from collections import defaultdict

from _common import rule, section
from comint_osquery.core import STIG_PACK


def main() -> None:
    rule("PURPLE TEAM  -  STIG pack -> ATT&CK coverage matrix")

    by_tech = defaultdict(list)
    for name, cfg in STIG_PACK.items():
        by_tech[cfg["attack"]].append((name, cfg))

    section("Technique <- the weak config that enables it")
    print(f"  {'ATT&CK':<12} {'Severity':<11} {'NIST':<10} Query")
    for tech in sorted(by_tech):
        for name, cfg in by_tech[tech]:
            print(f"  {tech:<12} {cfg['severity'].value.upper():<11} "
                  f"{cfg['nist']:<10} {name}")

    section("Coverage summary")
    techniques = sorted(by_tech)
    subtechs = [t for t in techniques if "." in t]
    print(f"  distinct techniques covered : {len(techniques)}")
    print(f"    of which sub-techniques    : {len(subtechs)}")
    print(f"  queries in the pack          : {len(STIG_PACK)}")
    # techniques that more than one query lands on
    multi = {t: v for t, v in by_tech.items() if len(v) > 1}
    if multi:
        print(f"  techniques with >1 query     : {sorted(multi)}")

    print(f"\n  Techniques: {', '.join(techniques)}")
    print("  Each failing query row becomes a detection the SOC can pivot on.")


if __name__ == "__main__":
    main()
