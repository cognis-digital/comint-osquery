"""Scenario 2 - SOC / endpoint detection engineering: ship the osquery pack.

A SOC doesn't want a one-off scan — it wants the *scheduled* query pack loaded
into the osquery fleet agent so the weak configs surface continuously, and it
wants every query mapped to the MITRE ATT&CK technique the weak config enables,
so the detection lands in the right place on the ATT&CK matrix.

This demo emits the REAL osquery YAML pack with ``core.emit_query_pack`` and
prints the ATT&CK coverage the ``STIG_PACK`` provides — straight from the
shipped pack metadata, no fabricated techniques.

Offline: no network, no files written (pack is returned as a string).
"""
from collections import defaultdict

from _common import rule, section
from comint_osquery.core import STIG_PACK, emit_query_pack


def main() -> None:
    rule("SOC / ENDPOINT  -  schedule the pack, map every query to ATT&CK")

    section("osquery scheduled-query pack (load into the fleet agent)")
    pack = emit_query_pack()
    # show the header + the first scheduled query so the shape is concrete
    shown = 0
    for line in pack.splitlines():
        print("  " + line)
        if line.strip().startswith("snapshot:"):
            shown += 1
        if shown >= 2:
            print("  ...")
            break
    print(f"\n  {len(STIG_PACK)} STIG-aligned queries, interval=3600s, snapshot mode.")
    print("  Load with: osqueryi --config_path=stig_pack.yaml")

    section("ATT&CK coverage  (technique <- the weak config that enables it)")
    by_tech = defaultdict(list)
    for name, cfg in STIG_PACK.items():
        by_tech[cfg.get("attack", "")].append((name, cfg))
    for tech in sorted(by_tech):
        rows = by_tech[tech]
        cfg0 = rows[0][1]
        print(f"  {tech:<12} {cfg0['severity'].value.upper():<10} "
              f"({len(rows)} query/queries)")
        for name, cfg in rows:
            print(f"      - {name}  [{cfg['nist']} / {cfg['stig']}]")

    techniques = sorted({c['attack'] for c in STIG_PACK.values() if c.get('attack')})
    print(f"\n  {len(techniques)} distinct ATT&CK techniques covered: {', '.join(techniques)}")
    print("\n  Failing rows from these queries become detections the SOC can pivot on.")


if __name__ == "__main__":
    main()
