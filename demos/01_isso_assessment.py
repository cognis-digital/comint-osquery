"""Scenario 1 - ISSO / ISSM: turn host telemetry into an RMF assessment.

The ISSO's question is never "is this one setting wrong?" — it is "what is my
control posture, what's the composite risk, and can I hand an AO an OSCAL
artifact?" This demo scans an un-hardened host fixture with the REAL
``comint_osquery.core.scan`` and shows the full RMF crosswalk every finding
already carries (NIST 800-53 control + DISA STIG rule + CCI + ATT&CK technique),
then renders OSCAL 1.1.2 Assessment Results — the package an ISSO actually
uploads to eMASS.

Offline: reads the bundled ``demos/01-failing-host`` osquery snapshot fixture.
"""
import json

from _common import fixture, rule, section
from comint_osquery.core import scan
from cognis_mil import to_console, to_oscal_skeleton


def main() -> None:
    rule("ISSO / ISSM  -  host telemetry -> RMF control posture -> OSCAL")

    target = fixture("01-failing-host")
    print("\nScanning an un-hardened Ubuntu host snapshot (osquery JSON results).")
    print(f"  target: demos/01-failing-host/\n")

    result = scan(target)

    print(f"Composite risk: {result.composite_score}/100  ({result.risk_level})")
    print(f"Findings: {result.total_findings()}  over {result.items_scanned} snapshot file(s)\n")

    section("Each finding carries its full RMF crosswalk")
    print(f"  {'CAT':<10} {'NIST':<10} {'DISA STIG':<11} {'CCI':<13} {'ATT&CK':<11} Title")
    for f in result.findings:
        print(f"  {f.severity.value.upper():<10} {f.nist_800_53:<10} {f.disa_stig:<11} "
              f"{(f.cci or '-'):<13} {(f.mitre_attack or '-'):<11} {f.title}")

    section("OSCAL 1.1.2 Assessment Results (the eMASS-ingestible artifact)")
    oscal = json.loads(to_oscal_skeleton(result))
    ar = oscal["assessment-results"]
    res0 = ar["results"][0]
    print(f"  oscal-version : {ar['metadata']['oscal-version']}")
    print(f"  classification: {ar['metadata']['props'][0]['value']}")
    print(f"  observations  : {len(res0['observations'])}")
    print(f"  findings      : {len(res0['findings'])} (each target status = not-satisfied)")
    f0 = res0["findings"][0]
    print(f"  e.g. finding  : '{f0['title']}' -> control {f0['target']['target-id']} "
          f"[{f0['target']['status']['state']}]")
    print("\n  UUIDs are deterministic (uuid5), so re-scans diff cleanly in the RMF package.")

    print("\nThe ISSO now has a scored posture and an OSCAL package to attach to the SAR.")


if __name__ == "__main__":
    main()
