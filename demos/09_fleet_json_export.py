"""Scenario 9 - continuous-monitoring pipeline: fleet posture as machine JSON.

A ConMon pipeline doesn't read console banners — it ingests structured JSON and
alerts on it. This demo drives the REAL ``fleet`` engine and serialises the
full fleet summary + baseline drift the same way the ``fleet --format json``
CLI does, then pulls out the signals a pipeline would gate on: systemic
findings (image-level), the drifted-host list, and per-control coverage.

Offline: reads the bundled ``demos/12-fleet-systemic`` snapshots.
"""
import json

from _common import fixture, rule, section
from comint_osquery import fleet as fl


def main() -> None:
    rule("CONMON PIPELINE  -  fleet posture + drift as machine-readable JSON")

    hosts = fl.scan_fleet(fixture("12-fleet-systemic"))
    base = fl.pick_baseline(hosts)
    drift = fl.baseline_drift(hosts, base) if base else None

    payload = {
        "classification": "UNCLASSIFIED//FOR PUBLIC RELEASE",
        "summary": fl.fleet_summary(hosts),
        "drift": drift,
    }
    blob = json.dumps(payload, default=str)
    print(f"\n  serialised {len(blob)} bytes of JSON (parses back cleanly)")
    round_trip = json.loads(blob)

    section("Signals a pipeline gates on")
    s = round_trip["summary"]
    print(f"  hosts scanned      : {s['hosts_scanned']}")
    print(f"  systemic findings  : {s['systemic_findings']}   <- fix the IMAGE, page on this")
    print(f"  isolated findings  : {s['isolated_findings']}")
    print(f"  drifted hosts      : {round_trip['drift']['drifted_hosts']}")

    section("Per-control coverage (fraction of fleet failing)")
    for q, d in sorted(s["correlation"].items()):
        print(f"  {d['nist']:<8} {q:<28} coverage={d['coverage']:<5} scope={d['scope']}")

    if s["systemic_findings"]:
        print("\n  ALERT: at least one control fails fleet-wide -> golden-image defect.")


if __name__ == "__main__":
    main()
