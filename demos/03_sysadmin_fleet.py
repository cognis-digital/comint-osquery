"""Scenario 3 - sysadmins / DevSecOps: systemic vs isolated, and baseline drift.

One host failing a control is a remediation ticket. The *same* control failing
on every host is a broken golden image / GPO / Ansible role — a very different,
much higher-leverage fix. This demo drives the REAL ``comint_osquery.fleet``
engine over three edge hosts built from one image: it correlates failures into
``systemic`` / ``widespread`` / ``isolated`` scope, picks the cleanest host as a
golden baseline, and reports per-host drift.

Offline: reads the bundled ``demos/12-fleet-systemic`` per-host snapshots.
"""
from _common import fixture, rule, section
from comint_osquery import fleet as fl


def main() -> None:
    rule("SYSADMIN / DEVSECOPS  -  fleet correlation + baseline drift")

    target = fixture("12-fleet-systemic")
    print("\nScanning 3 edge hosts built from one golden image.")
    print("  target: demos/12-fleet-systemic/  (host-edge01..03.json)\n")

    hosts = fl.scan_fleet(target)
    for h in hosts:
        state = "clean" if h.ok else f"failing: {', '.join(sorted(h.failing))}"
        print(f"  {h.host:<10} {state}")

    section("Correlation: where is the blast radius?")
    summ = fl.fleet_summary(hosts)
    print(f"  hosts scanned : {summ['hosts_scanned']}  "
          f"(clean={len(summ['hosts_clean'])}, failing={len(summ['hosts_failing'])})")
    corr = summ["correlation"]
    if summ["systemic_findings"]:
        print("\n  SYSTEMIC (every host -> fix the IMAGE, not the host):")
        for q in summ["systemic_findings"]:
            d = corr[q]
            print(f"    [SYS] {d['nist']:<8} {d['title']}  ({d['count']}/{summ['hosts_scanned']} hosts)")
    if summ["isolated_findings"]:
        print("\n  ISOLATED (single host -> per-host ticket):")
        for q in summ["isolated_findings"]:
            d = corr[q]
            print(f"    [ISO] {d['nist']:<8} {d['title']}  -> {', '.join(d['hosts'])}")

    section("Baseline drift against the cleanest host")
    base = fl.pick_baseline(hosts)
    drift = fl.baseline_drift(hosts, base)
    print(f"  auto-selected baseline: {drift['baseline']}  "
          f"(its own failing set: {drift['in_baseline'] or 'none'})")
    if not drift["drifted_hosts"]:
        print("  no drift detected.")
    for host in drift["drifted_hosts"]:
        regs = drift["drift"][host]["regression_controls"]
        print(f"    [DRIFT-] {host}: regressions beyond baseline -> {', '.join(regs)}")

    print("\n  The systemic FIPS failure says: re-bake the image. The rest are tickets.")


if __name__ == "__main__":
    main()
