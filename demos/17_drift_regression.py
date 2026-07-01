"""Scenario 17 - config-management: catch a host that drifted off the golden image.

Baseline drift is the daily ConMon question: which hosts have wandered away from
the golden image, and in which direction? This demo builds a small synthetic
fleet in memory (golden baseline + one regressed host + one *ahead* host) and
runs the REAL ``fleet.baseline_drift`` to separate regressions (worse than
golden — actionable) from improvements (better than golden — usually a stale
image).

Offline: synthetic in-memory HostResults, no fixtures.
"""
from _common import rule, section
from comint_osquery import fleet as fl
from comint_osquery.core import STIG_PACK


def main() -> None:
    rule("CONFIG MGMT  -  baseline drift: regressions vs improvements")

    golden = fl.HostResult("golden", "golden", {"ssh_root_login_permitted": 1})
    regressed = fl.HostResult("web02", "web02", {
        "ssh_root_login_permitted": 1,     # same as golden
        "fips_not_enforced": 1,            # NEW failure -> regression
        "audit_daemon_not_running": 1,     # NEW failure -> regression
    })
    ahead = fl.HostResult("web03", "web03", {})   # fixed even the golden's ssh issue

    hosts = [golden, regressed, ahead]
    drift = fl.baseline_drift(hosts, golden)

    print(f"\n  baseline: {drift['baseline']}  "
          f"(its own failing set: {drift['in_baseline']})")
    print(f"  drifted hosts: {drift['drifted_hosts']}")

    section("web02 — regressed (worse than golden, open tickets)")
    d = drift["drift"]["web02"]
    for q in d["regressions"]:
        print(f"    [DRIFT-] {STIG_PACK[q]['nist']:<8} {STIG_PACK[q]['title']}")
    print(f"    regression controls: {d['regression_controls']}")

    section("web03 — ahead of golden (image is probably stale)")
    d = drift["drift"]["web03"]
    for q in d["improvements"]:
        print(f"    [DRIFT+] {STIG_PACK[q]['nist']:<8} {STIG_PACK[q]['title']} (fixed vs golden)")

    print("\n  Regressions -> remediate the host. Improvements -> re-bake the golden image.")


if __name__ == "__main__":
    main()
