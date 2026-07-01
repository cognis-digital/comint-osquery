"""Scenario 15 - CI/CD gate: fail the pipeline on severity threshold.

A hardening pipeline should break the build when a host regresses past a
severity bar. This demo mirrors what the ``--fail-on`` CLI flag does: it scans
hosts at several severity thresholds and shows which exit non-zero, using the
REAL scoring so the gate reflects actual findings.

Offline: reads bundled fixtures.
"""
from _common import fixture, rule, section
from comint_osquery.core import scan
from cognis_mil.models import Severity

# mirror the threshold ladder cognis_mil.make_cli uses for --fail-on
THRESHOLDS = {
    "very_high": {Severity.VERY_HIGH},
    "high": {Severity.VERY_HIGH, Severity.HIGH},
    "moderate": {Severity.VERY_HIGH, Severity.HIGH, Severity.MODERATE},
    "low": {Severity.VERY_HIGH, Severity.HIGH, Severity.MODERATE, Severity.LOW},
    "none": set(),
}


def gate(result, fail_on):
    thresh = THRESHOLDS[fail_on]
    return 1 if any(f.severity in thresh for f in result.findings) else 0


def main() -> None:
    rule("CI/CD GATE  -  fail the build on a severity threshold")

    targets = {
        "clean baseline": fixture("02-clean-baseline"),
        "unsigned kmod (HIGH)": fixture("05-unsigned-kmod"),
        "no auditd (VERY HIGH)": fixture("06-no-auditd"),
    }

    section("Exit code per (target, --fail-on) — non-zero breaks the build")
    print(f"  {'target':<24} " + " ".join(f"{k:>10}" for k in THRESHOLDS))
    for label, path in targets.items():
        r = scan(path)
        codes = " ".join(f"{gate(r, k):>10}" for k in THRESHOLDS)
        print(f"  {label:<24} {codes}")

    print("\n  Read a row: the VERY-HIGH host trips every gate except --fail-on=none;")
    print("  the clean baseline passes them all. Pick your bar per environment.")


if __name__ == "__main__":
    main()
