"""Scenario 20 - SOC integration: forward findings downstream via cognis-connect.

comint-osquery findings don't have to stop at a report — they can flow into a
SIEM, a STIX bundle, or Sigma rules through the ``cognis-connect`` bridge. This
demo scans a host, shapes the findings into the canonical Finding contract, and
(if the optional ``[connect]`` extra is installed) renders a STIX bundle and
Sigma rules in a dry run. If cognis-connect isn't present, it degrades
gracefully and still exits 0 — the bridge is a soft dependency.

Offline: reads a bundled fixture; all emit is dry-run (no network).
"""
import json

from _common import fixture, rule, section
from comint_osquery.core import scan
from cognis_mil.exporters import to_json


def main() -> None:
    rule("SOC INTEGRATION  -  forward findings via cognis-connect (dry run)")

    result = scan(fixture("01-failing-host"))
    findings_json = to_json(result)
    print(f"\n  scanned demos/01-failing-host/ -> {result.total_findings()} finding(s)")

    try:
        from comint_osquery import connect
        import cognis_connect  # noqa: F401
    except ImportError:
        print("\n  [connect] extra not installed — the bridge is a soft dependency.")
        print("  Install with: pip install "
              "'git+https://github.com/cognis-digital/cognis-connect.git'")
        print("  Skipping downstream emit; nothing to do offline without it.")
        return

    fs = connect._findings(findings_json)
    print(f"  normalised {len(fs)} finding(s) into the cognis-connect contract")

    section("STIX 2.1 bundle (feed a TAXII server / TIP)")
    bundle = cognis_connect.stix.to_bundle(fs)
    print(f"  bundle type={bundle['type']}, objects={len(bundle['objects'])}")

    section("Sigma rules (load into the SIEM)")
    rules = cognis_connect.sigma.to_rules(fs)
    print(f"  emitted {rules.count('title:')} Sigma rule block(s)")
    print("  " + "\n  ".join(rules.splitlines()[:4]))

    print("\n  Same findings, now SIEM/TIP-ready — all dry-run, no network touched.")


if __name__ == "__main__":
    main()
