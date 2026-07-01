"""Scenario 7 - reliability engineer: malformed input never lies about posture.

A compliance scanner that silently reports a broken input file as a *clean*
host is worse than useless — it manufactures false assurance. This demo feeds
the REAL ``core.scan`` / ``fleet.scan_host`` three kinds of bad input
(truncated JSON, an empty file, and a bare single-query list that carries no
query name) and shows each is surfaced as an explicit diagnostic, never a
silent pass.

Offline: writes throwaway fixtures to a temp dir.
"""
import json
import tempfile
from pathlib import Path

from _common import rule, section
from comint_osquery.core import scan
from comint_osquery import fleet as fl


def main() -> None:
    rule("RELIABILITY  -  malformed input is flagged, never a silent clean pass")

    tmp = Path(tempfile.mkdtemp(prefix="comint_parse_"))
    (tmp / "host-truncated.json").write_text('{"fips_not_enforced": [')       # truncated
    (tmp / "host-empty.json").write_text("")                                  # empty
    (tmp / "host-adhoc.json").write_text(json.dumps([{"name": "auditd"}]))    # bare list
    (tmp / "host-clean.json").write_text(json.dumps({"fips_not_enforced": []}))

    section("Per-host scan surfaces each bad file as a parse error")
    for h in fl.scan_fleet(tmp):
        if h.parse_error:
            print(f"  {h.host:<12} PARSE ERROR: {h.parse_error[:60]}")
        elif h.ok:
            print(f"  {h.host:<12} clean")
        else:
            print(f"  {h.host:<12} failing: {', '.join(h.failing)}")

    section("Flat scan records a low-severity CO-PARSE finding (not a crash)")
    r = scan(str(tmp))
    parse_findings = [f for f in r.findings if f.id == "CO-PARSE"]
    print(f"  scanned {r.items_scanned} file(s) -> {len(parse_findings)} parse diagnostic(s)")
    for f in parse_findings:
        print(f"    [{f.severity.value}] {Path(f.location).name}")

    print("\n  The bare-list file is the subtle one: valid JSON, but no query")
    print("  name to map — so it's flagged, not counted as a clean host.")


if __name__ == "__main__":
    main()
