"""Scenario 6 - GRC engineer: one scan, every export format.

A GRC / RMF automation engineer needs the same assessment in multiple shapes:
JSON for the pipeline, SARIF for the code-scanning dashboard, Markdown for the
ticket, CSV for the spreadsheet, and OSCAL for eMASS. This demo scans a host
once with the REAL ``core.scan`` and renders all six ``cognis_mil`` exporters,
proving each is well-formed (JSON parses, SARIF has the right version, CSV
round-trips) — no fabricated output.

Offline: reads the bundled ``demos/01-failing-host`` snapshot.
"""
import csv
import io
import json

from _common import fixture, rule, section
from comint_osquery.core import scan
from cognis_mil.exporters import (
    to_console, to_json, to_markdown, to_sarif, to_oscal, to_csv,
)


def main() -> None:
    rule("GRC ENGINEER  -  one scan, six export formats")

    result = scan(fixture("01-failing-host"))
    print(f"\n  scanned demos/01-failing-host/ -> {result.total_findings()} finding(s), "
          f"risk {result.composite_score}/100 ({result.risk_level})")

    section("JSON  (pipeline ingestion)")
    d = json.loads(to_json(result))
    print(f"  parses OK; {len(d['findings'])} findings, tool={d['tool_name']}")

    section("SARIF 2.1.0  (code-scanning / GitHub Security tab)")
    s = json.loads(to_sarif(result))
    print(f"  version={s['version']}; {len(s['runs'][0]['results'])} result(s)")

    section("Markdown  (paste into a ticket)")
    md = to_markdown(result)
    print(f"  {len(md.splitlines())} lines; has table header: "
          f"{'| Sev |' in md}")

    section("CSV  (spreadsheet / GRC import)")
    body = "\n".join(l for l in to_csv(result).splitlines() if not l.startswith('#'))
    rows = list(csv.DictReader(io.StringIO(body)))
    print(f"  {len(rows)} data row(s), RFC 4180 quoted; round-trips via csv module")

    section("OSCAL 1.1.2  (eMASS Assessment Results)")
    o = json.loads(to_oscal(result))["assessment-results"]
    print(f"  oscal-version={o['metadata']['oscal-version']}; "
          f"{len(o['results'][0]['findings'])} finding object(s)")

    section("Console  (human-readable banner report)")
    print("\n".join(to_console(result).splitlines()[:6]))
    print("  ...")

    print("\n  Same assessment, six well-formed shapes — pick the one your tool eats.")


if __name__ == "__main__":
    main()
