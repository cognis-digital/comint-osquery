"""Tests for the cognis_mil exporters: console / json / markdown / sarif / oscal.

The CSV and OSCAL exporters have their own dedicated files; this covers the
remaining formats plus cross-format invariants (classification banner presence,
empty-result handling, determinism).
"""
import json

import pytest

from cognis_mil.models import Finding, ScanResult, Severity
from cognis_mil.exporters import (
    to_console,
    to_json,
    to_markdown,
    to_sarif,
    to_oscal,
)


def _result(n=3, cls="UNCLASSIFIED//FOR PUBLIC RELEASE"):
    r = ScanResult("comint-osquery", "0.1.0")
    r.started_at = 1_750_000_000
    sevs = [Severity.VERY_HIGH, Severity.HIGH, Severity.MODERATE,
            Severity.LOW, Severity.VERY_LOW]
    for i in range(n):
        r.add(Finding(f"F-{i}", sevs[i % len(sevs)], f"weakness {i}",
                      description=f"desc {i}", location=f"host{i}.json:1",
                      nist_800_53="AC-6", disa_stig="V-1", cci="CCI-1",
                      mitre_attack="T1078", remediation="fix it"))
    r.classification_placeholder = cls
    return r.finalize()


def _empty():
    return ScanResult("comint-osquery").finalize()


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def test_json_parses():
    d = json.loads(to_json(_result()))
    assert d["tool_name"] == "comint-osquery"
    assert len(d["findings"]) == 3


def test_json_empty_result():
    d = json.loads(to_json(_empty()))
    assert d["findings"] == []
    assert d["risk_level"] == "Very Low"


def test_json_carries_classification():
    d = json.loads(to_json(_result(cls="CUI//SP-PRVCY")))
    assert d["classification"] == "CUI//SP-PRVCY"


def test_json_deterministic():
    assert to_json(_result()) == to_json(_result())


# --------------------------------------------------------------------------- #
# console
# --------------------------------------------------------------------------- #
def test_console_has_banner_top_and_bottom():
    out = to_console(_result(cls="UNCLASSIFIED//TEST"))
    assert out.count("UNCLASSIFIED//TEST") == 2


def test_console_lists_findings():
    out = to_console(_result())
    assert "weakness 0" in out
    assert "F-0" in out


def test_console_shows_crosswalk_lines():
    out = to_console(_result(1))
    assert "AC-6" in out
    assert "V-1" in out
    assert "T1078" in out


def test_console_empty_result_ok():
    out = to_console(_empty())
    assert "Findings: 0" in out


def test_console_truncates_at_100():
    out = to_console(_result(150))
    # only the first 100 finding ids rendered
    assert "F-149" not in out


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #
def test_markdown_table_header():
    out = to_markdown(_result())
    assert "| Sev | ID | Title | NIST | STIG | ATT&CK |" in out


def test_markdown_one_row_per_finding():
    out = to_markdown(_result(4))
    rows = [l for l in out.splitlines() if "`F-" in l]
    assert len(rows) == 4


def test_markdown_carries_classification():
    assert "CUI//X" in to_markdown(_result(cls="CUI//X"))


def test_markdown_empty_result():
    out = to_markdown(_empty())
    assert "Findings:** 0" in out


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #
def test_sarif_valid_json_and_version():
    d = json.loads(to_sarif(_result()))
    assert d["version"] == "2.1.0"
    assert d["runs"][0]["tool"]["driver"]["name"] == "comint-osquery"


def test_sarif_result_count_matches():
    d = json.loads(to_sarif(_result(5)))
    assert len(d["runs"][0]["results"]) == 5


def test_sarif_severity_levels_mapped():
    d = json.loads(to_sarif(_result(5)))
    levels = {r["level"] for r in d["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}


def test_sarif_very_high_is_error():
    r = ScanResult("t"); r.add(Finding("A", Severity.VERY_HIGH, "x")); r.finalize()
    d = json.loads(to_sarif(r))
    assert d["runs"][0]["results"][0]["level"] == "error"


def test_sarif_low_is_note():
    r = ScanResult("t"); r.add(Finding("A", Severity.LOW, "x")); r.finalize()
    d = json.loads(to_sarif(r))
    assert d["runs"][0]["results"][0]["level"] == "note"


def test_sarif_empty_result():
    d = json.loads(to_sarif(_empty()))
    assert d["runs"][0]["results"] == []


def test_sarif_location_strips_line_suffix():
    r = ScanResult("t")
    r.add(Finding("A", Severity.LOW, "x", location="host.json:42"))
    r.finalize()
    d = json.loads(to_sarif(r))
    uri = d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "host.json"


def test_sarif_no_location_uses_unknown():
    r = ScanResult("t"); r.add(Finding("A", Severity.LOW, "x")); r.finalize()
    d = json.loads(to_sarif(r))
    uri = d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "unknown"


def test_sarif_carries_props_crosswalk():
    d = json.loads(to_sarif(_result(1)))
    props = d["runs"][0]["results"][0]["properties"]
    assert props["nist"] == "AC-6"
    assert props["attack"] == "T1078"


# --------------------------------------------------------------------------- #
# OSCAL extra coverage (empty + prop toggling)
# --------------------------------------------------------------------------- #
def test_oscal_empty_result_valid():
    d = json.loads(to_oscal(_empty()))
    res = d["assessment-results"]["results"][0]
    assert res["findings"] == []
    assert res["observations"] == []


def test_oscal_optional_props_omitted_when_blank():
    r = ScanResult("t")
    r.add(Finding("A", Severity.LOW, "x"))  # no stig/cci/attack
    r.finalize()
    d = json.loads(to_oscal(r))
    props = d["assessment-results"]["results"][0]["findings"][0]["props"]
    names = {p["name"] for p in props}
    assert "severity" in names
    assert "disa-stig" not in names  # blank -> omitted


def test_oscal_evidence_present_only_with_location():
    r = ScanResult("t")
    r.add(Finding("A", Severity.LOW, "x", location="h.json"))
    r.add(Finding("B", Severity.LOW, "y"))
    r.finalize()
    d = json.loads(to_oscal(r))
    obs = d["assessment-results"]["results"][0]["observations"]
    by_title = {o["title"]: o for o in obs}
    assert "relevant-evidence" in by_title["A"]
    assert "relevant-evidence" not in by_title["B"]
