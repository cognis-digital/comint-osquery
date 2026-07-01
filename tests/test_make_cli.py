"""Tests for the shared cognis_mil.make_cli builder used by comint-osquery."""
import json
import sys

import pytest

from cognis_mil import make_cli
from cognis_mil.models import ScanResult, Finding, Severity


def _scan_with_findings(target=".", **opts):
    r = ScanResult("demo-tool", "0.1.0")
    r.add(Finding("A", Severity.VERY_HIGH, "critical thing", nist_800_53="AC-2"))
    r.add(Finding("B", Severity.LOW, "minor thing"))
    return r


def _scan_clean(target=".", **opts):
    return ScanResult("demo-tool", "0.1.0")


def _run(scan_fn, argv, capsys):
    old = sys.argv
    sys.argv = ["demo-tool"] + argv
    rc = None
    try:
        try:
            make_cli("demo-tool", scan_fn, version="9.9")
        except SystemExit as e:
            rc = e.code
    finally:
        sys.argv = old
    out = capsys.readouterr()
    return rc, out.out, out.err


@pytest.mark.parametrize("fmt", ["console", "json", "markdown", "sarif", "oscal", "csv"])
def test_all_formats_exit_zero(fmt, capsys):
    rc, out, _ = _run(_scan_with_findings, ["--format", fmt], capsys)
    assert rc == 0
    assert out.strip()


def test_json_output_finalized(capsys):
    rc, out, _ = _run(_scan_with_findings, ["--format", "json"], capsys)
    d = json.loads(out)
    assert d["composite_score"] > 0     # finalize() ran
    assert d["risk_level"] in {"Very Low", "Low", "Moderate", "High", "Very High"}


def test_fail_on_very_high_triggers_exit1(capsys):
    rc, _, _ = _run(_scan_with_findings, ["--format", "json", "--fail-on", "very_high"], capsys)
    assert rc == 1


def test_fail_on_moderate_no_moderate_findings_exit0(capsys):
    # findings are VERY_HIGH + LOW, none MODERATE, but very_high is above the
    # moderate threshold set -> should still trip
    rc, _, _ = _run(_scan_with_findings, ["--format", "json", "--fail-on", "moderate"], capsys)
    assert rc == 1


def test_fail_on_clean_scan_exit0(capsys):
    rc, _, _ = _run(_scan_clean, ["--format", "json", "--fail-on", "very_high"], capsys)
    assert rc == 0


def test_classification_flag_applied(capsys):
    rc, out, _ = _run(_scan_with_findings, ["--format", "json", "--classification", "SECRET//NF"], capsys)
    assert json.loads(out)["classification"] == "SECRET//NF"


def test_out_file_written(tmp_path, capsys):
    dest = tmp_path / "r.json"
    rc, _, err = _run(_scan_with_findings, ["--format", "json", "--out", str(dest)], capsys)
    assert dest.exists()
    assert "Wrote" in err


def test_version_flag(capsys):
    rc, out, _ = _run(_scan_clean, ["--version"], capsys)
    assert rc == 0
    assert "9.9" in out
