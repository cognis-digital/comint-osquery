"""CLI error-path + subcommand-routing tests for comint_osquery.cli.

Drives cli.main() via argv patching, plus the feeds subcommand against the
committed offline fixture cache. Covers invalid feeds, offline-missing errors,
snapshot round-trips, and the default make_cli scan formats.
"""
import csv
import io
import json
import sys
from pathlib import Path

import pytest

from comint_osquery import cli

DEMOS = Path(__file__).parent.parent / "demos"
ROLLUP = DEMOS / "08-fleet-rollup"
FIXTURE_CACHE = Path(__file__).parent / "fixtures" / "feeds-cache"


def _run(argv, capsys):
    old = sys.argv
    sys.argv = ["comint-osquery"] + argv
    rc = None
    try:
        try:
            cli.main()
        except SystemExit as e:
            rc = e.code
    finally:
        sys.argv = old
    out = capsys.readouterr()
    return rc, out.out, out.err


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    yield


# --------------------------------------------------------------------------- #
# default scan CLI (make_cli) — formats
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fmt", ["console", "json", "markdown", "sarif", "oscal", "csv"])
def test_scan_all_formats(fmt, capsys):
    rc, out, _ = _run([str(ROLLUP), "--format", fmt], capsys)
    assert rc == 0
    assert out.strip()


def test_scan_json_shape(capsys):
    rc, out, _ = _run([str(ROLLUP), "--format", "json"], capsys)
    d = json.loads(out)
    assert d["tool_name"] == "comint-osquery"


def test_scan_fail_on_high_exits_nonzero(capsys):
    rc, out, _ = _run([str(ROLLUP), "--format", "json", "--fail-on", "high"], capsys)
    assert rc == 1  # rollup has HIGH+ findings


def test_scan_fail_on_none_exits_zero(capsys):
    rc, _, _ = _run([str(ROLLUP), "--format", "json", "--fail-on", "none"], capsys)
    assert rc == 0


def test_scan_out_file(tmp_path, capsys):
    dest = tmp_path / "out.json"
    rc, _, err = _run([str(ROLLUP), "--format", "json", "--out", str(dest)], capsys)
    assert rc == 0
    assert dest.exists()
    assert "Wrote" in err


def test_scan_classification_flag(capsys):
    rc, out, _ = _run([str(ROLLUP), "--classification", "UNCLASSIFIED//CUI"], capsys)
    assert "UNCLASSIFIED//CUI" in out


# --------------------------------------------------------------------------- #
# feeds subcommand
# --------------------------------------------------------------------------- #
def test_feeds_list(capsys):
    rc, out, _ = _run(["feeds", "list"], capsys)
    assert rc == 0
    assert "oscal-800-53-rev5-catalog" in out
    assert "attack-nist-mappings" in out


def test_feeds_get_offline(capsys):
    rc, out, _ = _run(["feeds", "get", "oscal-800-53-rev5-catalog", "--offline"], capsys)
    assert rc == 0
    assert "catalog" in out


def test_feeds_get_irrelevant_feed_errors(capsys):
    rc, out, err = _run(["feeds", "get", "cisa-kev", "--offline"], capsys)
    assert rc == 1
    assert "not a relevant feed" in err


def test_feeds_update_irrelevant_feed_errors(capsys):
    rc, out, err = _run(["feeds", "update", "cisa-kev"], capsys)
    assert rc == 1
    assert "not a relevant feed" in err


def test_feeds_enrich_offline(capsys):
    rc, out, _ = _run(["feeds", "enrich", str(DEMOS / "01-failing-host"), "--offline"], capsys)
    assert rc == 0
    d = json.loads(out)
    assert d["tool"] == "comint-osquery"
    assert d["findings"] > 0
    assert d["enrichment"]


def test_feeds_snapshot_roundtrip(tmp_path, monkeypatch, capsys):
    snap = tmp_path / "snap.tar.gz"
    rc, out, _ = _run(["feeds", "snapshot-export", str(snap)], capsys)
    assert rc == 0
    assert snap.exists()
    # import into a fresh cache
    fresh = tmp_path / "fresh"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(fresh))
    rc2, out2, _ = _run(["feeds", "snapshot-import", str(snap)], capsys)
    assert rc2 == 0
    assert "imported" in out2


# --------------------------------------------------------------------------- #
# fleet / poam error + edge paths
# --------------------------------------------------------------------------- #
def test_fleet_missing_target_still_zero(capsys, tmp_path):
    rc, out, _ = _run(["fleet", str(tmp_path / "nope"), "--format", "json"], capsys)
    assert rc == 0
    d = json.loads(out)
    assert d["summary"]["hosts_total"] == 0


def test_fleet_explicit_missing_baseline_no_drift(capsys):
    rc, out, _ = _run(["fleet", str(ROLLUP), "--format", "json", "--baseline", "ghost"], capsys)
    assert rc == 0
    d = json.loads(out)
    assert d["drift"] is None      # baseline not found -> no drift block


def test_poam_json_count(capsys):
    rc, out, _ = _run(["poam", str(ROLLUP), "--format", "json"], capsys)
    d = json.loads(out)
    assert d["count"] == 4


def test_poam_empty_target(capsys, tmp_path):
    rc, out, _ = _run(["poam", str(tmp_path / "nope"), "--format", "json"], capsys)
    assert rc == 0
    assert json.loads(out)["count"] == 0
