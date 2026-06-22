"""End-to-end CLI tests for the `fleet` and `poam` subcommands.

Drive `comint_osquery.cli.main()` via argv patching + captured stdout, exactly
as a shell invocation would. Offline, stdlib only.
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
SYSTEMIC = DEMOS / "12-fleet-systemic"


def _run(argv, capsys):
    old = sys.argv
    sys.argv = ["comint-osquery"] + argv
    try:
        rc = None
        try:
            cli.main()
        except SystemExit as e:
            rc = e.code
    finally:
        sys.argv = old
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_fleet_console_default(capsys):
    rc, out, _ = _run(["fleet", str(ROLLUP)], capsys)
    assert rc == 0
    assert "FLEET CORRELATION REPORT" in out
    assert "BASELINE DRIFT" in out


def test_fleet_json_format(capsys):
    rc, out, _ = _run(["fleet", str(SYSTEMIC), "--format", "json"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert data["summary"]["systemic_findings"] == ["fips_not_enforced"]
    assert data["drift"]["baseline"]  # a baseline was auto-picked


def test_fleet_explicit_baseline(capsys):
    rc, out, _ = _run(["fleet", str(ROLLUP), "--format", "json",
                       "--baseline", "web01"], capsys)
    data = json.loads(out)
    assert data["drift"]["baseline"] == "web01"


def test_fleet_classification_banner(capsys):
    rc, out, _ = _run(["fleet", str(ROLLUP), "--classification",
                       "UNCLASSIFIED//CUI"], capsys)
    assert "UNCLASSIFIED//CUI" in out


def test_fleet_out_file(tmp_path, capsys):
    dest = tmp_path / "fleet.json"
    rc, out, err = _run(["fleet", str(ROLLUP), "--format", "json",
                         "--out", str(dest)], capsys)
    assert rc == 0
    assert dest.exists()
    json.loads(dest.read_text(encoding="utf-8"))
    assert "Wrote" in err


def test_poam_csv_default(capsys):
    rc, out, _ = _run(["poam", str(ROLLUP)], capsys)
    assert rc == 0
    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 4
    assert {r["Affected Asset"] for r in rows} == {"db02", "web01"}


def test_poam_json_format(capsys):
    rc, out, _ = _run(["poam", str(ROLLUP), "--format", "json"], capsys)
    data = json.loads(out)
    assert data["count"] == 4


def test_poam_office_flag(capsys):
    rc, out, _ = _run(["poam", str(ROLLUP), "--office", "J6"], capsys)
    rows = list(csv.DictReader(io.StringIO(out)))
    assert all(r["Office/Org"] == "J6" for r in rows)


def test_poam_out_file(tmp_path, capsys):
    dest = tmp_path / "poam.csv"
    rc, out, err = _run(["poam", str(ROLLUP), "--out", str(dest)], capsys)
    assert rc == 0
    assert dest.exists()
    rows = list(csv.DictReader(io.StringIO(dest.read_text(encoding="utf-8"))))
    assert len(rows) == 4
    assert "POA&M item" in err


def test_poam_systemic_demo_five_rows(capsys):
    rc, out, _ = _run(["poam", str(SYSTEMIC)], capsys)
    rows = list(csv.DictReader(io.StringIO(out)))
    # 3 FIPS (one per host) + ssh on edge01 + auditd on edge02 = 5
    assert len(rows) == 5
    fips = [r for r in rows if r["Security Control Number (NC/NA)"] == "SC-13"]
    assert len(fips) == 3


def test_default_scan_still_works(capsys):
    # Ensure subcommand routing didn't break the plain scan path.
    rc, out, _ = _run([str(ROLLUP), "--format", "json"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert data["tool_name"] == "comint-osquery"
    assert data["items_scanned"] == 3
