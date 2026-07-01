"""Extended tests for the cognis-connect emit bridge (comint_osquery.connect).

Requires the optional [connect] extra; skipped otherwise.
"""
from __future__ import annotations

import importlib
import io
import json
import sys

import pytest

cc = pytest.importorskip("cognis_connect")
mod = importlib.import_module("comint_osquery.connect")


def _capture(argv, stdin_text):
    old = sys.stdin
    sys.stdin = io.StringIO(stdin_text)
    buf = io.StringIO()
    old_out = sys.stdout
    sys.stdout = buf
    try:
        rc = mod.emit_main(argv)
    finally:
        sys.stdin = old
        sys.stdout = old_out
    return rc, buf.getvalue()


# --------------------------------------------------------------------------- #
# map_record / _findings
# --------------------------------------------------------------------------- #
def test_map_record_passthrough():
    rec = {"title": "t", "severity": "high"}
    assert mod.map_record(rec) == rec


def test_findings_from_list_json():
    fs = mod._findings('[{"title": "a", "severity": "low"}]')
    assert len(fs) == 1


def test_findings_from_dict_with_findings_key():
    fs = mod._findings('{"findings": [{"title": "a", "severity": "low"}]}')
    assert len(fs) == 1


def test_findings_from_dict_with_results_key():
    fs = mod._findings('{"results": [{"title": "a", "severity": "low"}]}')
    assert len(fs) == 1


def test_findings_from_single_dict():
    fs = mod._findings('{"title": "solo", "severity": "high"}')
    assert len(fs) == 1


def test_findings_from_multiline_json_text():
    # multiline text is handled as inline content by the loader, not a path
    fs = mod._findings('[{"title": "a", "severity": "low"}]\n')
    assert isinstance(fs, list)
    assert len(fs) == 1


# --------------------------------------------------------------------------- #
# emit_main output formats
# --------------------------------------------------------------------------- #
def test_emit_stix_bundle():
    rc, out = _capture(["--to", "stix"],
                       '[{"title": "x", "severity": "high", "ip": "203.0.113.5"}]')
    assert rc == 0
    d = json.loads(out)
    assert d["type"] == "bundle"


def test_emit_sigma_rules():
    rc, out = _capture(["--to", "sigma"],
                       '[{"title": "x", "severity": "low", "domain": "evil.example"}]')
    assert rc == 0
    assert "title:" in out


def test_emit_findings_dump():
    rc, out = _capture(["--to", "findings"],
                       '[{"title": "x", "severity": "high"}]')
    assert rc == 0
    assert out.strip()


def test_emit_slack_dry_run():
    rc, out = _capture(["--to", "slack", "--dry-run"],
                       '[{"title": "x", "severity": "high"}]')
    assert rc == 0


def test_emit_reads_from_file(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('[{"title": "x", "severity": "high"}]')
    old_out = sys.stdout
    sys.stdout = io.StringIO()
    try:
        rc = mod.emit_main(["--to", "sigma", str(p)])
        out = sys.stdout.getvalue()
    finally:
        sys.stdout = old_out
    assert rc == 0
    assert "title:" in out
