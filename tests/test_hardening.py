"""Edge-case and error-path tests for the hardened comint-osquery code."""
import json
import sys
from pathlib import Path

import pytest

from comint_osquery.core import scan, parse_osquery_results, emit_query_pack


# ---------------------------------------------------------------------------
# parse_osquery_results
# ---------------------------------------------------------------------------

def test_parse_missing_file(tmp_path):
    """A path that does not exist returns an _error dict rather than crashing."""
    result = parse_osquery_results(tmp_path / "no_such_file.json")
    assert "_error" in result
    assert "cannot read" in result["_error"].lower() or "no such" in result["_error"].lower()


def test_parse_empty_file(tmp_path):
    """An empty JSON file returns a structured error, not a crash."""
    empty = tmp_path / "empty.json"
    empty.write_text("")
    result = parse_osquery_results(empty)
    assert "_error" in result
    assert "empty" in result["_error"].lower()


def test_parse_malformed_json(tmp_path):
    """A file with invalid JSON returns a structured error, not an exception."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json{{{{")
    result = parse_osquery_results(bad)
    assert "_error" in result
    assert "json" in result["_error"].lower()


def test_parse_unexpected_shape(tmp_path):
    """A JSON primitive (string) that is neither list nor dict returns _error."""
    weird = tmp_path / "weird.json"
    weird.write_text('"just a string"')
    result = parse_osquery_results(weird)
    assert "_error" in result


# ---------------------------------------------------------------------------
# scan() — input validation
# ---------------------------------------------------------------------------

def test_scan_nonexistent_target():
    """scan() raises FileNotFoundError for a target path that does not exist."""
    with pytest.raises(FileNotFoundError):
        scan("/tmp/comint_osquery_no_such_path_xyz_999")


def test_scan_produces_parse_finding_for_bad_json(tmp_path):
    """A directory with one malformed JSON file should produce a CO-PARSE finding."""
    (tmp_path / "broken.json").write_text("!!!! not json")
    r = scan(str(tmp_path))
    assert r.items_scanned == 1
    ids = {f.id for f in r.findings}
    assert "CO-PARSE" in ids


def test_scan_empty_directory(tmp_path):
    """An empty directory (no *.json files) yields 0 items scanned and 0 findings."""
    r = scan(str(tmp_path))
    assert r.items_scanned == 0
    assert r.total_findings() == 0
    assert r.composite_score == 0.0


def test_scan_non_list_rows_skipped(tmp_path):
    """A query whose value is not a list is silently skipped — no crash."""
    data = {"fips_not_enforced": "unexpected string value"}
    (tmp_path / "odd.json").write_text(json.dumps(data))
    r = scan(str(tmp_path))
    # No finding for fips, no CO-PARSE — the odd key was just skipped
    ids = {f.id for f in r.findings}
    assert "CO-PARSE" not in ids
    assert not any("FIPS" in i for i in ids)


# ---------------------------------------------------------------------------
# emit_query_pack — edge cases
# ---------------------------------------------------------------------------

def test_emit_query_pack_writes_file(tmp_path):
    """emit_query_pack(out=path) writes the YAML to disk."""
    out = tmp_path / "stig_pack.yaml"
    text = emit_query_pack(out=out)
    assert out.exists()
    assert out.read_text(encoding="utf-8") == text


def test_emit_query_pack_no_out_arg():
    """emit_query_pack() with no out argument returns a string without writing."""
    text = emit_query_pack()
    assert isinstance(text, str)
    assert "queries:" in text
