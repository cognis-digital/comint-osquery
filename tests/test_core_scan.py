"""Deep tests for comint_osquery.core: STIG pack integrity, scan behaviour,
parse-error / malformed-input handling, and the osquery YAML pack emitter.

Offline, stdlib only. Covers the shape-hardening that surfaces bare-list
(single-query) osquery output as a diagnostic instead of a silent clean pass.
"""
import json
import re
from pathlib import Path

import pytest

from cognis_mil import Severity
from comint_osquery.core import (
    STIG_PACK,
    emit_query_pack,
    parse_osquery_results,
    scan,
)

DEMOS = Path(__file__).parent.parent / "demos"


# --------------------------------------------------------------------------- #
# STIG_PACK integrity
# --------------------------------------------------------------------------- #
def test_pack_non_empty():
    assert len(STIG_PACK) >= 8


def test_every_entry_has_required_keys():
    for name, cfg in STIG_PACK.items():
        for key in ("sql", "nist", "stig", "attack", "severity", "title"):
            assert key in cfg, f"{name} missing {key}"


def test_every_severity_is_enum_member():
    for name, cfg in STIG_PACK.items():
        assert isinstance(cfg["severity"], Severity), name


def test_nist_ids_look_like_controls():
    pat = re.compile(r"^[A-Z]{2}-\d+(\(\d+\))?$")
    for name, cfg in STIG_PACK.items():
        assert pat.match(cfg["nist"]), f"{name}: {cfg['nist']}"


def test_stig_ids_look_like_v_rules():
    pat = re.compile(r"^V-\d+$")
    for name, cfg in STIG_PACK.items():
        assert pat.match(cfg["stig"]), f"{name}: {cfg['stig']}"


def test_attack_ids_wellformed():
    pat = re.compile(r"^T\d{4}(\.\d{3})?$")
    for name, cfg in STIG_PACK.items():
        assert pat.match(cfg["attack"]), f"{name}: {cfg['attack']}"


def test_cci_ids_wellformed_when_present():
    pat = re.compile(r"^CCI-\d{6}$")
    for name, cfg in STIG_PACK.items():
        if cfg.get("cci"):
            assert pat.match(cfg["cci"]), f"{name}: {cfg['cci']}"


def test_titles_are_nonempty_strings():
    for name, cfg in STIG_PACK.items():
        assert isinstance(cfg["title"], str) and cfg["title"].strip()


def test_sql_is_a_select():
    for name, cfg in STIG_PACK.items():
        assert cfg["sql"].strip().upper().startswith("SELECT"), name


def test_query_names_are_snake_case():
    for name in STIG_PACK:
        assert re.match(r"^[a-z][a-z0-9_]*$", name), name


# --------------------------------------------------------------------------- #
# parse_osquery_results
# --------------------------------------------------------------------------- #
def test_parse_valid_dict(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"fips_not_enforced": [{"value": "0"}]}))
    out = parse_osquery_results(p)
    assert "_error" not in out
    assert out["fips_not_enforced"]


def test_parse_malformed_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ this is not json ")
    out = parse_osquery_results(p)
    assert "_error" in out


def test_parse_empty_file(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("")
    out = parse_osquery_results(p)
    assert out.get("_error") == "empty file"


def test_parse_whitespace_only_file(tmp_path):
    p = tmp_path / "ws.json"
    p.write_text("   \n\t ")
    assert "empty file" in parse_osquery_results(p)["_error"]


def test_parse_bare_list_is_error_not_silent(tmp_path):
    # Real `osqueryi --json` single-query output is a bare list of row dicts.
    # It carries no query name, so it must be flagged, never silently treated
    # as clean (a false-negative for a compliance tool).
    p = tmp_path / "adhoc.json"
    p.write_text(json.dumps([{"name": "auditd"}, {"name": "x"}]))
    out = parse_osquery_results(p)
    assert "_error" in out
    assert "single-query" in out["_error"]


def test_parse_scalar_json_is_error(tmp_path):
    p = tmp_path / "scalar.json"
    p.write_text("42")
    out = parse_osquery_results(p)
    assert "_error" in out
    assert "unexpected JSON shape" in out["_error"]


def test_parse_string_json_is_error(tmp_path):
    p = tmp_path / "str.json"
    p.write_text('"hello"')
    assert "_error" in parse_osquery_results(p)


def test_parse_null_json_is_error(tmp_path):
    p = tmp_path / "null.json"
    p.write_text("null")
    assert "_error" in parse_osquery_results(p)


def test_parse_missing_file_returns_error():
    out = parse_osquery_results(Path("/no/such/file/xyz.json"))
    assert "_error" in out


# --------------------------------------------------------------------------- #
# scan()
# --------------------------------------------------------------------------- #
def test_scan_empty_dir_no_findings(tmp_path):
    r = scan(str(tmp_path))
    assert r.total_findings() == 0
    assert r.items_scanned == 0


def test_scan_missing_target_is_zero(tmp_path):
    r = scan(str(tmp_path / "nope"))
    assert r.items_scanned == 0
    assert r.total_findings() == 0


def test_scan_single_file_target(tmp_path):
    p = tmp_path / "h.json"
    p.write_text(json.dumps({"fips_not_enforced": [{"value": "0"}]}))
    r = scan(str(p))
    assert r.items_scanned == 1
    assert r.total_findings() == 1


def test_scan_bare_list_produces_parse_finding(tmp_path):
    (tmp_path / "adhoc.json").write_text(json.dumps([{"name": "auditd"}]))
    r = scan(str(tmp_path))
    assert r.total_findings() == 1
    assert r.findings[0].id == "CO-PARSE"
    assert r.findings[0].severity == Severity.LOW


def test_scan_malformed_json_produces_parse_finding(tmp_path):
    (tmp_path / "x.json").write_text("garbage{")
    r = scan(str(tmp_path))
    assert r.findings[0].id == "CO-PARSE"


def test_scan_ignores_passing_rows(tmp_path):
    (tmp_path / "h.json").write_text(json.dumps({"fips_not_enforced": []}))
    r = scan(str(tmp_path))
    assert r.total_findings() == 0


def test_scan_ignores_unknown_queries(tmp_path):
    (tmp_path / "h.json").write_text(json.dumps({"not_a_real_query": [{"x": 1}]}))
    r = scan(str(tmp_path))
    assert r.total_findings() == 0


def test_scan_finding_carries_crosswalk(tmp_path):
    (tmp_path / "h.json").write_text(json.dumps({"fips_not_enforced": [{"v": 0}]}))
    r = scan(str(tmp_path))
    f = r.findings[0]
    cfg = STIG_PACK["fips_not_enforced"]
    assert f.nist_800_53 == cfg["nist"]
    assert f.disa_stig == cfg["stig"]
    assert f.cci == cfg["cci"]
    assert f.mitre_attack == cfg["attack"]


def test_scan_finding_location_names_source(tmp_path):
    p = tmp_path / "src.json"
    p.write_text(json.dumps({"fips_not_enforced": [{"v": 0}]}))
    r = scan(str(tmp_path))
    assert "src.json" in r.findings[0].location


def test_scan_row_count_in_description(tmp_path):
    (tmp_path / "h.json").write_text(
        json.dumps({"world_writable_root_files": [{"p": 1}, {"p": 2}, {"p": 3}]}))
    r = scan(str(tmp_path))
    assert "3 row(s)" in r.findings[0].description


def test_scan_multiple_files_accumulate(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"fips_not_enforced": [{"v": 0}]}))
    (tmp_path / "b.json").write_text(json.dumps({"audit_daemon_not_running": [{"n": "x"}]}))
    r = scan(str(tmp_path))
    assert r.items_scanned == 2
    assert r.total_findings() == 2


def test_scan_finalize_sets_risk_level(tmp_path):
    (tmp_path / "h.json").write_text(json.dumps({
        "fips_not_enforced": [{"v": 0}],
        "users_no_password_required": [{"u": "x"}],
    }))
    r = scan(str(tmp_path))
    assert r.composite_score > 0
    assert r.risk_level in {"Low", "Moderate", "High", "Very High", "Very Low"}


def test_scan_clean_host_is_very_low(tmp_path):
    (tmp_path / "h.json").write_text(json.dumps({"fips_not_enforced": []}))
    r = scan(str(tmp_path))
    assert r.risk_level == "Very Low"
    assert r.composite_score == 0.0


def test_scan_default_tool_metadata(tmp_path):
    r = scan(str(tmp_path))
    assert r.tool_name == "comint-osquery"


# --------------------------------------------------------------------------- #
# emit_query_pack
# --------------------------------------------------------------------------- #
def test_pack_contains_every_query():
    pack = emit_query_pack()
    for name in STIG_PACK:
        assert name in pack


def test_pack_has_yaml_header():
    pack = emit_query_pack()
    assert "queries:" in pack
    assert pack.splitlines()[0].startswith("#")


def test_pack_each_query_has_interval_and_snapshot():
    pack = emit_query_pack()
    assert pack.count("interval: 3600") == len(STIG_PACK)
    assert pack.count("snapshot: true") == len(STIG_PACK)


def test_pack_writes_to_file(tmp_path):
    out = tmp_path / "pack.yaml"
    text = emit_query_pack(out)
    assert out.exists()
    assert out.read_text() == text


def test_pack_is_cp1252_safe():
    emit_query_pack().encode("cp1252")


def test_pack_descriptions_reference_stig():
    pack = emit_query_pack()
    for cfg in STIG_PACK.values():
        assert cfg["stig"] in pack
