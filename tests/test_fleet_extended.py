"""Extended fleet-engine tests: correlation boundaries, drift edge cases, the
per-host POA&M numbering fix, and render/parse-error handling.

Complements test_fleet.py. Offline, stdlib only.
"""
import json
from pathlib import Path

import pytest

from cognis_mil import Severity
from comint_osquery import fleet as fl
from comint_osquery.core import STIG_PACK

DEMOS = Path(__file__).parent.parent / "demos"
ROLLUP = DEMOS / "08-fleet-rollup"
SYSTEMIC = DEMOS / "12-fleet-systemic"


def _hosts(spec):
    """spec = {host: {query: count}} -> list[HostResult]."""
    return [fl.HostResult(h, h, dict(f)) for h, f in spec.items()]


# --------------------------------------------------------------------------- #
# scan_host — shape hardening (bare list now flagged, not silent-clean)
# --------------------------------------------------------------------------- #
def test_scan_host_bare_list_is_parse_error(tmp_path):
    p = tmp_path / "host-adhoc.json"
    p.write_text(json.dumps([{"name": "auditd"}]))
    h = fl.scan_host(p)
    assert h.parse_error is not None
    assert not h.ok            # NOT silently reported as clean


def test_scan_host_empty_file_is_parse_error(tmp_path):
    p = tmp_path / "host-x.json"
    p.write_text("")
    h = fl.scan_host(p)
    assert h.parse_error is not None


def test_scan_host_scalar_is_parse_error(tmp_path):
    p = tmp_path / "host-x.json"
    p.write_text("123")
    assert fl.scan_host(p).parse_error is not None


# --------------------------------------------------------------------------- #
# correlate — scope boundaries
# --------------------------------------------------------------------------- #
def test_correlate_exactly_half_is_widespread():
    h = _hosts({"a": {"selinux_not_enforcing": 1},
                "b": {"selinux_not_enforcing": 1},
                "c": {}, "d": {}})
    corr = fl.correlate(h)
    assert corr["selinux_not_enforcing"]["coverage"] == 0.5
    assert corr["selinux_not_enforcing"]["scope"] == "widespread"


def test_correlate_two_hosts_all_fail_is_systemic():
    h = _hosts({"a": {"fips_not_enforced": 1}, "b": {"fips_not_enforced": 1}})
    assert fl.correlate(h)["fips_not_enforced"]["scope"] == "systemic"


def test_correlate_multiple_queries_independent_scope():
    h = _hosts({
        "a": {"fips_not_enforced": 1, "ssh_root_login_permitted": 1},
        "b": {"fips_not_enforced": 1},
        "c": {"fips_not_enforced": 1},
    })
    corr = fl.correlate(h)
    assert corr["fips_not_enforced"]["scope"] == "systemic"
    assert corr["ssh_root_login_permitted"]["scope"] == "isolated"


def test_correlate_all_errored_denominator_safe(tmp_path):
    (tmp_path / "host-a.json").write_text("bad{")
    (tmp_path / "host-b.json").write_text("bad{")
    assert fl.correlate(fl.scan_fleet(tmp_path)) == {}


def test_correlate_hosts_sorted_in_output():
    h = _hosts({"zeta": {"fips_not_enforced": 1},
                "alpha": {"fips_not_enforced": 1}})
    assert fl.correlate(h)["fips_not_enforced"]["hosts"] == ["alpha", "zeta"]


# --------------------------------------------------------------------------- #
# fleet_summary buckets
# --------------------------------------------------------------------------- #
def test_summary_partial_not_in_any_named_bucket():
    h = _hosts({f"h{i}": ({"selinux_not_enforcing": 1} if i < 2 else {})
                for i in range(5)})   # 2/5 = 0.4 -> partial
    s = fl.fleet_summary(h)
    assert "selinux_not_enforcing" not in s["systemic_findings"]
    assert "selinux_not_enforcing" not in s["widespread_findings"]
    assert "selinux_not_enforcing" not in s["isolated_findings"]


def test_summary_all_clean_no_findings():
    s = fl.fleet_summary(_hosts({"a": {}, "b": {}}))
    assert s["hosts_clean"] == ["a", "b"]
    assert s["controls_failing"] == []


def test_summary_empty_fleet():
    s = fl.fleet_summary([])
    assert s["hosts_total"] == 0
    assert s["hosts_scanned"] == 0


# --------------------------------------------------------------------------- #
# baseline drift
# --------------------------------------------------------------------------- #
def test_drift_both_directions_same_host():
    base = fl.HostResult("base", "base", {"fips_not_enforced": 1})
    other = fl.HostResult("h", "h", {"audit_daemon_not_running": 1})
    d = fl.baseline_drift([base, other], base)["drift"]["h"]
    assert d["regressions"] == ["audit_daemon_not_running"]
    assert d["improvements"] == ["fips_not_enforced"]
    assert d["drifted"] is True


def test_drift_skips_errored_host(tmp_path):
    (tmp_path / "host-good.json").write_text(json.dumps({"fips_not_enforced": [{"v": 0}]}))
    (tmp_path / "host-bad.json").write_text("garbage{")
    hosts = fl.scan_fleet(tmp_path)
    base = fl.HostResult("z", "z", {})
    d = fl.baseline_drift(hosts, base)
    assert "bad" not in d["drift"]


def test_drift_regression_controls_map_to_nist():
    base = fl.HostResult("b", "b", {})
    worse = fl.HostResult("w", "w", {"fips_not_enforced": 1, "audit_daemon_not_running": 1})
    d = fl.baseline_drift([base, worse], base)
    assert set(d["drift"]["w"]["regression_controls"]) == {"SC-13", "AU-3"}


def test_pick_baseline_ties_break_by_host_id():
    h = _hosts({"zeta": {}, "alpha": {}})
    assert fl.pick_baseline(h).host == "alpha"


def test_pick_baseline_prefers_fewest_failing():
    h = _hosts({"a": {"fips_not_enforced": 1, "ssh_root_login_permitted": 1},
                "b": {"fips_not_enforced": 1}})
    assert fl.pick_baseline(h).host == "b"


def test_pick_baseline_all_errored_returns_none(tmp_path):
    (tmp_path / "host-a.json").write_text("bad{")
    assert fl.pick_baseline(fl.scan_fleet(tmp_path)) is None


# --------------------------------------------------------------------------- #
# POA&M — the per-host sequence numbering fix
# --------------------------------------------------------------------------- #
def test_poam_item_ids_reset_per_host():
    h = _hosts({
        "aaa": {"fips_not_enforced": 1, "audit_daemon_not_running": 1},
        "bbb": {"fips_not_enforced": 1},
    })
    items = fl.poam_items(h, assessed_at=0)
    ids = {r["Affected Asset"]: [] for r in items}
    for r in items:
        ids[r["Affected Asset"]].append(r["POA&M Item ID"])
    # each host's items start at -001
    assert ids["aaa"][0] == "aaa-001"
    assert ids["bbb"][0] == "bbb-001"          # was bbb-003 before the fix
    assert ids["aaa"] == ["aaa-001", "aaa-002"]


def test_poam_ids_still_globally_unique():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=0)
    ids = [r["POA&M Item ID"] for r in items]
    assert len(ids) == len(set(ids))


def test_poam_id_prefix_is_host():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=0)
    for r in items:
        assert r["POA&M Item ID"].startswith(r["Affected Asset"] + "-")


def test_poam_all_columns_present():
    items = fl.poam_items(fl.scan_fleet(SYSTEMIC), assessed_at=0)
    for r in items:
        assert set(r.keys()) == set(fl.POAM_COLUMNS)


def test_poam_status_is_ongoing():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=0)
    assert all(r["Status"] == "Ongoing" for r in items)


def test_poam_comments_reference_source():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=0)
    assert all("comint-osquery" in r["Comments"] for r in items)


def test_poam_milestone_mentions_stig():
    items = fl.poam_items(fl.scan_fleet(SYSTEMIC), assessed_at=0)
    fips = next(r for r in items if r["Security Control Number (NC/NA)"] == "SC-13")
    assert "V-238298" in fips["Milestone with Completion Dates"]


# --------------------------------------------------------------------------- #
# POA&M serialisation extras
# --------------------------------------------------------------------------- #
def test_poam_csv_empty_items_header_only():
    text = fl.poam_to_csv([])
    lines = text.strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("POA&M Item ID,")


def test_poam_json_empty():
    data = json.loads(fl.poam_to_json([]))
    assert data["count"] == 0
    assert data["poam_items"] == []


def test_poam_csv_ignores_extra_keys():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=0)
    items[0]["EXTRA"] = "ignored"      # extrasaction='ignore'
    text = fl.poam_to_csv(items)
    assert "ignored" not in text


# --------------------------------------------------------------------------- #
# render_fleet_report
# --------------------------------------------------------------------------- #
def test_render_no_drift_message():
    h = _hosts({"a": {"fips_not_enforced": 1}, "b": {"fips_not_enforced": 1}})
    base = fl.pick_baseline(h)
    out = fl.render_fleet_report(h, fl.baseline_drift(h, base))
    assert "no drift" in out


def test_render_all_clean_fleet():
    out = fl.render_fleet_report(_hosts({"a": {}, "b": {}}))
    assert "0 failing" in out


def test_render_errored_host_counted():
    import tempfile
    d = Path(tempfile.mkdtemp())
    (d / "host-ok.json").write_text(json.dumps({"fips_not_enforced": []}))
    (d / "host-bad.json").write_text("bad{")
    out = fl.render_fleet_report(fl.scan_fleet(d))
    assert "1 errored" in out


def test_render_widespread_section():
    h = _hosts({"a": {"selinux_not_enforcing": 1},
                "b": {"selinux_not_enforcing": 1},
                "c": {}})
    out = fl.render_fleet_report(h)
    assert "WIDESPREAD" in out


def test_render_is_cp1252_safe_with_drift():
    h = _hosts({"a": {}, "b": {"fips_not_enforced": 1}})
    base = fl.pick_baseline(h)
    fl.render_fleet_report(h, fl.baseline_drift(h, base)).encode("cp1252")


def test_render_custom_classification_twice():
    out = fl.render_fleet_report(_hosts({"a": {}}), classification="SECRET//NOFORN")
    assert out.count("SECRET//NOFORN") == 2


# --------------------------------------------------------------------------- #
# HostResult
# --------------------------------------------------------------------------- #
def test_hostresult_ok_true_when_clean():
    assert fl.HostResult("a", "a", {}).ok


def test_hostresult_ok_false_with_parse_error():
    assert not fl.HostResult("a", "a", {}, parse_error="boom").ok


def test_hostresult_controls_multi_query_dedup():
    # two queries mapping to different controls
    h = fl.HostResult("a", "a", {"fips_not_enforced": 1, "audit_daemon_not_running": 1})
    assert h.controls() == {"SC-13", "AU-3"}
