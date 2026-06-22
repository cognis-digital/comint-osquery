"""Offline tests for the fleet-correlation + baseline-drift engine.

Pure stdlib, no network. Exercises per-host attribution, systemic vs. isolated
classification, baseline-drift in both directions, parse-error handling, and the
console/JSON rendering. Drives both real demo fixtures and synthetic edge cases.
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


# --------------------------------------------------------------------------- #
# host naming + single-host scan
# --------------------------------------------------------------------------- #
def test_host_name_strips_host_prefix():
    assert fl._host_name(Path("host-web01.json")) == "web01"
    assert fl._host_name(Path("host_db02.json")) == "db02"
    assert fl._host_name(Path("results.json")) == "results"


def test_scan_host_counts_failing_queries():
    h = fl.scan_host(ROLLUP / "host-db02.json")
    assert h.host == "db02"
    assert set(h.failing) == {"fips_not_enforced", "audit_daemon_not_running"}
    assert h.failing["fips_not_enforced"] == 1
    assert not h.ok
    assert h.parse_error is None


def test_scan_host_clean_is_ok():
    h = fl.scan_host(ROLLUP / "host-app03.json")
    assert h.failing == {}
    assert h.ok


def test_scan_host_controls_set():
    h = fl.scan_host(ROLLUP / "host-db02.json")
    assert h.controls() == {"SC-13", "AU-3"}


def test_scan_host_parse_error(tmp_path):
    bad = tmp_path / "host-broken.json"
    bad.write_text("{ not valid json ")
    h = fl.scan_host(bad)
    assert h.parse_error is not None
    assert h.host == "broken"
    assert not h.ok


def test_scan_host_ignores_passing_and_unknown_queries(tmp_path):
    f = tmp_path / "host-x.json"
    f.write_text(json.dumps({
        "fips_not_enforced": [],                 # passing -> ignored
        "some_unknown_query": [{"x": 1}],        # not in pack -> ignored
        "audit_daemon_not_running": [{"name": "auditd"}],
    }))
    h = fl.scan_host(f)
    assert set(h.failing) == {"audit_daemon_not_running"}


# --------------------------------------------------------------------------- #
# scan_fleet
# --------------------------------------------------------------------------- #
def test_scan_fleet_directory():
    hosts = fl.scan_fleet(ROLLUP)
    assert {h.host for h in hosts} == {"web01", "db02", "app03"}


def test_scan_fleet_is_sorted_deterministic():
    hosts = fl.scan_fleet(ROLLUP)
    names = [h.host for h in hosts]
    assert names == sorted(names)


def test_scan_fleet_single_file():
    hosts = fl.scan_fleet(ROLLUP / "host-web01.json")
    assert len(hosts) == 1 and hosts[0].host == "web01"


def test_scan_fleet_missing_target():
    assert fl.scan_fleet(Path("/no/such/path/xyz")) == []


# --------------------------------------------------------------------------- #
# correlation: scope classification
# --------------------------------------------------------------------------- #
def test_correlate_isolated_findings_in_rollup():
    hosts = fl.scan_fleet(ROLLUP)
    corr = fl.correlate(hosts)
    # In the rollup every failure is on exactly one host -> all isolated.
    assert all(d["scope"] == "isolated" for d in corr.values())
    assert corr["fips_not_enforced"]["hosts"] == ["db02"]


def test_correlate_systemic_finding():
    hosts = fl.scan_fleet(SYSTEMIC)
    corr = fl.correlate(hosts)
    # FIPS fails on all three edge nodes -> systemic.
    assert corr["fips_not_enforced"]["scope"] == "systemic"
    assert corr["fips_not_enforced"]["count"] == 3
    assert corr["fips_not_enforced"]["coverage"] == 1.0


def test_correlate_isolated_alongside_systemic():
    hosts = fl.scan_fleet(SYSTEMIC)
    corr = fl.correlate(hosts)
    assert corr["ssh_root_login_permitted"]["scope"] == "isolated"
    assert corr["audit_daemon_not_running"]["scope"] == "isolated"


def test_correlate_widespread_threshold():
    # 2 of 3 hosts fail the same control -> coverage 0.667 -> widespread.
    h = [
        fl.HostResult("a", "a", {"selinux_not_enforcing": 1}),
        fl.HostResult("b", "b", {"selinux_not_enforcing": 1}),
        fl.HostResult("c", "c", {}),
    ]
    corr = fl.correlate(h)
    assert corr["selinux_not_enforcing"]["scope"] == "widespread"


def test_correlate_partial_below_half():
    # 1 of 4 would be isolated; build 2 of 5 -> 0.4 coverage -> partial.
    h = [fl.HostResult(f"h{i}", f"h{i}",
                       {"selinux_not_enforcing": 1} if i < 2 else {})
         for i in range(5)]
    corr = fl.correlate(h)
    assert corr["selinux_not_enforcing"]["scope"] == "partial"


def test_correlate_single_host_not_systemic():
    # Only one host scanned -> a failure is isolated, never systemic.
    h = [fl.HostResult("solo", "solo", {"fips_not_enforced": 1})]
    corr = fl.correlate(h)
    assert corr["fips_not_enforced"]["scope"] == "isolated"


def test_correlate_carries_pack_metadata():
    hosts = fl.scan_fleet(SYSTEMIC)
    d = fl.correlate(hosts)["fips_not_enforced"]
    cfg = STIG_PACK["fips_not_enforced"]
    assert d["nist"] == cfg["nist"]
    assert d["stig"] == cfg["stig"]
    assert d["cci"] == cfg["cci"]
    assert d["attack"] == cfg["attack"]
    assert d["severity"] == cfg["severity"].value


def test_correlate_skips_errored_hosts(tmp_path):
    good = tmp_path / "host-good.json"
    good.write_text(json.dumps({"fips_not_enforced": [{"value": "0"}]}))
    bad = tmp_path / "host-bad.json"
    bad.write_text("garbage{")
    hosts = fl.scan_fleet(tmp_path)
    corr = fl.correlate(hosts)
    # errored host not counted in denominator; single good host -> isolated
    assert corr["fips_not_enforced"]["count"] == 1
    assert corr["fips_not_enforced"]["scope"] == "isolated"


def test_correlate_empty_fleet():
    assert fl.correlate([]) == {}


# --------------------------------------------------------------------------- #
# fleet_summary
# --------------------------------------------------------------------------- #
def test_fleet_summary_counts():
    hosts = fl.scan_fleet(ROLLUP)
    s = fl.fleet_summary(hosts)
    assert s["hosts_total"] == 3
    assert s["hosts_scanned"] == 3
    assert s["hosts_clean"] == ["app03"]
    assert set(s["hosts_failing"]) == {"db02", "web01"}
    assert s["hosts_errored"] == []


def test_fleet_summary_systemic_bucket():
    hosts = fl.scan_fleet(SYSTEMIC)
    s = fl.fleet_summary(hosts)
    assert s["systemic_findings"] == ["fips_not_enforced"]
    assert "ssh_root_login_permitted" in s["isolated_findings"]


def test_fleet_summary_controls_failing_dedup():
    hosts = fl.scan_fleet(ROLLUP)
    s = fl.fleet_summary(hosts)
    assert s["controls_failing"] == sorted({"SC-13", "AU-3", "AC-6(2)", "AC-3"})


def test_fleet_summary_with_errored_host(tmp_path):
    (tmp_path / "host-ok.json").write_text(json.dumps({"fips_not_enforced": []}))
    (tmp_path / "host-x.json").write_text("not json")
    s = fl.fleet_summary(fl.scan_fleet(tmp_path))
    assert s["hosts_errored"] == ["x"]
    assert s["hosts_scanned"] == 1


# --------------------------------------------------------------------------- #
# baseline drift
# --------------------------------------------------------------------------- #
def test_pick_baseline_auto_cleanest():
    hosts = fl.scan_fleet(ROLLUP)
    base = fl.pick_baseline(hosts)
    assert base.host == "app03"   # the only clean host


def test_pick_baseline_explicit():
    hosts = fl.scan_fleet(ROLLUP)
    base = fl.pick_baseline(hosts, "web01")
    assert base.host == "web01"


def test_pick_baseline_explicit_missing_returns_none():
    hosts = fl.scan_fleet(ROLLUP)
    assert fl.pick_baseline(hosts, "nope") is None


def test_pick_baseline_empty():
    assert fl.pick_baseline([]) is None


def test_baseline_drift_regressions():
    hosts = fl.scan_fleet(ROLLUP)
    base = fl.pick_baseline(hosts)        # app03, clean
    d = fl.baseline_drift(hosts, base)
    assert d["baseline"] == "app03"
    assert set(d["drifted_hosts"]) == {"db02", "web01"}
    assert d["drift"]["db02"]["regressions"] == sorted(
        ["fips_not_enforced", "audit_daemon_not_running"])
    assert set(d["drift"]["db02"]["regression_controls"]) == {"SC-13", "AU-3"}


def test_baseline_drift_improvements_direction():
    # baseline is the *worst* host: others look like improvements.
    hosts = fl.scan_fleet(ROLLUP)
    base = fl.pick_baseline(hosts, "db02")
    d = fl.baseline_drift(hosts, base)
    # app03 (clean) is strictly better -> improvements, no regressions
    assert d["drift"]["app03"]["improvements"] == sorted(
        ["fips_not_enforced", "audit_daemon_not_running"])
    assert d["drift"]["app03"]["regressions"] == []
    assert d["drift"]["app03"]["drifted"] is True


def test_baseline_drift_excludes_baseline_itself():
    hosts = fl.scan_fleet(ROLLUP)
    base = fl.pick_baseline(hosts, "app03")
    d = fl.baseline_drift(hosts, base)
    assert "app03" not in d["drift"]


def test_baseline_drift_no_drift_when_identical():
    a = fl.HostResult("a", "a", {"fips_not_enforced": 1})
    b = fl.HostResult("b", "b", {"fips_not_enforced": 1})
    d = fl.baseline_drift([a, b], a)
    assert d["drifted_hosts"] == []
    assert d["drift"]["b"]["drifted"] is False


# --------------------------------------------------------------------------- #
# POA&M generation
# --------------------------------------------------------------------------- #
FIXED_EPOCH = 1_750_000_000  # deterministic for date assertions


def test_poam_items_one_row_per_control_host():
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    # db02 has 2 failing, web01 has 2 failing, app03 clean -> 4 rows
    assert len(items) == 4
    assets = {r["Affected Asset"] for r in items}
    assert assets == {"db02", "web01"}


def test_poam_item_ids_unique_and_sequential():
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    ids = [r["POA&M Item ID"] for r in items]
    assert len(ids) == len(set(ids))


def test_poam_cat_level_from_severity():
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    fips = next(r for r in items if r["Security Control Number (NC/NA)"] == "SC-13")
    assert fips["Raw Severity"] == "CAT I"        # VERY_HIGH
    ssh = next(r for r in items if r["Security Control Number (NC/NA)"] == "AC-6(2)")
    assert ssh["Raw Severity"] == "CAT II"        # HIGH


def test_poam_scheduled_date_offset_by_severity():
    import time
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    fips = next(r for r in items if r["Security Control Number (NC/NA)"] == "SC-13")
    ssh = next(r for r in items if r["Security Control Number (NC/NA)"] == "AC-6(2)")
    # VERY_HIGH -> 30 days; HIGH -> 90 days
    exp_fips = time.strftime("%Y-%m-%d", time.gmtime(FIXED_EPOCH + 30 * 86400))
    exp_ssh = time.strftime("%Y-%m-%d", time.gmtime(FIXED_EPOCH + 90 * 86400))
    assert fips["Scheduled Completion Date"] == exp_fips
    assert ssh["Scheduled Completion Date"] == exp_ssh


def test_poam_security_checks_include_stig_and_cci():
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    fips = next(r for r in items if r["Security Control Number (NC/NA)"] == "SC-13")
    assert "V-238298" in fips["Security Checks"]
    assert "CCI-002450" in fips["Security Checks"]


def test_poam_office_propagates():
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, office="J6/CYBER", assessed_at=FIXED_EPOCH)
    assert all(r["Office/Org"] == "J6/CYBER" for r in items)


def test_poam_deterministic_ordering():
    hosts = fl.scan_fleet(ROLLUP)
    a = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    b = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    assert [r["POA&M Item ID"] for r in a] == [r["POA&M Item ID"] for r in b]
    # sorted by host first
    assert a[0]["Affected Asset"] == "db02"


def test_poam_skips_errored_hosts(tmp_path):
    (tmp_path / "host-ok.json").write_text(
        json.dumps({"fips_not_enforced": [{"value": "0"}]}))
    (tmp_path / "host-bad.json").write_text("nope{")
    items = fl.poam_items(fl.scan_fleet(tmp_path), assessed_at=FIXED_EPOCH)
    assert {r["Affected Asset"] for r in items} == {"ok"}


def test_poam_empty_fleet():
    assert fl.poam_items([]) == []


def test_poam_attack_column_populated():
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    fips = next(r for r in items if r["Security Control Number (NC/NA)"] == "SC-13")
    assert fips["MITRE ATT&CK"] == STIG_PACK["fips_not_enforced"]["attack"]


# --------------------------------------------------------------------------- #
# POA&M serialisation
# --------------------------------------------------------------------------- #
def test_poam_csv_header_and_rows():
    hosts = fl.scan_fleet(ROLLUP)
    items = fl.poam_items(hosts, assessed_at=FIXED_EPOCH)
    text = fl.poam_to_csv(items)
    lines = text.strip().splitlines()
    assert lines[0].startswith("POA&M Item ID,")
    assert len(lines) == 1 + len(items)


def test_poam_csv_rfc4180_quotes_commas():
    # The description contains parentheses + the office may contain commas.
    items = fl.poam_items(fl.scan_fleet(ROLLUP),
                          office="A, B, C", assessed_at=FIXED_EPOCH)
    text = fl.poam_to_csv(items)
    assert '"A, B, C"' in text


def test_poam_csv_roundtrips_via_csv_module():
    import csv
    import io
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=FIXED_EPOCH)
    text = fl.poam_to_csv(items)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == len(items)
    assert rows[0]["Affected Asset"] == items[0]["Affected Asset"]


def test_poam_json_shape():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=FIXED_EPOCH)
    data = json.loads(fl.poam_to_json(items))
    assert data["count"] == len(items)
    assert data["poam_items"][0]["Affected Asset"] == items[0]["Affected Asset"]


def test_poam_columns_constant_matches_rows():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=FIXED_EPOCH)
    for r in items:
        assert set(r.keys()) == set(fl.POAM_COLUMNS)


# --------------------------------------------------------------------------- #
# console / report rendering
# --------------------------------------------------------------------------- #
def test_render_fleet_report_systemic_section():
    hosts = fl.scan_fleet(SYSTEMIC)
    base = fl.pick_baseline(hosts)
    drift = fl.baseline_drift(hosts, base) if base else None
    out = fl.render_fleet_report(hosts, drift)
    assert "FLEET CORRELATION REPORT" in out
    assert "SYSTEMIC" in out
    assert "Cryptographic" not in out  # title resolution is the feeds layer's job
    assert "FIPS 140 mode disabled" in out


def test_render_fleet_report_isolated_section():
    hosts = fl.scan_fleet(ROLLUP)
    out = fl.render_fleet_report(hosts)
    assert "ISOLATED" in out


def test_render_fleet_report_classification_banner():
    hosts = fl.scan_fleet(ROLLUP)
    out = fl.render_fleet_report(hosts, classification="UNCLASSIFIED//TEST")
    assert out.count("UNCLASSIFIED//TEST") == 2  # top + bottom banner


def test_render_fleet_report_is_ascii_safe():
    # Must not emit chars that crash a cp1252 console.
    hosts = fl.scan_fleet(SYSTEMIC)
    base = fl.pick_baseline(hosts)
    out = fl.render_fleet_report(hosts, fl.baseline_drift(hosts, base))
    out.encode("cp1252")  # raises if any char is unencodable


def test_render_fleet_report_drift_section():
    hosts = fl.scan_fleet(ROLLUP)
    base = fl.pick_baseline(hosts)
    out = fl.render_fleet_report(hosts, fl.baseline_drift(hosts, base))
    assert "BASELINE DRIFT" in out
    assert "db02" in out


# --------------------------------------------------------------------------- #
# remediation tables sanity
# --------------------------------------------------------------------------- #
def test_remediation_days_cover_all_severities():
    for s in Severity:
        assert s in fl.REMEDIATION_DAYS


def test_cat_level_covers_all_severities():
    for s in Severity:
        assert s in fl.CAT_LEVEL


def test_very_high_is_fastest_remediation():
    assert fl.REMEDIATION_DAYS[Severity.VERY_HIGH] < fl.REMEDIATION_DAYS[Severity.LOW]


# --------------------------------------------------------------------------- #
# additional edge cases
# --------------------------------------------------------------------------- #
def test_poam_csv_is_ascii_safe():
    items = fl.poam_items(fl.scan_fleet(SYSTEMIC), assessed_at=FIXED_EPOCH)
    fl.poam_to_csv(items).encode("cp1252")  # raises if unencodable


def test_correlate_coverage_is_fraction():
    h = [fl.HostResult(f"h{i}", f"h{i}",
                       {"fips_not_enforced": 1} if i == 0 else {})
         for i in range(4)]
    corr = fl.correlate(h)
    assert corr["fips_not_enforced"]["coverage"] == 0.25


def test_hostresult_controls_empty_when_clean():
    assert fl.HostResult("a", "a", {}).controls() == set()


def test_baseline_drift_marks_drifted_flag_true_on_regression():
    base = fl.HostResult("base", "base", {})
    worse = fl.HostResult("worse", "worse", {"fips_not_enforced": 1})
    d = fl.baseline_drift([base, worse], base)
    assert d["drift"]["worse"]["drifted"] is True
    assert d["drift"]["worse"]["regression_controls"] == ["SC-13"]


def test_fleet_summary_widespread_bucket():
    h = [fl.HostResult("a", "a", {"selinux_not_enforcing": 1}),
         fl.HostResult("b", "b", {"selinux_not_enforcing": 1}),
         fl.HostResult("c", "c", {})]
    s = fl.fleet_summary(h)
    assert "selinux_not_enforcing" in s["widespread_findings"]


def test_poam_item_id_includes_host():
    items = fl.poam_items(fl.scan_fleet(ROLLUP), assessed_at=FIXED_EPOCH)
    assert all(r["POA&M Item ID"].split("-")[0] == r["Affected Asset"]
               for r in items)
