"""Assert the runnable demos produce the *content* they claim, not just exit 0.

Each demo is imported and run with its output captured; we assert on the
distinctive lines each scenario documents. Offline: feed cache pinned to the
committed fixture cache; demos import siblings by bare name.
"""
import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DEMOS = REPO_ROOT / "demos"
FIXTURE_CACHE = REPO_ROOT / "tests" / "fixtures" / "feeds-cache"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    monkeypatch.syspath_prepend(str(DEMOS))
    yield


def _run(name, capsys):
    mod = importlib.import_module(name)
    importlib.reload(mod)
    mod.main()
    return capsys.readouterr().out


def test_06_all_six_formats(capsys):
    out = _run("06_multiformat_export", capsys)
    for token in ("JSON", "SARIF", "Markdown", "CSV", "OSCAL", "Console"):
        assert token in out


def test_07_flags_bare_list_and_parse_errors(capsys):
    out = _run("07_parse_error_handling", capsys)
    assert "PARSE ERROR" in out
    assert "CO-PARSE" in out or "parse diagnostic" in out


def test_08_pack_validated(capsys):
    out = _run("08_pack_deployment", capsys)
    assert "stig_pack.yaml" in out
    assert "snapshot mode" in out or "snapshot" in out


def test_09_fleet_json_signals(capsys):
    out = _run("09_fleet_json_export", capsys)
    assert "systemic findings" in out
    assert "coverage=" in out


def test_10_poam_json_per_asset(capsys):
    out = _run("10_poam_json", capsys)
    assert "POA&M item" in out
    assert "-001" in out


def test_11_banner_valid_and_invalid(capsys):
    out = _run("11_classification_banner", capsys)
    assert "valid" in out
    assert ("INVALID" in out) or ("valid=False" in out)


def test_12_airgap_snapshot_roundtrip(capsys):
    out = _run("12_airgap_snapshot", capsys)
    assert "exported" in out
    assert "imported" in out
    assert "Cryptographic Protection" in out  # sc-13 resolved offline


def test_13_expansion_factor(capsys):
    out = _run("13_countermeasure_expansion", capsys)
    assert "countermeasure" in out.lower()
    assert "expansion factor" in out


def test_14_all_tampers_caught(capsys):
    out = _run("14_audit_chain", capsys)
    assert out.count("intact=False") >= 3   # three tampers all detected
    assert "intact=True" in out


def test_15_gate_matrix(capsys):
    out = _run("15_fail_on_gating", capsys)
    assert "very_high" in out
    assert "clean baseline" in out


def test_16_titles_resolved(capsys):
    out = _run("16_control_titles", capsys)
    assert "Cryptographic Protection" in out


def test_17_regression_and_improvement(capsys):
    out = _run("17_drift_regression", capsys)
    assert "DRIFT-" in out
    assert "DRIFT+" in out


def test_18_all_five_steps(capsys):
    out = _run("18_full_rmf_workflow", capsys)
    for step in ("1. Scan", "2. Correlate", "3. Enrich", "4. Emit", "5. Prove"):
        assert step in out
    assert "intact=True" in out


def test_19_attack_matrix(capsys):
    out = _run("19_attack_coverage_matrix", capsys)
    assert "distinct techniques covered" in out
    assert "T1078" in out


def test_20_connect_emit_graceful(capsys):
    out = _run("20_connect_emit", capsys)
    # either the bridge ran (STIX/Sigma) or it degraded gracefully — both exit 0
    assert ("STIX" in out) or ("soft dependency" in out)
