"""Tests for the cognis_mil severity/finding/scanresult model layer."""
import pytest

from cognis_mil.models import Finding, ScanResult, Severity, WEIGHTS


# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #
def test_critical_is_alias_for_very_high():
    assert Severity.CRITICAL is Severity.VERY_HIGH
    assert Severity.CRITICAL.value == "very_high"


def test_severity_from_string():
    assert Severity("high") is Severity.HIGH
    assert Severity("very_low") is Severity.VERY_LOW


def test_weights_defined_for_every_real_member():
    for s in Severity:
        assert s in WEIGHTS


def test_weights_monotonic():
    assert (WEIGHTS[Severity.VERY_HIGH] > WEIGHTS[Severity.HIGH]
            > WEIGHTS[Severity.MODERATE] > WEIGHTS[Severity.LOW]
            > WEIGHTS[Severity.VERY_LOW])


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
def test_finding_auto_weight():
    f = Finding("X", Severity.HIGH, "t")
    assert f.weight == WEIGHTS[Severity.HIGH]


def test_finding_accepts_string_severity():
    f = Finding("X", "moderate", "t")
    assert f.severity is Severity.MODERATE


def test_finding_explicit_weight_preserved():
    f = Finding("X", Severity.LOW, "t", weight=99.0)
    assert f.weight == 99.0


def test_finding_to_dict_stringifies_severity():
    d = Finding("X", Severity.HIGH, "t").to_dict()
    assert d["severity"] == "high"
    assert isinstance(d["severity"], str)


def test_finding_defaults_blank_crosswalks():
    f = Finding("X", Severity.LOW, "t")
    assert f.nist_800_53 == "" and f.disa_stig == "" and f.cci == ""


# --------------------------------------------------------------------------- #
# ScanResult scoring
# --------------------------------------------------------------------------- #
def test_empty_result_is_very_low():
    r = ScanResult("t").finalize()
    assert r.composite_score == 0.0
    assert r.risk_level == "Very Low"


def test_add_and_count():
    r = ScanResult("t")
    r.add(Finding("A", Severity.LOW, "a"))
    r.add(Finding("B", Severity.HIGH, "b"))
    assert r.total_findings() == 2
    assert len(r.all_findings()) == 2


def test_score_capped_at_100():
    r = ScanResult("t")
    for i in range(50):
        r.add(Finding(f"F{i}", Severity.VERY_HIGH, "x"))
    r.finalize()
    assert r.composite_score == 100.0


def test_score_scales_with_severity():
    low = ScanResult("t"); low.add(Finding("A", Severity.LOW, "a")); low.finalize()
    high = ScanResult("t"); high.add(Finding("A", Severity.VERY_HIGH, "a")); high.finalize()
    assert high.composite_score > low.composite_score


@pytest.mark.parametrize("n,expected_floor", [(1, "Very Low"), (20, "Moderate")])
def test_risk_level_bands(n, expected_floor):
    r = ScanResult("t")
    for i in range(n):
        r.add(Finding(f"F{i}", Severity.HIGH, "x"))
    r.finalize()
    assert r.risk_level in {"Very Low", "Low", "Moderate", "High", "Very High"}


def test_to_dict_shape():
    r = ScanResult("t", tool_version="9.9")
    r.add(Finding("A", Severity.HIGH, "a", nist_800_53="AC-2"))
    r.finalize()
    d = r.to_dict()
    assert d["tool_name"] == "t"
    assert d["tool_version"] == "9.9"
    assert d["findings"][0]["nist_800_53"] == "AC-2"
    assert "classification" in d


def test_default_classification_placeholder():
    r = ScanResult("t")
    assert "UNCLASSIFIED" in r.classification_placeholder


def test_finalize_returns_self():
    r = ScanResult("t")
    assert r.finalize() is r
