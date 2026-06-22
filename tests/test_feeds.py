"""Offline tests for the data-feed enrichment layer.

These NEVER hit the network: COGNIS_FEEDS_CACHE is pointed at the committed
trimmed fixture cache and every feed access uses offline=True. Real feed
content (NIST 800-53 rev5 OSCAL catalog + CTID ATT&CK<->800-53 mappings),
trimmed to the controls/techniques this tool references.
"""
import os
from pathlib import Path

import pytest

FIXTURE_CACHE = Path(__file__).parent / "fixtures" / "feeds-cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    # Point the ingestion engine at the committed fixture cache (no network).
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    yield


def test_fixture_cache_present():
    assert (FIXTURE_CACHE / "oscal-800-53-rev5-catalog.data").exists()
    assert (FIXTURE_CACHE / "attack-nist-mappings.data").exists()


def test_relevant_catalog_is_filtered():
    from comint_osquery import feeds
    cat = feeds.relevant_catalog()
    ids = {f["id"] for f in cat["feeds"]}
    assert ids == {"oscal-800-53-rev5-catalog", "attack-nist-mappings"}


def test_control_id_normalisation():
    from comint_osquery.feeds import _to_oscal_id
    assert _to_oscal_id("AC-6(2)") == "ac-6.2"
    assert _to_oscal_id("IA-2(11)") == "ia-2.11"
    assert _to_oscal_id("SC-13") == "sc-13"


def test_oscal_resolves_official_titles():
    from comint_osquery import feeds
    titles = feeds.control_titles(offline=True)
    # Real NIST SP 800-53 rev5 control titles.
    assert titles["ia-5"] == "Authenticator Management"
    assert titles["ac-6"] == "Least Privilege"
    assert titles["sc-13"] == "Cryptographic Protection"
    assert titles["au-3"] == "Content of Audit Records"


def test_resolve_control_title_handles_enhancement_notation():
    from comint_osquery import feeds
    titles = feeds.control_titles(offline=True)
    assert feeds.resolve_control_title("AC-6(2)", titles) == \
        "Non-privileged Access for Nonsecurity Functions"
    assert feeds.resolve_control_title("ZZ-99", titles) == ""


def test_attack_mappings_expand_countermeasures():
    from comint_osquery import feeds
    idx = feeds.attack_control_index(offline=True)
    # T1078 (Valid Accounts) maps to a set of 800-53 controls per CTID.
    cms = feeds.countermeasure_controls("T1078", idx)
    assert "AC-02" in cms and "AC-06" in cms
    # unknown technique -> empty list, no crash
    assert feeds.countermeasure_controls("T9999", idx) == []


def test_enrich_result_offline():
    from comint_osquery import feeds
    from comint_osquery.core import scan

    demos = Path(__file__).parent.parent / "demos" / "01-failing-host"
    result = scan(str(demos))
    summary = feeds.enrich_result(result, offline=True)

    assert summary, "expected at least one enriched finding"
    # Every finding got an official control title and countermeasure expansion.
    for f in result.findings:
        s = summary[f.id]
        assert s["control_title"], f"{f.id} missing resolved NIST title"
        assert f.control_title == s["control_title"]
        assert isinstance(f.attack_countermeasures, list)
    # The FIPS finding (SC-13) resolves to the real catalog title.
    fips = [f for f in result.findings if "FIPS" in f.id]
    assert fips and fips[0].control_title == "Cryptographic Protection"


def test_enrich_adds_defense_in_depth_controls():
    from comint_osquery import feeds
    from comint_osquery.core import scan

    demos = Path(__file__).parent.parent / "demos" / "01-failing-host"
    result = scan(str(demos))
    feeds.enrich_result(result, offline=True)
    # SSH finding maps to ATT&CK T1021.004; CTID expands it beyond the single
    # STIG control to a defense-in-depth set including AC-17 (Remote Access).
    ssh = [f for f in result.findings if "SSH" in f.id]
    assert ssh
    assert any(c.startswith("AC-") for c in ssh[0].attack_countermeasures)


def test_offline_missing_feed_raises_not_network(tmp_path, monkeypatch):
    """offline=True with nothing cached raises FileNotFoundError, never a fetch."""
    import comint_osquery.datafeeds as df

    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))  # empty cache
    with pytest.raises(FileNotFoundError):
        df.get("attack-nist-mappings", offline=True,
               catalog={"feeds": [{"id": "attack-nist-mappings", "format": "json",
                                   "url": "http://0.0.0.0"}]})
