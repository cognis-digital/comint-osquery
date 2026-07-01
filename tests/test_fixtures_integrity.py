"""Integrity + integration tests over the bundled demo fixture directories.

Every ``demos/NN-name/`` directory must: hold valid JSON in the osquery shape,
carry a SCENARIO.md, scan without crashing, and (where it fails) map every
finding to a known STIG query. Also runs each fixture through the full
scan -> enrich -> poam pipeline offline.
"""
import json
from pathlib import Path

import pytest

from cognis_mil import Severity
from comint_osquery.core import scan, STIG_PACK
from comint_osquery import fleet as fl, feeds

REPO_ROOT = Path(__file__).parent.parent
DEMOS = REPO_ROOT / "demos"
FIXTURE_CACHE = REPO_ROOT / "tests" / "fixtures" / "feeds-cache"

# fixture directories = NN-name (hyphen), not NN_name.py scripts
FIXTURE_DIRS = sorted(
    d for d in DEMOS.iterdir()
    if d.is_dir() and not d.name.startswith("__") and "-" in d.name
)
JSON_FILES = sorted(p for d in FIXTURE_DIRS for p in d.glob("*.json"))


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    yield


def test_there_are_fixture_dirs():
    assert len(FIXTURE_DIRS) >= 12


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_dir_has_scenario_md(d):
    assert (d / "SCENARIO.md").exists()


@pytest.mark.parametrize("jf", JSON_FILES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_json_is_parseable_or_intentional_parse_demo(jf):
    text = jf.read_text()
    # the 10-parse-error fixture is intentionally malformed
    if jf.parent.name == "10-parse-error":
        with pytest.raises(json.JSONDecodeError):
            json.loads(text)
    else:
        data = json.loads(text)
        assert isinstance(data, dict)


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_scan_does_not_crash(d):
    r = scan(str(d))
    assert r.tool_name == "comint-osquery"
    assert r.items_scanned >= 0


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_findings_map_to_known_queries_or_parse(d):
    r = scan(str(d))
    for f in r.findings:
        # every non-parse finding's control must appear in the pack
        if f.id != "CO-PARSE":
            assert f.nist_800_53 in {c["nist"] for c in STIG_PACK.values()}


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_enrich_pipeline_offline(d):
    r = scan(str(d))
    summary = feeds.enrich_result(r, offline=True)
    # summary keyed by finding id, never raises offline
    assert set(summary) == {f.id for f in r.findings}


@pytest.mark.parametrize("d", FIXTURE_DIRS, ids=lambda d: d.name)
def test_poam_pipeline(d):
    hosts = fl.scan_fleet(d)
    items = fl.poam_items(hosts, assessed_at=0)
    # one row per (failing control, host); all columns present
    for it in items:
        assert set(it.keys()) == set(fl.POAM_COLUMNS)
        assert it["Raw Severity"].startswith("CAT")


def test_scenario_md_nonempty():
    for d in FIXTURE_DIRS:
        assert (d / "SCENARIO.md").read_text().strip()
