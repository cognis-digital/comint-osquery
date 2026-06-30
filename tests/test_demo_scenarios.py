"""The runnable demo scenarios (demos/NN_name.py) must execute and exit 0.

These drive the real comint_osquery / cognis_mil API over the bundled offline
fixtures. We import each module and call main(); any exception or stray exit
fails the test. Feed enrichment is served from the committed fixture cache.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DEMOS = REPO_ROOT / "demos"
FIXTURE_CACHE = REPO_ROOT / "tests" / "fixtures" / "feeds-cache"

SCENARIOS = [
    "01_isso_assessment",
    "02_soc_detection",
    "03_sysadmin_fleet",
    "04_auditor_poam",
    "05_airgap_enrichment",
]


@pytest.fixture(autouse=True)
def _offline_and_path(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    # demos import `_common` and sibling modules by bare name.
    monkeypatch.syspath_prepend(str(DEMOS))
    yield


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario_runs_and_exits_zero(name, capsys):
    mod = importlib.import_module(name)
    importlib.reload(mod)  # re-bind to the patched sys.path / env
    mod.main()  # must not raise or SystemExit
    out = capsys.readouterr().out
    assert out.strip(), f"{name} produced no output"


def test_run_all_imports_every_scenario():
    run_all = importlib.import_module("run_all")
    importlib.reload(run_all)
    assert set(run_all.SCENARIOS) == set(SCENARIOS)
    # files actually exist
    for name in run_all.SCENARIOS:
        assert (DEMOS / f"{name}.py").exists()


def test_common_points_feed_cache_at_fixture(monkeypatch):
    # _common must default the feed cache to the committed fixture cache.
    monkeypatch.delenv("COGNIS_FEEDS_CACHE", raising=False)
    sys.path.insert(0, str(DEMOS))
    common = importlib.import_module("_common")
    importlib.reload(common)
    assert os.environ["COGNIS_FEEDS_CACHE"] == str(FIXTURE_CACHE)
