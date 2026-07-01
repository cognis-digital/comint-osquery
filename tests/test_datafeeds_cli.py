"""Tests for the standalone datafeeds.main() CLI (offline paths only)."""
import json
import time
from pathlib import Path

import pytest

import comint_osquery.datafeeds as df


@pytest.fixture(autouse=True)
def _tmp_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    yield tmp_path


def _seed(feed_id, payload, fmt="json"):
    data_path, meta_path = df._paths(feed_id)
    data_path.write_bytes(json.dumps(payload).encode())
    meta_path.write_text(json.dumps({
        "feed": feed_id, "url": "x", "fetched_at": time.time(),
        "bytes": 0, "format": fmt}))


def test_cli_list(capsys):
    rc = df.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "oscal-800-53-rev5-catalog" in out


def test_cli_list_domain_filter(capsys):
    rc = df.main(["list", "--domain", "vuln"])
    assert rc == 0


def test_cli_get_offline(capsys):
    _seed("oscal-800-53-rev5-catalog", {"catalog": {"groups": []}})
    rc = df.main(["get", "oscal-800-53-rev5-catalog", "--offline"])
    assert rc == 0
    assert "catalog" in capsys.readouterr().out


def test_cli_get_offline_missing_errors(capsys):
    rc = df.main(["get", "oscal-800-53-rev5-catalog", "--offline"])
    assert rc == 1
    assert "error" in capsys.readouterr().err


def test_cli_no_command_prints_help(capsys):
    rc = df.main([])
    assert rc == 1


def test_cli_snapshot_export_import(tmp_path, capsys, monkeypatch):
    _seed("oscal-800-53-rev5-catalog", {"catalog": {"groups": []}})
    snap = tmp_path / "snap.tar.gz"
    assert df.main(["snapshot-export", str(snap)]) == 0
    assert snap.exists()
    fresh = tmp_path / "fresh"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(fresh))
    assert df.main(["snapshot-import", str(snap)]) == 0
    assert "imported" in capsys.readouterr().out
