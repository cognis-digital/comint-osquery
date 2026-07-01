"""Tests for the datafeeds ingestion engine (offline paths + air-gap snapshot).

Never hits the network: every test either points COGNIS_FEEDS_CACHE at a tmp
dir or uses offline=True against a pre-seeded cache. Exercises cache freshness,
error paths, format decoding, and the sneakernet snapshot export/import.
"""
import json
import time
from pathlib import Path

import pytest

import comint_osquery.datafeeds as df


@pytest.fixture(autouse=True)
def _tmp_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    yield tmp_path


def _seed(feed_id, payload, fmt="json", fetched_at=None):
    """Write a cache entry directly, bypassing the network."""
    data_path, meta_path = df._paths(feed_id)
    if isinstance(payload, (dict, list)):
        data_path.write_bytes(json.dumps(payload).encode())
    else:
        data_path.write_bytes(payload.encode() if isinstance(payload, str) else payload)
    meta_path.write_text(json.dumps({
        "feed": feed_id, "url": "https://example/x",
        "fetched_at": fetched_at if fetched_at is not None else time.time(),
        "bytes": 0, "format": fmt,
    }))
    return data_path


CAT = {"feeds": [{"id": "f-json", "url": "https://x", "format": "json"},
                 {"id": "f-text", "url": "https://x", "format": "csv"}]}


# --------------------------------------------------------------------------- #
# cache_dir / catalog
# --------------------------------------------------------------------------- #
def test_cache_dir_created(tmp_path):
    d = df.cache_dir()
    assert d.exists() and d.is_dir()


def test_load_catalog_default_has_feeds():
    cat = df.load_catalog()
    assert "feeds" in cat
    ids = {f["id"] for f in cat["feeds"]}
    assert "oscal-800-53-rev5-catalog" in ids


def test_load_catalog_missing_path(tmp_path):
    cat = df.load_catalog(str(tmp_path / "nope.json"))
    assert cat == {"feeds": []}


def test_list_feeds_filter_by_domain():
    feeds = df.list_feeds(domain="vuln")
    assert all(f.get("domain") == "vuln" for f in feeds)


def test_list_feeds_all():
    assert len(df.list_feeds()) >= 2


# --------------------------------------------------------------------------- #
# cached_age_hours
# --------------------------------------------------------------------------- #
def test_cached_age_none_when_absent():
    assert df.cached_age_hours("never-fetched") is None


def test_cached_age_recent_is_small():
    _seed("f-json", {"a": 1})
    age = df.cached_age_hours("f-json")
    assert age is not None and age < 1.0


def test_cached_age_old():
    _seed("f-json", {"a": 1}, fetched_at=time.time() - 48 * 3600)
    assert df.cached_age_hours("f-json") > 47


def test_cached_age_corrupt_meta_returns_none():
    _, meta = df._paths("f-json")
    meta.write_text("not json")
    assert df.cached_age_hours("f-json") is None


# --------------------------------------------------------------------------- #
# get() offline + format decode
# --------------------------------------------------------------------------- #
def test_get_offline_json_returns_dict():
    _seed("f-json", {"k": "v"})
    out = df.get("f-json", offline=True, catalog=CAT)
    assert out == {"k": "v"}


def test_get_offline_text_returns_str():
    _seed("f-text", "a,b,c\n1,2,3", fmt="csv")
    out = df.get("f-text", offline=True, catalog=CAT)
    assert isinstance(out, str)
    assert "a,b,c" in out


def test_get_offline_missing_raises():
    with pytest.raises(FileNotFoundError):
        df.get("f-json", offline=True, catalog=CAT)


def test_get_offline_serves_stale_without_refresh():
    _seed("f-json", {"stale": True}, fetched_at=time.time() - 999 * 3600)
    # offline: stale cache is served, no network attempt
    out = df.get("f-json", offline=True, catalog=CAT)
    assert out == {"stale": True}


def test_get_unknown_format_decodes_as_text():
    _seed("f-raw", "hello", fmt="raw")
    cat = {"feeds": [{"id": "f-raw", "url": "x", "format": "raw"}]}
    out = df.get("f-raw", offline=True, catalog=cat)
    assert out == "hello"


# --------------------------------------------------------------------------- #
# update() error path (unknown feed) — no network
# --------------------------------------------------------------------------- #
def test_update_unknown_feed_raises_keyerror():
    with pytest.raises(KeyError):
        df.update("does-not-exist", catalog=CAT)


# --------------------------------------------------------------------------- #
# air-gap snapshot export / import
# --------------------------------------------------------------------------- #
def test_snapshot_export_counts_feeds(tmp_path):
    _seed("f-json", {"a": 1})
    _seed("f-text", "x", fmt="csv")
    out = tmp_path / "snap.tar.gz"
    n = df.snapshot_export(str(out))
    assert out.exists()
    assert n == 2


def test_snapshot_roundtrip_into_new_cache(tmp_path, monkeypatch):
    _seed("f-json", {"roundtrip": True})
    snap = tmp_path / "snap.tar.gz"
    df.snapshot_export(str(snap))
    # point at a fresh empty cache and import
    fresh = tmp_path / "fresh-cache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(fresh))
    n = df.snapshot_import(str(snap))
    assert n == 1
    out = df.get("f-json", offline=True, catalog=CAT)
    assert out == {"roundtrip": True}


def test_snapshot_import_ignores_dotfiles(tmp_path, monkeypatch):
    # craft a tar with a hidden + a traversal-looking member; import must skip
    import tarfile
    import io
    # isolate the cache dir from tmp_path so we can prove no parent traversal
    cachedir = tmp_path / "thecache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(cachedir))
    snap = tmp_path / "evil.tar.gz"
    with tarfile.open(snap, "w:gz") as tar:
        for name, body in ((".hidden", b"x"), ("../escape.data", b"y"),
                            ("legit.data", b"z")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    df.snapshot_import(str(snap))
    cache = df.cache_dir()
    # basename-only extraction: escape.data lands flat, hidden skipped
    assert not (cache / ".hidden").exists()
    assert (cache / "legit.data").exists()
    # traversal is neutralised: `../escape.data` is stripped to its basename
    # and lands INSIDE the cache dir, never in the parent.
    assert (cache / "escape.data").exists()
    assert not (tmp_path / "escape.data").exists()


def test_snapshot_export_empty_cache(tmp_path):
    out = tmp_path / "empty.tar.gz"
    n = df.snapshot_export(str(out))
    assert n == 0
    assert out.exists()
