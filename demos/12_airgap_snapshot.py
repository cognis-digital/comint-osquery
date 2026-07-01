"""Scenario 12 - air-gap logistics: sneakernet the feed cache across the gap.

Before enriching on a disconnected enclave you first have to *get the feeds
there*. This demo exercises the REAL ``datafeeds.snapshot_export`` /
``snapshot_import`` round-trip: it exports the committed fixture feed cache to a
tarball (the thing you burn to media and carry across the air gap), imports it
into a fresh empty cache dir, and proves an ``offline=True`` control-title
lookup works from the imported cache — never touching the network.

Offline: uses the committed ``tests/fixtures/feeds-cache`` as the source cache.
"""
import os
import tempfile
from pathlib import Path

from _common import FIXTURE_CACHE, rule, section
from comint_osquery import datafeeds, feeds


def main() -> None:
    rule("AIR-GAP LOGISTICS  -  snapshot the feed cache, import it across the gap")

    section("Export the source cache to a sneakernet tarball")
    # source cache = the committed fixture cache
    os.environ["COGNIS_FEEDS_CACHE"] = FIXTURE_CACHE
    snap = Path(tempfile.mkdtemp(prefix="comint_snap_")) / "feeds.tar.gz"
    n = datafeeds.snapshot_export(str(snap))
    print(f"  exported {n} feed(s) -> {snap.name} ({snap.stat().st_size} bytes)")

    section("Import into a fresh (empty) cache on the far side")
    farside = Path(tempfile.mkdtemp(prefix="comint_farside_"))
    os.environ["COGNIS_FEEDS_CACHE"] = str(farside)
    imported = datafeeds.snapshot_import(str(snap))
    print(f"  imported {imported} feed(s) into {farside.name}/")
    print(f"  cache now holds: {sorted(p.name for p in farside.glob('*.data'))}")

    section("Resolve a control title from the imported cache, fully offline")
    titles = feeds.control_titles(offline=True)
    for cid in ("sc-13", "ia-5", "au-3"):
        print(f"  {cid.upper():<7} -> {titles.get(cid, '(unresolved)')}")

    print(f"\n  {len(titles)} control titles available offline on the far side.")
    print("  The enclave never reached the network — the cache came in on media.")


if __name__ == "__main__":
    main()
