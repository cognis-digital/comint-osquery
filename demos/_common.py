"""Shared helpers for the runnable demo scenarios.

The ``demos/`` directory bundles two kinds of artifact:

  * ``NN-name/`` directories — osquery snapshot JSON fixtures (the tool's real
    input shape) plus a ``SCENARIO.md``. These are the offline data the demos
    feed into the real API.
  * ``NN_name.py`` scripts (this family) — runnable, narrated scenarios that
    drive the **real** ``comint_osquery`` / ``cognis_mil`` API over those
    fixtures. No network, no fabricated functions, exit 0.

Every scenario is self-contained: it rebuilds nothing on disk it can't throw
away, and points the data-feed engine at the committed fixture cache so feed
enrichment works fully offline.
"""
from __future__ import annotations

import os
import sys

# allow `python demos/NN_name.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")

# The committed, trimmed offline feed cache (OSCAL 800-53 rev5 catalog + the
# CTID ATT&CK<->800-53 crosswalk). Pointing COGNIS_FEEDS_CACHE here makes every
# `offline=True` feed read serve from disk — never the network.
FIXTURE_CACHE = os.path.join(REPO_ROOT, "tests", "fixtures", "feeds-cache")
os.environ.setdefault("COGNIS_FEEDS_CACHE", FIXTURE_CACHE)


def fixture(name: str) -> str:
    """Absolute path to a bundled demo fixture directory, e.g. ``01-failing-host``."""
    return os.path.join(DEMOS_DIR, name)


def rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def section(title: str) -> None:
    print("\n" + "-" * 72)
    print(f"  {title}")
    print("-" * 72)
