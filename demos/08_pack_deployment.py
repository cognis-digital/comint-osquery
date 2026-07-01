"""Scenario 8 - fleet engineer: emit the osquery pack to disk and validate it.

The osquery STIG pack is the artifact you actually deploy to endpoints. This
demo writes the REAL YAML pack to a file with ``core.emit_query_pack(out=...)``,
re-reads it, and confirms every scheduled query, its interval, and its snapshot
flag survived the round-trip — the pre-flight check before pushing to the fleet
agent.

Offline: writes the pack to a temp file.
"""
import tempfile
from pathlib import Path

from _common import rule, section
from comint_osquery.core import STIG_PACK, emit_query_pack


def main() -> None:
    rule("FLEET ENGINEER  -  emit + validate the osquery STIG pack")

    out = Path(tempfile.mkdtemp(prefix="comint_pack_")) / "stig_pack.yaml"
    text = emit_query_pack(out)
    print(f"\n  wrote {out.name} ({out.stat().st_size} bytes)")

    section("Re-read and validate the deployed pack")
    reread = out.read_text()
    assert reread == text, "round-trip mismatch"
    n_queries = reread.count("interval: 3600")
    n_snapshot = reread.count("snapshot: true")
    print(f"  queries with interval=3600 : {n_queries}")
    print(f"  queries in snapshot mode    : {n_snapshot}")
    print(f"  pack query definitions      : {len(STIG_PACK)}")
    assert n_queries == len(STIG_PACK) == n_snapshot

    section("Every query is present and STIG-tagged")
    for name, cfg in STIG_PACK.items():
        present = name in reread and cfg["stig"] in reread
        print(f"  [{'OK' if present else '!!'}] {name:<28} {cfg['stig']}")

    print(f"\n  Deploy with: osqueryi --config_path={out.name}")
    print("  Failing rows from these queries become STIG findings on ingest.")


if __name__ == "__main__":
    main()
