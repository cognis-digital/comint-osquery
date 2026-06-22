import argparse
import json
import sys

from cognis_mil import make_cli

from . import __version__
from .core import scan


def _feeds_cli(argv):
    """`comint-osquery feeds <list|update|get|enrich> ...` — the data-feed layer.

    Restricted to this repo's relevant feeds (OSCAL 800-53 rev5 catalog +
    ATT&CK<->NIST mappings). Works offline with --offline (serve from cache).
    """
    from . import datafeeds, feeds

    p = argparse.ArgumentParser(prog="comint-osquery feeds",
                                description="Edge/air-gap data-feed layer (compliance domain).")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="List this repo's relevant feeds")
    pu = sub.add_parser("update", help="Fetch + cache feed(s)")
    pu.add_argument("ids", nargs="*", help="feed ids (default: all relevant)")
    pg = sub.add_parser("get", help="Print a cached/fetched feed")
    pg.add_argument("id")
    pg.add_argument("--offline", action="store_true")
    pe = sub.add_parser("enrich", help="Scan a target and enrich findings with feed data")
    pe.add_argument("target", nargs="?", default=".")
    pe.add_argument("--offline", action="store_true")
    px = sub.add_parser("snapshot-export", help="Tar cache for air-gap sneakernet")
    px.add_argument("path")
    pi = sub.add_parser("snapshot-import", help="Import an air-gap snapshot")
    pi.add_argument("path")
    args = p.parse_args(argv)

    cat = feeds.relevant_catalog()

    if args.cmd == "list":
        for f in cat["feeds"]:
            age = datafeeds.cached_age_hours(f["id"])
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {f['id']:30} {f.get('domain',''):11} [{fresh}]  {f['name']}")
        return 0

    if args.cmd == "update":
        ids = args.ids or feeds.RELEVANT_FEEDS
        rc = 0
        for fid in ids:
            if fid not in feeds.RELEVANT_FEEDS:
                print(f"  {fid}: not a relevant feed for this repo", file=sys.stderr); rc = 1; continue
            try:
                pth = datafeeds.update(fid, catalog=cat)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as e:
                print(f"  {fid}: {e}", file=sys.stderr); rc = 1
        return rc

    if args.cmd == "get":
        if args.id not in feeds.RELEVANT_FEEDS:
            print(f"error: {args.id} is not a relevant feed for this repo", file=sys.stderr); return 1
        try:
            data = datafeeds.get(args.id, offline=args.offline, catalog=cat)
        except (KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr); return 1
        print(json.dumps(data, indent=2)[:4000] if isinstance(data, (dict, list)) else data[:4000])
        return 0

    if args.cmd == "enrich":
        try:
            result = scan(args.target)
            summary = feeds.enrich_result(result, offline=args.offline)
        except (FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr); return 1
        print(json.dumps({
            "tool": "comint-osquery",
            "target": args.target,
            "findings": result.total_findings(),
            "enrichment": summary,
        }, indent=2))
        return 0

    if args.cmd == "snapshot-export":
        print(f"exported {datafeeds.snapshot_export(args.path)} feed(s) -> {args.path}"); return 0
    if args.cmd == "snapshot-import":
        print(f"imported {datafeeds.snapshot_import(args.path)} feed(s) from {args.path}"); return 0
    return 1


def main():
    # `feeds` subcommand: edge/air-gap data-feed layer.
    if len(sys.argv) > 1 and sys.argv[1] == "feeds":
        sys.exit(_feeds_cli(sys.argv[2:]))
    make_cli("comint-osquery", scan, version=__version__)


if __name__ == "__main__":
    main()
