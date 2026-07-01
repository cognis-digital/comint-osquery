"""Scenario 16 - RMF author: resolve bare control ids to official NIST titles.

A finding carries ``SC-13``; the RMF package wants "Cryptographic Protection".
This demo runs the REAL ``feeds`` control-title resolver offline against the
committed OSCAL 800-53 rev5 catalog, resolving every finding's control id —
including enhancement notation like ``AC-6(2)`` -> ``ac-6.2`` -> its official
enhancement title — and flags any id the catalog can't resolve (a crosswalk
gap worth investigating).

Offline: served from the committed fixture feed cache.
"""
from _common import fixture, rule, section
from comint_osquery.core import scan
from comint_osquery import feeds


def main() -> None:
    rule("RMF AUTHOR  -  resolve control ids to official NIST 800-53 titles")

    result = scan(fixture("01-failing-host"))
    titles = feeds.control_titles(offline=True)
    print(f"\n  loaded {len(titles)} control titles from the OSCAL catalog (offline)")

    section("Each finding's control id -> official title")
    resolved = unresolved = 0
    for f in result.findings:
        title = feeds.resolve_control_title(f.nist_800_53, titles)
        if title:
            resolved += 1
            print(f"  {f.nist_800_53:<10} -> {title}")
        else:
            unresolved += 1
            print(f"  {f.nist_800_53:<10} -> (UNRESOLVED — crosswalk gap)")

    section("Enhancement notation is normalised before lookup")
    for human in ("AC-6(2)", "IA-2(11)", "SC-13"):
        oscal = feeds._to_oscal_id(human)
        print(f"  {human:<10} -> {oscal:<10} -> {titles.get(oscal, '(unresolved)')}")

    print(f"\n  {resolved} resolved, {unresolved} unresolved. Titles come straight from")
    print("  the authoritative catalog — no hand-maintained mapping to drift.")


if __name__ == "__main__":
    main()
