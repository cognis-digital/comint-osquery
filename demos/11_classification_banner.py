"""Scenario 11 - security officer: build + validate CAPCO-shape banners.

Reports on cleared systems carry a classification banner. This tool ships a
CAPCO-*shape* validator (``cognis_mil.ClassificationBanner``) — it validates the
form, never invents real markings. This demo builds several banners, shows the
rendered line, and demonstrates the validator rejecting an impossible marking
(UNCLASSIFIED carrying an SCI compartment) — all placeholder content.

Offline: pure computation, no fixtures.
"""
from _common import rule, section
from cognis_mil.classmark import ClassificationBanner


def main() -> None:
    rule("SECURITY OFFICER  -  CAPCO-shape banner build + validation (placeholders)")

    section("Rendering valid banner shapes (operator-supplied content)")
    examples = [
        ClassificationBanner.placeholder(),
        ClassificationBanner(level="SECRET", dissem=["NOFORN"]),
        ClassificationBanner(level="TOP SECRET", sci=["SI", "TK"], dissem=["NOFORN"]),
        ClassificationBanner(level="UNCLASSIFIED", nonic=["CUI//SP-PRVCY"]),
    ]
    for b in examples:
        ok, _ = b.validate()
        print(f"  [{'valid' if ok else 'INVALID':<7}] {b.render()}")

    section("The validator rejects impossible markings")
    bad = ClassificationBanner(level="UNCLASSIFIED", sci=["SI"])
    ok, errs = bad.validate()
    print(f"  UNCLASSIFIED + SCI compartment -> valid={ok}")
    for e in errs:
        print(f"    - {e}")

    bad2 = ClassificationBanner(level="ULTRA SECRET")
    ok2, errs2 = bad2.validate()
    print(f"  bogus base level 'ULTRA SECRET' -> valid={ok2}")
    for e in errs2:
        print(f"    - {e}")

    print("\n  Shape is validated; content is always operator-supplied placeholders.")


if __name__ == "__main__":
    main()
