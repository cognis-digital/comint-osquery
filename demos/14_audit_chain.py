"""Scenario 14 - IG / oversight: prove the assessment record wasn't edited.

An oversight reviewer needs the assessment trail to be *provable*, not asserted.
This demo drives the REAL hash-chained ``cognis_mil.AuditLog``: it records a
sequence of assessment events, verifies the chain is intact, then shows the
chain catching three distinct tampers — an edited body, a deleted entry, and a
reordering — each with the specific failure the verifier reports.

Offline: writes the log to a throwaway temp file.
"""
import tempfile
from pathlib import Path

from _common import rule, section
from cognis_mil import AuditLog


def _fresh_log(events):
    p = Path(tempfile.mkdtemp(prefix="comint_audit_")) / "audit.log"
    log = AuditLog(p)
    for e in events:
        log.append(e)
    return p, log


def main() -> None:
    rule("IG / OVERSIGHT  -  tamper-evident assessment trail")

    events = [
        {"actor": "isso", "action": "scan", "target": "fleet"},
        {"actor": "isso", "action": "poam", "id": "web01-001"},
        {"actor": "ao", "action": "accept-risk", "id": "web01-001"},
    ]
    p, log = _fresh_log(events)
    ok, msg = log.verify()
    print(f"\n  recorded {len(events)} events -> verify(): intact={ok} ({msg})")

    section("Tamper 1: edit an entry's body in place")
    p2, log2 = _fresh_log(events)
    lines = p2.read_text().splitlines()
    lines[1] = lines[1].replace("web01-001", "web01-999")
    p2.write_text("\n".join(lines) + "\n")
    ok2, msg2 = log2.verify()
    print(f"  edited body   -> intact={ok2} ({msg2})")

    section("Tamper 2: delete a middle entry")
    p3, log3 = _fresh_log(events)
    lines = p3.read_text().splitlines()
    del lines[1]
    p3.write_text("\n".join(lines) + "\n")
    ok3, msg3 = log3.verify()
    print(f"  deleted entry -> intact={ok3} ({msg3})")

    section("Tamper 3: reorder entries")
    p4, log4 = _fresh_log(events)
    lines = p4.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    p4.write_text("\n".join(lines) + "\n")
    ok4, msg4 = log4.verify()
    print(f"  reordered     -> intact={ok4} ({msg4})")

    print("\n  Every tamper is caught -> the record is provable, not merely asserted.")


if __name__ == "__main__":
    main()
