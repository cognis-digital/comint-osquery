"""Scenario 4 - auditors / assessors: a POA&M workbook + a provable audit trail.

The artifact an auditor lives by is the Plan of Action & Milestones (POA&M): one
row per (weakness, asset), with a CAT level, the security check (STIG/CCI), and a
severity-driven scheduled-completion date. This demo builds the REAL eMASS-style
POA&M with ``comint_osquery.fleet.poam_items`` and shows the columns, then uses
the shipped hash-chained ``AuditLog`` to make the assessment itself
tamper-evident — and proves the chain catches an edit.

Offline: reads the bundled ``demos/12-fleet-systemic`` snapshots; the audit log
is written to a throwaway temp file.
"""
import csv
import io
import tempfile
from pathlib import Path

from _common import fixture, rule, section
from comint_osquery import fleet as fl
from cognis_mil import AuditLog


def main() -> None:
    rule("AUDITOR / ASSESSOR  -  eMASS POA&M + tamper-evident audit trail")

    target = fixture("12-fleet-systemic")
    hosts = fl.scan_fleet(target)

    section("POA&M workbook (one row per failing control, per host)")
    # assessed_at fixed so the scheduled-completion dates are deterministic.
    items = fl.poam_items(hosts, office="J6 / Cyber", assessed_at=0)
    print(f"  {len(items)} POA&M item(s). eMASS columns: {len(fl.POAM_COLUMNS)}")
    print(f"\n  {'Item ID':<13} {'CAT':<7} {'Control':<9} {'Sched. Complete':<16} Check")
    for it in items:
        print(f"  {it['POA&M Item ID']:<13} {it['Raw Severity']:<7} "
              f"{it['Security Control Number (NC/NA)']:<9} "
              f"{it['Scheduled Completion Date']:<16} {it['Security Checks']}")

    # Render the real CSV and confirm it round-trips (eMASS import sanity).
    csv_text = fl.poam_to_csv(items)
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    print(f"\n  CSV renders {len(rows)} data row(s), RFC 4180 quoted, header = eMASS columns.")

    section("Tamper-evident audit trail (hash-chained, local-only)")
    log_path = Path(tempfile.mkdtemp(prefix="comint_audit_")) / "audit.log"
    log = AuditLog(log_path)
    log.append({"actor": "isso", "action": "scan", "target": "demos/12-fleet-systemic"})
    for it in items:
        log.append({"actor": "isso", "action": "poam_item", "id": it["POA&M Item ID"]})
    ok, msg = log.verify()
    print(f"  appended {len(items) + 1} entries -> verify(): intact={ok}  ({msg})")

    # Tamper: rewrite one line's body directly, bypassing append().
    lines = log_path.read_text().splitlines()
    lines[1] = lines[1].replace("poam_item", "poam_item_HACKED")
    log_path.write_text("\n".join(lines) + "\n")
    ok2, msg2 = log.verify()
    print(f"  after editing one row directly: intact={ok2}  ({msg2})")
    print("\n  The chain catches the edit -> the assessment record is provable, not asserted.")


if __name__ == "__main__":
    main()
