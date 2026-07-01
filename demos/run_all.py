"""Run every runnable demo scenario end to end.

    python demos/run_all.py            # all five, narrated, offline
    python demos/03_sysadmin_fleet.py  # or just one

Each scenario is independent and reads only the bundled ``demos/NN-name/``
osquery fixtures and the committed offline feed cache, so they run in any order,
on their own, and with no network. Every scenario exits 0, so they double as
smoke tests alongside ``tests/``.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_isso_assessment",
    "02_soc_detection",
    "03_sysadmin_fleet",
    "04_auditor_poam",
    "05_airgap_enrichment",
    "06_multiformat_export",
    "07_parse_error_handling",
    "08_pack_deployment",
    "09_fleet_json_export",
    "10_poam_json",
    "11_classification_banner",
    "12_airgap_snapshot",
    "13_countermeasure_expansion",
    "14_audit_chain",
    "15_fail_on_gating",
    "16_control_titles",
    "17_drift_regression",
    "18_full_rmf_workflow",
    "19_attack_coverage_matrix",
    "20_connect_emit",
]


def main() -> None:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 72)
    print("  All demo scenarios completed.")
    print("=" * 72)


if __name__ == "__main__":
    main()
