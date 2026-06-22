"""Every demo directory must scan cleanly and produce its documented outcome."""
from pathlib import Path

import pytest

from comint_osquery.core import scan

DEMOS = Path(__file__).parent.parent / "demos"

# (dir, expected finding count, expected severities present)
EXPECTED = {
    "01-failing-host":        (4, None),
    "02-clean-baseline":      (0, set()),
    "03-fips-violation":      (1, {"very_high"}),
    "04-selinux-permissive":  (2, {"high", "very_high"}),
    "05-unsigned-kmod":       (1, {"high"}),
    "06-no-auditd":           (1, {"very_high"}),
    "07-smartcard-bypass":    (2, {"high"}),
    "08-fleet-rollup":        (4, {"high", "very_high"}),
    "09-mixed-workstation":   (2, {"high", "very_high"}),
    "10-parse-error":         (1, {"low"}),
}


@pytest.mark.parametrize("name,expected", EXPECTED.items())
def test_demo_fires(name, expected):
    count, sevs = expected
    r = scan(str(DEMOS / name))
    assert r.total_findings() == count, f"{name}: got {r.total_findings()} findings"
    if sevs is not None:
        assert {f.severity.value for f in r.findings} == sevs


def test_fleet_rollup_scans_three_files():
    r = scan(str(DEMOS / "08-fleet-rollup"))
    assert r.items_scanned == 3
    # each finding's location names the host file it came from
    assert any("host-db02" in f.location for f in r.findings)


def test_parse_error_is_low_not_crash():
    r = scan(str(DEMOS / "10-parse-error"))
    assert r.findings[0].id == "CO-PARSE"
    assert r.findings[0].severity.value == "low"
