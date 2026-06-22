"""CSV exporter (cognis_mil) + ATT&CK enrichment in the STIG pack."""
import csv
import io

from cognis_mil.models import ScanResult, Finding, Severity
from cognis_mil.exporters import to_csv
from comint_osquery.core import STIG_PACK, scan
from pathlib import Path

D = Path(__file__).parent.parent / "demos"


def _result():
    r = ScanResult(tool_name="tool", tool_version="0.1.0")
    r.add(Finding("F-1", Severity.HIGH, "Quoted, value", description='has "quotes"',
                  nist_800_53="AC-6", disa_stig="V-1", cci="CCI-1", mitre_attack="T1078"))
    r.finalize()
    return r


def test_csv_has_header_and_row():
    text = to_csv(_result())
    # Two comment lines, then the real CSV body.
    body = [ln for ln in text.splitlines() if not ln.startswith("#")]
    rows = list(csv.reader(io.StringIO("\n".join(body))))
    assert rows[0] == ["id", "severity", "title", "description", "location",
                       "nist_800_53", "disa_stig", "cci", "mitre_attack",
                       "category", "remediation"]
    assert rows[1][0] == "F-1"
    assert rows[1][8] == "T1078"


def test_csv_quotes_embedded_delimiters():
    # A title containing a comma and a description containing quotes must round-trip.
    text = to_csv(_result())
    body = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))
    rows = list(csv.reader(io.StringIO(body)))
    assert rows[1][2] == "Quoted, value"
    assert rows[1][3] == 'has "quotes"'


def test_csv_carries_classification_banner():
    r = _result()
    r.classification_placeholder = "CUI//SP-PRVCY"
    assert "CUI//SP-PRVCY" in to_csv(r)


def test_every_stig_query_has_real_attack_technique():
    import re
    pat = re.compile(r"^T\d{4}(\.\d{3})?$")
    for name, cfg in STIG_PACK.items():
        assert "attack" in cfg, f"{name} missing attack mapping"
        assert pat.match(cfg["attack"]), f"{name} has malformed technique {cfg['attack']}"


def test_scan_populates_mitre_attack_on_findings():
    r = scan(str(D / "07-smartcard-bypass"))
    assert r.findings
    assert all(f.mitre_attack for f in r.findings)
