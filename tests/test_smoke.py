from pathlib import Path
from comint_osquery.core import scan, emit_query_pack, STIG_PACK
D = Path(__file__).parent.parent / "demos" / "01-failing-host"
def test_pack_emits():
    s = emit_query_pack()
    assert "queries:" in s
    assert "fips_not_enforced" in s
def test_failing_host():
    r = scan(str(D))
    ids = {f.id for f in r.findings}
    assert any("FIPS" in i for i in ids)
    assert any("SSH" in i for i in ids)
    assert r.composite_score > 30
def test_clean_host(tmp_path):
    (tmp_path / "ok.json").write_text('{"users_no_password_required":[],"audit_daemon_not_running":[]}')
    r = scan(str(tmp_path))
    assert r.total_findings() == 0
