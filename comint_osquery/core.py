"""comint-osquery — STIG-aligned osquery preset bundle and result mapper.

Cognis additions only. Upstream osquery is Apache-2.0, separately installed.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from cognis_mil import ScanResult, Finding, Severity

# ---- STIG-aligned query pack ----
STIG_PACK = {
    "users_no_password_required":  {"sql": "SELECT username FROM users WHERE password_status='empty'",
                                    "nist":"IA-5","stig":"V-242418","cci":"CCI-000196",
                                    "severity": Severity.VERY_HIGH,
                                    "title":"Account allows blank password"},
    "ssh_root_login_permitted":    {"sql": "SELECT * FROM augeas WHERE path LIKE '/etc/ssh/sshd_config' AND label='PermitRootLogin' AND value='yes'",
                                    "nist":"AC-6(2)","stig":"V-238213","cci":"CCI-000206",
                                    "severity": Severity.HIGH,
                                    "title":"SSH root login permitted"},
    "unsigned_kernel_modules":     {"sql":"SELECT name FROM kernel_modules WHERE signed='0'",
                                    "nist":"SI-7","stig":"V-238230",
                                    "severity": Severity.HIGH,
                                    "title":"Unsigned kernel module loaded"},
    "fips_not_enforced":           {"sql":"SELECT * FROM augeas WHERE path='/proc/sys/crypto/fips_enabled' AND value='0'",
                                    "nist":"SC-13","stig":"V-238298","cci":"CCI-002450",
                                    "severity": Severity.VERY_HIGH,
                                    "title":"FIPS 140 mode disabled"},
    "smartcard_not_required":      {"sql":"SELECT * FROM augeas WHERE label='pam_pkcs11' AND enabled='0'",
                                    "nist":"IA-2(11)","stig":"V-238219","cci":"CCI-000765",
                                    "severity": Severity.HIGH,
                                    "title":"PIV/CAC not required for authentication"},
    "audit_daemon_not_running":    {"sql":"SELECT * FROM processes WHERE name='auditd'",
                                    "nist":"AU-3","stig":"V-238201",
                                    "severity": Severity.VERY_HIGH,
                                    "title":"auditd not running"},
    "world_writable_root_files":   {"sql":"SELECT path FROM file WHERE mode LIKE '%w_%' AND uid=0",
                                    "nist":"AC-3","stig":"V-238382",
                                    "severity": Severity.HIGH,
                                    "title":"World-writable file owned by root"},
    "selinux_not_enforcing":       {"sql":"SELECT * FROM selinux_settings WHERE key='mode' AND value!='enforcing'",
                                    "nist":"AC-6","stig":"V-238311",
                                    "severity": Severity.HIGH,
                                    "title":"SELinux not in enforcing mode"},
}

def parse_osquery_results(json_path: Path) -> dict:
    """Parse osquery's JSON output (scheduled-query results or single-query mode)."""
    try:
        data = json.loads(json_path.read_text())
    except Exception as e:
        return {"_error": str(e)}
    # Two shapes: list of records, or dict keyed by query name
    return data if isinstance(data, (list, dict)) else {"_error": "unknown shape"}

def scan(target=".", **opts):
    """Scan an osquery JSON results file for STIG violations.

    For demo/CI: also accepts a directory containing simulated results.
    """
    r = ScanResult(tool_name="comint-osquery", tool_version="0.1.0")
    p = Path(target)
    if p.is_dir():
        files = list(p.glob("*.json"))
    elif p.is_file():
        files = [p]
    else:
        files = []
    r.items_scanned = len(files)
    for jf in files:
        results = parse_osquery_results(jf)
        if isinstance(results, dict) and "_error" in results:
            r.add(Finding("CO-PARSE", Severity.LOW, f"Couldn't parse {jf}: {results['_error']}", location=str(jf)))
            continue
        # Demo shape: {query_name: [rows...]}
        if isinstance(results, dict):
            for query, rows in results.items():
                if query in STIG_PACK and rows:
                    cfg = STIG_PACK[query]
                    r.add(Finding(f"CO-{query.upper()[:10]}", cfg["severity"], cfg["title"],
                                  description=f"{len(rows)} row(s) matched STIG-failing condition",
                                  location=str(jf),
                                  nist_800_53=cfg["nist"], disa_stig=cfg["stig"],
                                  cci=cfg.get("cci",""),
                                  remediation=f"Run remediation playbook for {cfg['stig']}"))
    r.finalize(); return r

def emit_query_pack(out: Path = None) -> str:
    """Emit a YAML osquery pack the operator can load into upstream osquery."""
    lines = ["# Cognis comint-osquery STIG pack","# Load with: osqueryi --config_path=stig_pack.yaml","queries:"]
    for name, cfg in STIG_PACK.items():
        lines.append(f"  {name}:")
        lines.append(f"    query: \"{cfg['sql']}\"")
        lines.append(f"    interval: 3600")
        lines.append(f"    description: \"{cfg['title']} (STIG {cfg['stig']})\"")
        lines.append(f"    platform: linux")
        lines.append("    snapshot: true")
    text = "\n".join(lines)
    if out: out.write_text(text)
    return text
