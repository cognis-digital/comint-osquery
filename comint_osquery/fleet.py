"""comint_osquery.fleet — fleet correlation, baseline-drift, and POA&M engine.

The base :func:`comint_osquery.core.scan` globs every ``*.json`` in a directory
and *flattens* the fleet into one assessment.  That is the right shape for a
single composite risk score, but it throws away the cross-host structure a real
RMF / continuous-monitoring workflow needs:

  * **Per-host attribution** — *which* boxes failed *which* control, not just a
    pile of findings.
  * **Systemic vs. isolated** — a control that fails on one host is a
    remediation ticket; the *same* control failing on every host in the fleet is
    a broken golden image / GPO / Ansible role.  Those are very different
    response priorities and this module separates them.
  * **Baseline drift** — given a known-good "golden" host (or an explicit
    baseline file), report exactly which hosts have *drifted* away from it and
    in which direction (regressions vs. unexpected hardening).
  * **DISA POA&M** — emit the actual eMASS-style Plan of Action & Milestones
    workbook columns (CSV + JSON), one row per (control, host) weakness, with
    severity-driven scheduled-completion offsets.  This is the artifact an ISSO
    actually hands to an AO; producing it directly from a scan is the value.

Everything here is pure-stdlib, deterministic, and offline.  No network, no
fabricated data: control/STIG/CCI/ATT&CK identifiers all come straight from the
``STIG_PACK`` already shipped in :mod:`comint_osquery.core`.

Defensive / authorized-use compliance & situational-awareness only.
"""
from __future__ import annotations

import csv as _csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from cognis_mil import Severity
from .core import STIG_PACK, parse_osquery_results

# DISA / NIST-aligned remediation windows.  These are the conventional RMF
# scheduled-completion offsets (in days) by severity — the same cadence eMASS
# POA&M reviewers expect (CAT I fastest).  Operator may override.
REMEDIATION_DAYS = {
    Severity.VERY_HIGH: 30,
    Severity.HIGH:      90,
    Severity.MODERATE: 180,
    Severity.LOW:      365,
    Severity.VERY_LOW: 365,
}

# DISA STIG CAT level <- our severity.  CAT I = direct/immediate loss; CAT II =
# may lead to loss; CAT III = degrades protection.
CAT_LEVEL = {
    Severity.VERY_HIGH: "CAT I",
    Severity.HIGH:      "CAT II",
    Severity.MODERATE:  "CAT II",
    Severity.LOW:       "CAT III",
    Severity.VERY_LOW:  "CAT III",
}


# --------------------------------------------------------------------------- #
# host-level scan (keeps attribution that core.scan flattens away)
# --------------------------------------------------------------------------- #
@dataclass
class HostResult:
    """One osquery snapshot file = one host."""
    host: str
    source: str
    failing: dict = field(default_factory=dict)   # {query_name: row_count}
    parse_error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.parse_error is None and not self.failing

    def controls(self) -> set:
        """Set of NIST control ids this host failed."""
        return {STIG_PACK[q]["nist"] for q in self.failing if q in STIG_PACK}


def _host_name(path: Path) -> str:
    """Derive a stable host id from a results filename.

    ``host-web01.json`` -> ``web01``;  ``results.json`` -> the stem.
    """
    stem = path.stem
    for pfx in ("host-", "host_"):
        if stem.startswith(pfx):
            return stem[len(pfx):]
    return stem


def scan_host(path: Path) -> HostResult:
    """Parse a single osquery results file into a :class:`HostResult`."""
    path = Path(path)
    res = parse_osquery_results(path)
    host = _host_name(path)
    if isinstance(res, dict) and "_error" in res:
        return HostResult(host=host, source=str(path), parse_error=res["_error"])
    failing: dict[str, int] = {}
    if isinstance(res, dict):
        for query, rows in res.items():
            if query in STIG_PACK and rows:
                failing[query] = len(rows)
    return HostResult(host=host, source=str(path), failing=failing)


def scan_fleet(target) -> list[HostResult]:
    """Scan every ``*.json`` under *target* (or a single file) per-host."""
    p = Path(target)
    if p.is_dir():
        files = sorted(p.glob("*.json"))
    elif p.is_file():
        files = [p]
    else:
        files = []
    return [scan_host(f) for f in files]


# --------------------------------------------------------------------------- #
# correlation: systemic vs. isolated
# --------------------------------------------------------------------------- #
def correlate(hosts: Iterable[HostResult]) -> dict:
    """Cross-host correlation of failing controls.

    Returns a dict with, per failing query:
      * ``hosts``      — sorted list of hosts that failed it
      * ``count``      — how many hosts
      * ``coverage``   — fraction of the fleet (0..1)
      * ``scope``      — ``systemic`` (all hosts) / ``widespread`` (>=50%) /
                          ``isolated`` (a single host) / ``partial``
      * the control/stig/cci/attack/severity metadata from STIG_PACK
    """
    hosts = list(hosts)
    scanned = [h for h in hosts if h.parse_error is None]
    n = len(scanned) or 1
    agg: dict[str, dict] = {}
    for h in scanned:
        for q in h.failing:
            agg.setdefault(q, {"hosts": []})["hosts"].append(h.host)

    out: dict[str, dict] = {}
    for q, d in agg.items():
        cfg = STIG_PACK[q]
        hs = sorted(d["hosts"])
        cov = len(hs) / n
        if len(hs) == n and n > 1:
            scope = "systemic"
        elif len(hs) == 1:
            scope = "isolated"
        elif cov >= 0.5:
            scope = "widespread"
        else:
            scope = "partial"
        out[q] = {
            "title": cfg["title"],
            "nist": cfg["nist"],
            "stig": cfg["stig"],
            "cci": cfg.get("cci", ""),
            "attack": cfg.get("attack", ""),
            "severity": cfg["severity"].value,
            "hosts": hs,
            "count": len(hs),
            "coverage": round(cov, 3),
            "scope": scope,
        }
    return out


def fleet_summary(hosts: Iterable[HostResult]) -> dict:
    """High-level fleet posture, ready to print/export."""
    hosts = list(hosts)
    scanned = [h for h in hosts if h.parse_error is None]
    clean = [h for h in scanned if not h.failing]
    errored = [h for h in hosts if h.parse_error is not None]
    corr = correlate(hosts)
    systemic = sorted(q for q, d in corr.items() if d["scope"] == "systemic")
    widespread = sorted(q for q, d in corr.items() if d["scope"] == "widespread")
    isolated = sorted(q for q, d in corr.items() if d["scope"] == "isolated")
    # control-level coverage (a control may map from >1 query)
    control_hosts: dict[str, set] = {}
    for h in scanned:
        for c in h.controls():
            control_hosts.setdefault(c, set()).add(h.host)
    return {
        "hosts_total": len(hosts),
        "hosts_scanned": len(scanned),
        "hosts_clean": sorted(h.host for h in clean),
        "hosts_failing": sorted(h.host for h in scanned if h.failing),
        "hosts_errored": sorted(h.host for h in errored),
        "controls_failing": sorted(control_hosts),
        "systemic_findings": systemic,
        "widespread_findings": widespread,
        "isolated_findings": isolated,
        "correlation": corr,
    }


# --------------------------------------------------------------------------- #
# baseline drift
# --------------------------------------------------------------------------- #
def baseline_drift(hosts: Iterable[HostResult], baseline: HostResult) -> dict:
    """Compare each host's failing-control set against a baseline host.

    ``regressions`` = controls the host fails that the baseline does NOT
    (the host is *worse* than golden — the actionable case).
    ``improvements`` = controls the baseline fails that the host does not
    (the host is *better* — usually means the golden image itself is stale).
    ``in_baseline`` = the baseline's own failing set (for context).
    """
    hosts = list(hosts)
    base_fail = set(baseline.failing)
    drift = {}
    for h in hosts:
        if h.host == baseline.host or h.parse_error is not None:
            continue
        hf = set(h.failing)
        regressions = sorted(hf - base_fail)
        improvements = sorted(base_fail - hf)
        drift[h.host] = {
            "regressions": regressions,
            "improvements": improvements,
            "drifted": bool(regressions or improvements),
            "regression_controls": sorted(
                {STIG_PACK[q]["nist"] for q in regressions if q in STIG_PACK}),
        }
    return {
        "baseline": baseline.host,
        "in_baseline": sorted(base_fail),
        "drift": drift,
        "drifted_hosts": sorted(h for h, d in drift.items() if d["drifted"]),
    }


def pick_baseline(hosts: Iterable[HostResult],
                  baseline_host: Optional[str] = None) -> Optional[HostResult]:
    """Select a baseline host.

    If *baseline_host* is given, match it by host id.  Otherwise pick the
    cleanest scanned host (fewest failing controls; ties broken by host id).
    Returns ``None`` if there is nothing to pick.
    """
    scanned = [h for h in hosts if h.parse_error is None]
    if not scanned:
        return None
    if baseline_host:
        for h in scanned:
            if h.host == baseline_host:
                return h
        return None
    return sorted(scanned, key=lambda h: (len(h.failing), h.host))[0]


# --------------------------------------------------------------------------- #
# DISA POA&M (Plan of Action & Milestones)
# --------------------------------------------------------------------------- #
# eMASS POA&M workbook columns (the abbreviated public/unclassified set).
POAM_COLUMNS = [
    "POA&M Item ID",
    "Control Vulnerability Description",
    "Security Control Number (NC/NA)",
    "Office/Org",
    "Security Checks",          # STIG / CCI
    "Resources Required",
    "Scheduled Completion Date",
    "Milestone with Completion Dates",
    "Status",
    "Comments",
    "Raw Severity",             # CAT level
    "Affected Asset",           # host
    "MITRE ATT&CK",
]


def _iso_date(epoch: float) -> str:
    import time
    return time.strftime("%Y-%m-%d", time.gmtime(epoch or 0))


def poam_items(hosts: Iterable[HostResult],
               office: str = "",
               assessed_at: Optional[float] = None) -> list[dict]:
    """Build POA&M items — one per (failing control, host).

    Deterministic ordering (host, then control number) so re-runs diff cleanly.
    Scheduled-completion offsets are derived from severity via REMEDIATION_DAYS.
    """
    import time
    base = assessed_at if assessed_at is not None else time.time()
    rows = []
    hosts = sorted((h for h in hosts if h.parse_error is None),
                   key=lambda h: h.host)
    for h in hosts:
        # Item IDs are per-asset sequential (``web01-001``, ``web01-002``, …),
        # which is what an eMASS reviewer expects — a global counter made the
        # first item on a second host read as ``web01-003``.
        seq = 0
        for q in sorted(h.failing,
                        key=lambda q: (STIG_PACK[q]["nist"], q)):
            cfg = STIG_PACK[q]
            sev = cfg["severity"]
            seq += 1
            days = REMEDIATION_DAYS[sev]
            sched = _iso_date(base + days * 86400)
            checks = cfg["stig"]
            if cfg.get("cci"):
                checks += f" / {cfg['cci']}"
            rows.append({
                "POA&M Item ID": f"{h.host}-{seq:03d}",
                "Control Vulnerability Description":
                    f"{cfg['title']} ({h.failing[q]} finding(s) on {h.host})",
                "Security Control Number (NC/NA)": cfg["nist"],
                "Office/Org": office,
                "Security Checks": checks,
                "Resources Required": "Engineering / config-management remediation",
                "Scheduled Completion Date": sched,
                "Milestone with Completion Dates":
                    f"Apply STIG {cfg['stig']} fix; re-scan to confirm by {sched}",
                "Status": "Ongoing",
                "Comments": f"Detected by comint-osquery on {_iso_date(base)}; "
                            f"source {h.source}",
                "Raw Severity": CAT_LEVEL[sev],
                "Affected Asset": h.host,
                "MITRE ATT&CK": cfg.get("attack", ""),
            })
    return rows


def poam_to_csv(items: list[dict]) -> str:
    """Render POA&M items as an eMASS-importable CSV (RFC 4180 quoting)."""
    buf = io.StringIO()
    w = _csv.DictWriter(buf, fieldnames=POAM_COLUMNS, lineterminator="\n",
                        extrasaction="ignore")
    w.writeheader()
    for r in items:
        w.writerow(r)
    return buf.getvalue()


def poam_to_json(items: list[dict]) -> str:
    return json.dumps({"poam_items": items, "count": len(items)}, indent=2)


# --------------------------------------------------------------------------- #
# console rendering for the fleet report
# --------------------------------------------------------------------------- #
_SCOPE_ICON = {"systemic": "[SYS]", "widespread": "[WID]", "partial": "[PRT]",
               "isolated": "[ISO]"}


def render_fleet_report(hosts: Iterable[HostResult],
                        drift: Optional[dict] = None,
                        classification: str = "UNCLASSIFIED//FOR PUBLIC RELEASE") -> str:
    hosts = list(hosts)
    summ = fleet_summary(hosts)
    lines = [
        "=" * 72,
        f"  {classification}",
        "=" * 72,
        "  comint-osquery — FLEET CORRELATION REPORT",
        f"  Hosts: {summ['hosts_scanned']} scanned"
        f" ({len(summ['hosts_clean'])} clean,"
        f" {len(summ['hosts_failing'])} failing,"
        f" {len(summ['hosts_errored'])} errored)",
        f"  Failing controls across fleet: {len(summ['controls_failing'])}",
        "-" * 72,
    ]
    if summ["systemic_findings"]:
        lines.append("  SYSTEMIC (every host — likely broken golden image / GPO):")
        for q in summ["systemic_findings"]:
            d = summ["correlation"][q]
            lines.append(f"    {_SCOPE_ICON['systemic']} {d['nist']:<9} {d['title']}"
                         f"  [{d['count']} hosts]")
    for label, key in (("WIDESPREAD (>=50%)", "widespread_findings"),
                        ("ISOLATED (single host)", "isolated_findings")):
        ids = summ[key]
        if ids:
            lines.append(f"  {label}:")
            for q in ids:
                d = summ["correlation"][q]
                ic = _SCOPE_ICON.get(d["scope"], "")
                lines.append(f"    {ic} {d['nist']:<9} {d['title']}"
                             f"  -> {', '.join(d['hosts'])}")
    if drift:
        lines.append("-" * 72)
        lines.append(f"  BASELINE DRIFT (baseline = {drift['baseline']}):")
        if not drift["drifted_hosts"]:
            lines.append("    no drift — all hosts match baseline")
        for host in drift["drifted_hosts"]:
            d = drift["drift"][host]
            if d["regressions"]:
                regs = ", ".join(STIG_PACK[q]["nist"] for q in d["regressions"])
                lines.append(f"    [DRIFT-] {host}: regressions -> {regs}")
            if d["improvements"]:
                imps = ", ".join(STIG_PACK[q]["nist"] for q in d["improvements"])
                lines.append(f"    [DRIFT+] {host}: ahead of baseline -> {imps}")
    lines.append("=" * 72)
    lines.append(f"  {classification}")
    lines.append("=" * 72)
    return "\n".join(lines)
