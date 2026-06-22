"""comint_osquery.feeds — edge/air-gap data-feed layer for comint-osquery.

Wires the bundled ``datafeeds`` ingestion engine to the two authoritative,
keyless, public feeds this compliance tool genuinely consumes:

  * ``oscal-800-53-rev5-catalog`` — NIST SP 800-53 rev5 control catalog (OSCAL
    JSON, from usnistgov/oscal-content). Resolves a finding's bare control id
    (e.g. ``IA-5``) to its *official* NIST control title
    ("Authenticator Management").
  * ``attack-nist-mappings`` — Center for Threat-Informed Defense crosswalk of
    MITRE ATT&CK techniques to NIST 800-53 rev5 controls. Expands a finding's
    single STIG-mapped technique into the full set of countermeasure controls
    CTID recommends — defense-in-depth coverage for RMF packages.

Everything is fetched over HTTPS, cached to disk, and re-served **offline** so
the tool keeps working on disconnected / air-gapped gear. See README for the
snapshot (sneakernet) workflow.

Defensive / authorized-use compliance crosswalking only.
"""
from __future__ import annotations

from typing import Optional

from . import datafeeds

# Feeds this repo is authorized to consume (compliance domain only).
RELEVANT_FEEDS = ["oscal-800-53-rev5-catalog", "attack-nist-mappings"]


def relevant_catalog() -> dict:
    """The shared catalog filtered to just this tool's relevant feed ids."""
    full = datafeeds.load_catalog()
    feeds = [f for f in full.get("feeds", []) if f["id"] in RELEVANT_FEEDS]
    return {"feeds": feeds}


# --------------------------------------------------------------------------- #
# control-id normalisation:  "AC-6(2)" / "IA-2(11)"  <->  OSCAL "ac-6.2"
# --------------------------------------------------------------------------- #
def _to_oscal_id(nist: str) -> str:
    """Normalise a human NIST id (``AC-6(2)``) to an OSCAL control id (``ac-6.2``)."""
    s = (nist or "").strip().lower().replace("(", ".").replace(")", "")
    return s


# --------------------------------------------------------------------------- #
# OSCAL catalog -> control title resolver
# --------------------------------------------------------------------------- #
def _index_catalog(catalog: dict) -> dict:
    """Flatten an OSCAL 800-53 catalog into {control_id: title}."""
    index: dict[str, str] = {}

    def walk(controls):
        for c in controls or []:
            cid = c.get("id")
            if cid and c.get("title"):
                index[cid] = c["title"]
            if "controls" in c:
                walk(c["controls"])

    cat = catalog.get("catalog", catalog)
    for g in cat.get("groups", []):
        walk(g.get("controls", []))
    return index


def control_titles(offline: bool = False, catalog: Optional[dict] = None) -> dict:
    """Return {oscal_control_id: official_title} from the live/cached OSCAL catalog."""
    data = datafeeds.get("oscal-800-53-rev5-catalog", offline=offline,
                         catalog=catalog or relevant_catalog())
    return _index_catalog(data)


def resolve_control_title(nist: str, titles: dict) -> str:
    """Resolve a finding's NIST id to its official title; '' if unknown."""
    return titles.get(_to_oscal_id(nist), "")


# --------------------------------------------------------------------------- #
# ATT&CK -> NIST 800-53 countermeasure controls
# --------------------------------------------------------------------------- #
def attack_control_index(offline: bool = False, catalog: Optional[dict] = None) -> dict:
    """{technique_id: sorted[control_id]} from the CTID ATT&CK<->800-53 crosswalk."""
    data = datafeeds.get("attack-nist-mappings", offline=offline,
                         catalog=catalog or relevant_catalog())
    out: dict[str, set] = {}
    for o in data.get("mapping_objects", []):
        tid = o.get("attack_object_id")
        cid = o.get("capability_id")
        if tid and cid:
            out.setdefault(tid, set()).add(cid)
    return {t: sorted(c) for t, c in out.items()}


def countermeasure_controls(technique: str, index: dict) -> list:
    """Controls CTID maps as countermeasures for an ATT&CK technique id."""
    return index.get((technique or "").strip(), [])


# --------------------------------------------------------------------------- #
# scan-result enrichment (the real value-add)
# --------------------------------------------------------------------------- #
def enrich_result(result, offline: bool = False) -> dict:
    """Enrich a ScanResult's findings with authoritative feed data, in place.

    For every finding, attaches to ``finding`` extra attributes and to a
    returned summary dict:
      * ``control_title``      — official NIST 800-53 title for its control id.
      * ``attack_countermeasures`` — full CTID-recommended control set for its
        ATT&CK technique (defense-in-depth beyond the single STIG control).

    Returns a dict summary {finding_id: {...}} for export/printing. Network is
    only touched when ``offline`` is False and the cache is stale.
    """
    titles = control_titles(offline=offline)
    attack_idx = attack_control_index(offline=offline)
    summary: dict[str, dict] = {}
    for f in result.findings:
        title = resolve_control_title(getattr(f, "nist_800_53", ""), titles)
        cms = countermeasure_controls(getattr(f, "mitre_attack", ""), attack_idx)
        # annotate the finding object (used by exporters/console)
        try:
            f.control_title = title
            f.attack_countermeasures = cms
            if title and not f.description.endswith(title):
                f.description = (f.description + f" | NIST {f.nist_800_53}: {title}").strip(" |")
        except Exception:  # pragma: no cover - dataclass slots edge
            pass
        summary[f.id] = {
            "nist_800_53": getattr(f, "nist_800_53", ""),
            "control_title": title,
            "mitre_attack": getattr(f, "mitre_attack", ""),
            "attack_countermeasures": cms,
        }
    return summary
