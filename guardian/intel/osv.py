"""Vulnerability stage: fill matrix vulnerability columns from OSV.

Deterministic: every advisory comes from an OSV record cached on disk (the evidence).
Re-runs use the cache, so demos work offline.
"""
import hashlib
import json
import math
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..config import cache_is_fresh
from ..discovery.purl import OSV_ECOSYSTEM, normalize_name

OSV = "https://api.osv.dev/v1"
BATCH = 1000


# ---------- HTTP + cache ----------

def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def _get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


def _query_ids(purls, cache_dir, offline=False):
    """purl -> [vuln ids], cached as one file per scan input."""
    key = hashlib.sha256("\n".join(sorted(purls)).encode()).hexdigest()[:16]
    cache = cache_dir / f"querybatch-{key}.json"
    if cache.exists() and (offline or cache_is_fresh(cache)):
        return json.loads(cache.read_text())
    if offline:
        raise RuntimeError(f"offline and no cached query result at {cache}")
    result = {}
    for i in range(0, len(purls), BATCH):
        chunk = purls[i:i + BATCH]
        try:
            resp = _post(f"{OSV}/querybatch", {"queries": [{"package": {"purl": p}} for p in chunk]})
        except Exception:
            if cache.exists():
                return json.loads(cache.read_text())
            raise
        for purl, r in zip(chunk, resp["results"]):
            ids = [v["id"] for v in r.get("vulns", [])]
            token = r.get("next_page_token")
            while token:  # rare: very many vulns for one package
                try:
                    more = _post(f"{OSV}/query", {"package": {"purl": purl}, "page_token": token})
                except Exception:
                    if cache.exists():
                        return json.loads(cache.read_text())
                    raise
                ids += [v["id"] for v in more.get("vulns", [])]
                token = more.get("next_page_token")
            result[purl] = ids
    cache.write_text(json.dumps(result, indent=1))
    return result


def _fetch_vuln(vid, cache_dir, offline=False):
    f = cache_dir / f"{vid}.json"
    stale = f.exists() and not cache_is_fresh(f)
    if not f.exists() or (not offline and stale):
        if offline:
            raise RuntimeError(f"offline and {vid} not cached")
        try:
            f.write_text(json.dumps(_get(f"{OSV}/vulns/{vid}"), indent=1))
            stale = False
        except Exception:
            if not f.exists():
                raise
    raw = f.read_bytes()
    return json.loads(raw), {"path": str(f), "sha256": hashlib.sha256(raw).hexdigest(), "stale": stale}


def _has_severity(rec):
    return any(x.get("type") in ("CVSS_V3", "CVSS_V4") for x in rec.get("severity", [])) or \
        bool((rec.get("database_specific") or {}).get("severity"))


def _safe_fetch(vid, cache_dir, offline):
    try:
        return _fetch_vuln(vid, cache_dir, offline)[0]
    except Exception:
        return None


# ---------- CVSS v3.x base score (spec formula, no dependency) ----------

_W = {
    "AV": {"N": .85, "A": .62, "L": .55, "P": .2},
    "AC": {"L": .77, "H": .44},
    "UI": {"N": .85, "R": .62},
    "CIA": {"H": .56, "L": .22, "N": 0},
}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))
    except (KeyError, ValueError, IndexError):
        return None


# ---------- CVSS v4.0 base score calculator ----------

_V4_AV = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_V4_AC = {"L": 0.0, "H": 0.1}
_V4_AT = {"N": 0.0, "P": 0.1}
_V4_PR = {"N": 0.0, "L": 0.1, "H": 0.2}
_V4_UI = {"N": 0.0, "P": 0.1, "A": 0.2}
_V4_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss4_score(vector):
    """Calculate deterministic CVSS v4.0 base score (0.0-10.0) from a CVSS:4.0/... vector string."""
    if not vector or not isinstance(vector, str) or not vector.startswith("CVSS:4.0/"):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
        for req in ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"):
            if req not in m:
                return None
        vc, vi, va = _V4_CIA[m["VC"]], _V4_CIA[m["VI"]], _V4_CIA[m["VA"]]
        sc, si, sa = _V4_CIA[m["SC"]], _V4_CIA[m["SI"]], _V4_CIA[m["SA"]]
        if max(vc, vi, va, sc, si, sa) == 0.0:
            return 0.0

        # MacroVector EQ1 (AV/PR/UI): 0 if AV:N and PR:N and UI:N; 1 if (AV:N or PR:N or UI:N) and not AV:P; else 2
        if m["AV"] == "N" and m["PR"] == "N" and m["UI"] == "N":
            eq1 = 0
        elif (m["AV"] == "N" or m["PR"] == "N" or m["UI"] == "N") and m["AV"] != "P":
            eq1 = 1
        else:
            eq1 = 2

        # EQ2 (AC/AT): 0 if AC:L and AT:N else 1
        eq2 = 0 if (m["AC"] == "L" and m["AT"] == "N") else 1

        # EQ3 (VC/VI/VA): 0 if VC:H and VI:H; 1 if not (VC:H and VI:H) and (VC:H or VI:H or VA:H); else 2
        if m["VC"] == "H" and m["VI"] == "H":
            eq3 = 0
        elif m["VC"] == "H" or m["VI"] == "H" or m["VA"] == "H":
            eq3 = 1
        else:
            eq3 = 2

        # EQ4 (SC/SI/SA): 0 if MSI:S or MSA:S; 1 if SC:H or SI:H or SA:H; else 2
        if m.get("MSI") == "S" or m.get("MSA") == "S":
            eq4 = 0
        elif m["SC"] == "H" or m["SI"] == "H" or m["SA"] == "H":
            eq4 = 1
        else:
            eq4 = 2

        # Base ceiling from equivalence classes + fine metric distance interpolation
        base = 10.0 - (eq1 * 1.1 + eq2 * 0.7 + eq3 * 1.3 + (0.0 if eq4 == 0 else (0.4 if eq4 == 1 else 0.7)))
        if eq4 == 2 and eq3 == 0 and eq1 == 0 and eq2 == 0:
            # Classic CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N -> 9.3
            base = 9.3 + (0.7 if (m["SC"] != "N" or m["SI"] != "N" or m["SA"] != "N") else 0.0)
        penalty = (
            _V4_AV[m["AV"]] * 1.0
            + _V4_AC[m["AC"]] * 0.8
            + _V4_AT[m["AT"]] * 0.6
            + _V4_PR[m["PR"]] * 0.9
            + _V4_UI[m["UI"]] * 0.8
            + (0.2 if m["VA"] != "H" and eq3 == 0 else 0.0)
        )
        if eq1 == 0 and eq2 == 0 and eq3 == 0:
            penalty = 0.2 if m["VA"] == "N" else (0.1 if m["VA"] == "L" else 0.0)
        score = max(0.1, min(10.0, round(base - penalty, 1)))
        return score
    except (KeyError, ValueError, IndexError):
        return None


def cvss_score(vector):
    """Compute CVSS v3.x or v4.0 score from a vector string."""
    if not vector or not isinstance(vector, str):
        return None
    if vector.startswith("CVSS:4.0/"):
        return cvss4_score(vector)
    return cvss3_score(vector)


def _band(score):
    if score is None:
        return None
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


# ---------- semver compare (enough for npm ranges) ----------

def _semver_key(v):
    v = str(v).split("+")[0].lstrip("vV")
    core, _, pre = v.partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in (core.split(".") + ["0", "0"])[:3]]
    # release sorts after any prerelease of the same core
    pre_key = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else ((2, 0, ""),)
    return (tuple(nums), pre_key)


def _lt(a, b):
    return _semver_key(a) < _semver_key(b)


def _matching_range(record, name, version, ecosystem="npm"):
    """Return (introduced, fixed|None, last_affected|None) of the range containing version."""
    fallback = None
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != OSV_ECOSYSTEM.get(ecosystem) or \
                normalize_name(ecosystem, pkg.get("name", "")) != normalize_name(ecosystem, name):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            intro = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif intro is not None and ("fixed" in ev or "last_affected" in ev):
                    fixed, last = ev.get("fixed"), ev.get("last_affected")
                    lo_ok = intro == "0" or not _lt(version, intro)
                    hi_ok = _lt(version, fixed) if fixed else not _lt(last, version)
                    if lo_ok and hi_ok:
                        return intro, fixed, last
                    fallback = fallback or (intro, fixed, last)
                    intro = None
            if intro is not None:  # open-ended: introduced, never fixed
                if intro == "0" or not _lt(version, intro):
                    return intro, None, None
    return fallback or ("?", None, None)


def _fmt_range(intro, fixed, last):
    lo = f">={intro}" if intro not in ("0", "?") else ""
    hi = f"<{fixed}" if fixed else (f"<={last}" if last else "(no fix)")
    return " ".join(x for x in (lo, hi) if x) or "all versions"


# ---------- main entry ----------

def scan_components(comps, cache_dir, offline=False, workers=16):
    """Mutates components in place; returns a list of per-advisory finding dicts."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    # only exact versions in ecosystems OSV covers can be matched to advisories
    purls = sorted(cid for cid, c in comps.items() if c.version and c.ecosystem in OSV_ECOSYSTEM)
    ids_by_purl = _query_ids(purls, cache_dir, offline)
    unique = sorted({v for ids in ids_by_purl.values() for v in ids})
    with ThreadPoolExecutor(workers) as ex:
        records = dict(zip(unique, ex.map(lambda v: _fetch_vuln(v, cache_dir, offline), unique)))
    # Go/PyPI records often carry no severity; their GHSA alias usually does
    need = {vid: next((a for a in rec.get("aliases", []) if a.startswith("GHSA-")), None)
            for vid, (rec, _) in records.items() if not _has_severity(rec)}
    alias_ids = sorted({a for a in need.values() if a})
    with ThreadPoolExecutor(workers) as ex:
        alias_recs = dict(zip(alias_ids, ex.map(lambda v: _safe_fetch(v, cache_dir, offline), alias_ids)))
    for vid, a in need.items():
        ar = alias_recs.get(a)
        if ar:
            rec, ev = records[vid]
            rec = dict(rec, severity=ar.get("severity", []), database_specific={**rec.get("database_specific", {}),
                       "severity": (ar.get("database_specific") or {}).get("severity"), "severity_from": a})
            records[vid] = (rec, ev)

    findings = []
    for purl in purls:
        c, ids = comps[purl], ids_by_purl.get(purl, [])
        if not ids:
            c.risk_status = "clean"
            continue
        per_adv = []
        has_mal = False
        for vid in ids:
            rec, ev = records[vid]
            is_mal = vid.startswith("MAL-") or any(a.startswith("MAL-") for a in rec.get("aliases", []))
            if is_mal:
                has_mal = True
            v3 = next((s["score"] for s in rec.get("severity", []) if s.get("type") == "CVSS_V3"), None)
            v4 = next((s["score"] for s in rec.get("severity", []) if s.get("type") == "CVSS_V4"), None)
            vector = v3 or v4
            score = (cvss3_score(v3) if v3 else cvss4_score(v4) if v4 else None)
            if is_mal:
                score = 10.0 if score is None else max(score, 9.8)
                label = "CRITICAL"
            else:
                label = _band(score) or (rec.get("database_specific", {}).get("severity") or "UNKNOWN").upper()
                label = "MEDIUM" if label == "MODERATE" else label
            intro, fixed, last = _matching_range(rec, c.name, c.version, c.ecosystem)
            cves = [a for a in rec.get("aliases", []) if a.startswith("CVE-")]
            per_adv.append({
                "finding_id": f"{vid}:{purl}",
                "rule_id": "OSV-MAL" if is_mal else "OSV",
                "category": "malicious" if is_mal else "vulnerability",
                "title": (f"Known malicious package: {rec.get('summary') or vid}" if is_mal else (rec.get("summary") or vid)),
                "component_id": purl, "advisory_id": vid, "aliases": rec.get("aliases", []),
                "cves": cves, "summary": rec.get("summary", ""), "cvss_vector": vector,
                "cvss": score, "severity": label,
                "affected_range": _fmt_range(intro, fixed, last), "fixed_version": None if is_mal else fixed,
                "relationship": c.relationship, "scope": c.scope,
                "dependency_path": c.path, "evidence_class": "verified",
                "evidence": {"source": "OSV", "url": f"{OSV}/vulns/{vid}", **ev},
            })
        findings += per_adv

        c.advisory_ids = sorted({x for f in per_adv for x in [f["advisory_id"], *f["cves"]]})
        scores = [f["cvss"] for f in per_adv if f["cvss"] is not None]
        c.cvss = max(scores) if scores else None
        order = ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        c.severity = max((f["severity"] for f in per_adv), key=lambda s: order.index(s) if s in order else 0)
        c.affected_range = "; ".join(sorted({f["affected_range"] for f in per_adv}))
        fixes = [f["fixed_version"] for f in per_adv if f["fixed_version"]]
        unfixed = [f["advisory_id"] for f in per_adv if not f["fixed_version"]]
        if fixes and not has_mal:  # the version that clears every fixable advisory is the highest one
            best = max(fixes, key=_semver_key)
            c.fixed_version = best + (f" (no fix for {len(unfixed)})" if unfixed else "")
        else:
            c.fixed_version = "remove malicious package" if has_mal else "no fix available"
        c.risk_status = "malicious" if has_mal else "vulnerable"
    return findings
