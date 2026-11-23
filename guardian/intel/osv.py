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
    if cache.exists():
        return json.loads(cache.read_text())
    if offline:
        raise RuntimeError(f"offline and no cached query result at {cache}")
    result = {}
    for i in range(0, len(purls), BATCH):
        chunk = purls[i:i + BATCH]
        resp = _post(f"{OSV}/querybatch", {"queries": [{"package": {"purl": p}} for p in chunk]})
        for purl, r in zip(chunk, resp["results"]):
            ids = [v["id"] for v in r.get("vulns", [])]
            token = r.get("next_page_token")
            while token:  # rare: very many vulns for one package
                more = _post(f"{OSV}/query", {"package": {"purl": purl}, "page_token": token})
                ids += [v["id"] for v in more.get("vulns", [])]
                token = more.get("next_page_token")
            result[purl] = ids
    cache.write_text(json.dumps(result, indent=1))
    return result


def _fetch_vuln(vid, cache_dir, offline=False):
    f = cache_dir / f"{vid}.json"
    if not f.exists():
        if offline:
            raise RuntimeError(f"offline and {vid} not cached")
        f.write_text(json.dumps(_get(f"{OSV}/vulns/{vid}"), indent=1))
    raw = f.read_bytes()
    return json.loads(raw), {"path": str(f), "sha256": hashlib.sha256(raw).hexdigest()}


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


def _band(score):
    if score is None:
        return None
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


# ---------- semver compare (enough for npm ranges) ----------

def _semver_key(v):
    v = v.split("+")[0]
    core, _, pre = v.partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in (core.split(".") + ["0", "0"])[:3]]
    # release sorts after any prerelease of the same core
    pre_key = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else ((2, 0, ""),)
    return (tuple(nums), pre_key)


def _lt(a, b):
    return _semver_key(a) < _semver_key(b)


def _matching_range(record, name, version):
    """Return (introduced, fixed|None, last_affected|None) of the range containing version."""
    fallback = None
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != "npm" or pkg.get("name") != name:
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
    purls = sorted(comps)
    ids_by_purl = _query_ids(purls, cache_dir, offline)
    unique = sorted({v for ids in ids_by_purl.values() for v in ids})
    with ThreadPoolExecutor(workers) as ex:
        records = dict(zip(unique, ex.map(lambda v: _fetch_vuln(v, cache_dir, offline), unique)))

    findings = []
    for purl in purls:
        c, ids = comps[purl], ids_by_purl.get(purl, [])
        if not ids:
            c.risk_status = "clean"
            continue
        per_adv = []
        for vid in ids:
            rec, ev = records[vid]
            vector = next((s["score"] for s in rec.get("severity", []) if s.get("type") == "CVSS_V3"), None)
            score = cvss3_score(vector) if vector else None
            label = _band(score) or (rec.get("database_specific", {}).get("severity") or "UNKNOWN").upper()
            label = "MEDIUM" if label == "MODERATE" else label
            intro, fixed, last = _matching_range(rec, c.name, c.version)
            cves = [a for a in rec.get("aliases", []) if a.startswith("CVE-")]
            per_adv.append({
                "finding_id": f"{vid}:{purl}", "rule_id": "OSV", "category": "vulnerability",
                "title": rec.get("summary") or vid,
                "component_id": purl, "advisory_id": vid, "aliases": rec.get("aliases", []),
                "cves": cves, "summary": rec.get("summary", ""), "cvss_vector": vector,
                "cvss": score, "severity": label,
                "affected_range": _fmt_range(intro, fixed, last), "fixed_version": fixed,
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
        if fixes:  # the version that clears every fixable advisory is the highest one
            best = max(fixes, key=_semver_key)
            c.fixed_version = best + (f" (no fix for {len(unfixed)})" if unfixed else "")
        else:
            c.fixed_version = "no fix available"
        c.risk_status = "vulnerable"
    return findings
