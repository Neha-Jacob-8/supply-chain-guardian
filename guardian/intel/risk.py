"""Deterministic, explainable risk scoring (0-100) for every finding.

The LLM never sets these numbers. Agents read them, explain them and may *recommend*
escalation, but the score and its factor breakdown always come from this file.

Vulnerability score
    severity      40 * cvss/10            (CVSS v3 base; label-derived if no vector)
    exploitability 25 if CVE in CISA KEV, else 15 * EPSS probability
    exposure      15 prod / 3 dev
    reachability  15 direct dep imported by app code, 8 transitive under an imported direct dep
    directness     5 direct dependency
Indicator score: rule base weight + exposure modifier for prod components.
Confidence = share of factors that were observed rather than defaulted.
"""
import json
import re
import urllib.request
from pathlib import Path

from ..policies import load as load_policy

_W = load_policy("risk_weights.json")
LABEL_CVSS = _W["label_to_cvss"]
RULE_BASE = _W["indicator_rule_base"]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="


def band(score):
    return "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"


# ---------- exploit intelligence (cached, optional) ----------

def _fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-scanner"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def load_intel(cves, cache_dir, offline=False):
    """Returns (kev_set | None, {cve: epss} | None). None means 'unknown' (lowers confidence)."""
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    kev_f, epss_f = cache_dir / "kev.json", cache_dir / "epss.json"
    kev = None
    if kev_f.exists():
        kev = set(json.loads(kev_f.read_text()))
    elif not offline:
        try:
            data = _fetch_json(KEV_URL)
            kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
            kev_f.write_text(json.dumps(sorted(kev)))
        except Exception:
            kev = None
    epss = json.loads(epss_f.read_text()) if epss_f.exists() else {}
    missing = sorted(set(cves) - set(epss))
    if missing and not offline:
        try:
            for i in range(0, len(missing), 50):
                chunk = missing[i:i + 50]
                for row in _fetch_json(EPSS_URL + ",".join(chunk)).get("data", []):
                    epss[row["cve"]] = float(row["epss"])
                for c in chunk:          # record "no EPSS score" so we don't refetch
                    epss.setdefault(c, None)
            epss_f.write_text(json.dumps(epss, indent=1))
        except Exception:
            pass
    return kev, (epss if epss else None)


# ---------- package-level reachability ----------

def import_usage(repo, names):
    """name -> [file:line] where app code (not node_modules) requires/imports the package."""
    repo = Path(repo)
    pats = {n: re.compile(r"""(require\(\s*|from\s+|import\s+)['"]""" + re.escape(n) + r"""(/[^'"]*)?['"]""") for n in names}
    hits = {n: [] for n in names}
    for p in repo.rglob("*"):
        rel = p.relative_to(repo)
        if p.suffix not in (".js", ".mjs", ".cjs", ".ts") or {"node_modules", ".git"} & set(rel.parts):
            continue
        try:
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                for n, pat in pats.items():
                    if pat.search(line):
                        hits[n].append(f"{rel}:{i}")
        except OSError:
            continue
    return hits


# ---------- scoring ----------

def score_all(findings, comps, repo, intel_cache, offline=False):
    direct_names = sorted({c.name for c in comps.values() if c.relationship == "direct"})
    usage = import_usage(repo, direct_names)
    cves = sorted({c for f in findings for c in f.get("cves", [])})
    kev, epss = load_intel(cves, intel_cache, offline)
    out = {}
    for f in findings:
        out[f["finding_id"]] = (_score_vuln if f["category"] == "vulnerability" else _score_indicator)(
            f, comps, usage, kev, epss)
    return out, usage


def _reach(c, usage):
    if c is None or c.scope != "prod" or len(c.path) < 2:
        return 0, "not in prod path", True
    direct = c.path[1].split("pkg:npm/", 1)[-1].replace("%40", "@").rsplit("@", 1)[0]
    hits = usage.get(direct, [])
    if c.relationship == "direct":
        return (15, f"imported by app code ({len(hits)} sites, e.g. {hits[0]})", True) if hits else \
               (0, "direct dependency but no import found in app code", True)
    return (8, f"under directly imported '{direct}' ({hits[0]})", True) if hits else \
           (0, f"its direct ancestor '{direct}' is not imported by app code", True)


def _score_vuln(f, comps, usage, kev, epss):
    c = comps.get(f["component_id"])
    factors, observed, total = {}, 0, 5
    cvss = f.get("cvss")
    if cvss is None:
        cvss = LABEL_CVSS.get(f.get("severity"), 5.0)
        factors["severity"] = {"points": round(4 * cvss, 1), "why": f"no CVSS vector; label {f.get('severity')}"}
    else:
        observed += 1
        factors["severity"] = {"points": round(4 * cvss, 1), "why": f"CVSS {cvss}"}
    cves = f.get("cves", [])
    if kev is not None and any(x in kev for x in cves):
        observed += 1
        factors["exploitability"] = {"points": 25, "why": "listed in CISA KEV (exploited in the wild)"}
    elif epss is not None and cves:
        vals = [epss.get(x) for x in cves if epss.get(x) is not None]
        observed += 1 if (vals or kev is not None) else 0
        e = max(vals) if vals else 0.0
        factors["exploitability"] = {"points": round(15 * e, 1),
                                     "why": f"EPSS {e:.3f}" + ("" if vals else " (no score published)") + ", not in KEV"}
    else:
        factors["exploitability"] = {"points": 0, "why": "no CVE alias or exploit intel unavailable"}
    prod = bool(c and c.scope == "prod")
    observed += 1
    factors["exposure"] = {"points": 15 if prod else 3, "why": "prod dependency" if prod else "dev-only tooling"}
    pts, why, ok = _reach(c, usage)
    observed += 1 if ok else 0
    factors["reachability"] = {"points": pts, "why": why}
    direct = bool(c and c.relationship == "direct")
    observed += 1
    factors["directness"] = {"points": 5 if direct else 0, "why": "direct dependency" if direct else "transitive"}
    score = min(100, round(sum(v["points"] for v in factors.values())))
    return {"score": score, "severity": band(score), "factors": factors,
            "confidence": round(observed / total, 2), "computed_by": "formula"}


def _score_indicator(f, comps, usage, kev, epss):
    c = comps.get(f["component_id"]) if f.get("component_id") else None
    base = RULE_BASE.get(f["rule_id"], 20)
    factors = {"rule": {"points": base, "why": f"{f['rule_id']} base weight"}}
    if f["rule_id"] == "SC2" and "moving branch" in f.get("detail", ""):
        factors["rule"] = {"points": base + 10, "why": "SC2 on a moving branch"}
    if c is not None:
        prod = c.scope == "prod"
        factors["exposure"] = {"points": 10 if prod else -5, "why": "prod component" if prod else "dev-only component"}
    if f.get("evidence", {}).get("source") == "git":
        factors["history"] = {"points": 5, "why": "introduced by a specific commit (git evidence)"}
    score = max(0, min(100, round(sum(v["points"] for v in factors.values()))))
    return {"score": score, "severity": band(score), "factors": factors,
            "confidence": 0.6 if f["rule_id"] in ("SC3", "SC4", "MT1") else 0.8, "computed_by": "formula"}
