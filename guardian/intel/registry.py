"""Read-only package intelligence: npm, PyPI, Maven Central metadata, release-age diffing, and git ref -> SHA resolution."""
import concurrent.futures as cf
from datetime import datetime, timezone
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..config import cache_is_fresh

REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"
MAVEN_SEARCH = "https://search.maven.org/solrsearch/select"


def _sha(text):
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def _parse_iso(s):
    if not s or not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-scanner", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"__404": True}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def registry_metadata(name, version, cache_dir, offline=False):
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    f = cache_dir / (re.sub(r"[^\w.@-]", "_", f"{name}@{version}") + ".json")
    if f.exists() and (offline or cache_is_fresh(f)):
        return json.loads(f.read_text())
    if offline:
        return None
    url = f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            d = json.load(r)
    except Exception as e:
        return {"error": str(e)}
    keep = {"name": d.get("name"), "version": d.get("version"), "deprecated": d.get("deprecated"),
            "license": d.get("license"), "dist": {k: d.get("dist", {}).get(k) for k in ("integrity", "shasum", "tarball")},
            "npm_user": (d.get("_npmUser") or {}).get("name"),
            "maintainers": [m.get("name") for m in d.get("maintainers", [])],
            "has_install_scripts": any(k in (d.get("scripts") or {}) for k in ("preinstall", "install", "postinstall")),
            "source": url}
    f.write_text(json.dumps(keep, indent=1))
    return keep


def npm_packument(name, cache_dir, offline=False):
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    f = cache_dir / (re.sub(r"[^\w.@-]", "_", f"npm-pack-{name}") + ".json")
    if f.exists() and (offline or cache_is_fresh(f)):
        return json.loads(f.read_text())
    if offline:
        return None
    url = f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}"
    d = _get_json(url)
    if d and not d.get("error"):
        keep = {"__404": True} if d.get("__404") else {
            "name": d.get("name"),
            "time": d.get("time", {}),
            "latest": (d.get("dist-tags") or {}).get("latest"),
        }
        f.write_text(json.dumps(keep, indent=1))
        return keep
    return None


def pypi_metadata(name, cache_dir, offline=False):
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    f = cache_dir / (re.sub(r"[^\w.@-]", "_", f"pypi-{name}") + ".json")
    if f.exists() and (offline or cache_is_fresh(f)):
        return json.loads(f.read_text())
    if offline:
        return None
    url = f"{PYPI_REGISTRY}/{urllib.parse.quote(name)}/json"
    d = _get_json(url)
    if d and not d.get("error"):
        if d.get("__404"):
            keep = {"__404": True}
        else:
            rels = {}
            for ver, files in (d.get("releases") or {}).items():
                if files and isinstance(files, list):
                    rels[ver] = [{"upload_time_iso_8601": files[0].get("upload_time_iso_8601", "")}]
            keep = {"name": (d.get("info") or {}).get("name", name), "version": (d.get("info") or {}).get("version"), "releases": rels}
        f.write_text(json.dumps(keep, indent=1))
        return keep
    return None


def maven_metadata(name, cache_dir, offline=False):
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    f = cache_dir / (re.sub(r"[^\w.@-]", "_", f"maven-{name}") + ".json")
    if f.exists() and (offline or cache_is_fresh(f)):
        return json.loads(f.read_text())
    if offline:
        return None
    if ":" not in name:
        return None
    g, a = name.split(":", 1)
    q = urllib.parse.quote(f"g:{g} AND a:{a}")
    url = f"{MAVEN_SEARCH}?q={q}&rows=5&wt=json"
    d = _get_json(url)
    if d and not d.get("error"):
        keep = {"response": {"numFound": (d.get("response") or {}).get("numFound", 0)}}
        f.write_text(json.dumps(keep, indent=1))
        return keep
    return None


def _check_component_registry(comp, cache_dir, offline=False, min_age_days=7, new_pkg_days=30, now=None):
    now = now or datetime.now(timezone.utc)
    eco, name, ver = comp.ecosystem, comp.name, comp.version
    if not name or comp.resolution != "locked":
        return []
    cid = comp.component_id
    path = (comp.found_in or comp.projects or [""])[0]
    findings = []

    def _emit(rule, sev, title, detail, ev_extra):
        anchor = f"{rule}|{cid}|{path}"
        return {
            "finding_id": f"{rule}-{_sha(anchor)[:10]}",
            "rule_id": rule,
            "category": "suspicious",
            "severity": sev,
            "title": title,
            "detail": detail,
            "component_id": cid,
            "evidence_class": "indicator",
            "evidence": {"source": "registry", "path": path, **ev_extra},
            "recommendation": "Verify package provenance and publisher before installing.",
        }

    if eco == "npm":
        data = npm_packument(name, cache_dir, offline)
        if not data:
            return []
        if data.get("__404"):
            findings.append(_emit("SC10", "HIGH", f"Package '{name}' not found on official npm registry (404)",
                                  "Unpublished, private, or removed package name (potential dependency confusion / unknown provenance).",
                                  {"registry": "registry.npmjs.org", "status": 404}))
            return findings
        times = data.get("time") or {}
        rel_time = _parse_iso(times.get(ver, ""))
        created = _parse_iso(times.get("created", ""))
        if rel_time and 0 <= (now - rel_time).days < min_age_days:
            age = (now - rel_time).days
            findings.append(_emit("SC11", "MEDIUM", f"npm release {name}@{ver} published {age}d ago (< {min_age_days}d)",
                                  f"Newly published release ({times.get(ver, '')}).",
                                  {"registry": "registry.npmjs.org", "published": times.get(ver, ""), "age_days": age}))
        elif created and 0 <= (now - created).days < new_pkg_days:
            age = (now - created).days
            findings.append(_emit("SC11", "MEDIUM", f"npm package '{name}' created {age}d ago (< {new_pkg_days}d)",
                                  f"Newly created package ({times.get('created', '')}).",
                                  {"registry": "registry.npmjs.org", "created": times.get("created", ""), "age_days": age}))

    elif eco == "pypi":
        data = pypi_metadata(name, cache_dir, offline)
        if not data:
            return []
        if data.get("__404"):
            findings.append(_emit("SC10", "HIGH", f"Package '{name}' not found on official PyPI (404)",
                                  "Unpublished or internal package name not on pypi.org.",
                                  {"registry": "pypi.org", "status": 404}))
            return findings
        rels = (data.get("releases") or {}).get(ver, [])
        if rels:
            up = _parse_iso(rels[0].get("upload_time_iso_8601", ""))
            if up and 0 <= (now - up).days < min_age_days:
                age = (now - up).days
                findings.append(_emit("SC11", "MEDIUM", f"PyPI release {name}=={ver} uploaded {age}d ago (< {min_age_days}d)",
                                      f"Newly uploaded release ({rels[0].get('upload_time_iso_8601', '')}).",
                                      {"registry": "pypi.org", "uploaded": rels[0].get("upload_time_iso_8601", ""), "age_days": age}))

    elif eco == "maven":
        data = maven_metadata(name, cache_dir, offline)
        if not data:
            return []
        if (data.get("response") or {}).get("numFound", 0) == 0:
            findings.append(_emit("SC10", "HIGH", f"Artifact '{name}' not found on Maven Central",
                                  "Artifact coordinates returned 0 matches on Maven Central.",
                                  {"registry": "search.maven.org", "numFound": 0}))

    return findings


def verify_registries(comps, cache_dir, offline=False, max_checks=24, now=None):
    """Verify direct (and up to max_checks) components against npm, PyPI, and Maven Central in parallel."""
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    supported = [c for c in comps.values() if c.ecosystem in ("npm", "pypi", "maven") and c.resolution == "locked"]
    direct = [c for c in supported if c.relationship == "direct"]
    targets = (direct if len(supported) > max_checks and direct else supported)[:max_checks]
    if not targets:
        return []
    out = []
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_check_component_registry, c, cache_dir, offline, 7, 30, now) for c in targets]
        for fut in futs:
            try:
                out.extend(fut.result())
            except Exception:
                pass
    return out


def resolve_ref_sha(repo_url, ref, cache_dir, offline=False):
    """Tag/branch -> commit SHA via `git ls-remote` (read-only, no clone)."""
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    f = cache_dir / "refs.json"
    cache = json.loads(f.read_text()) if f.exists() else {}
    key = f"{repo_url}@{ref}"
    if key in cache or offline:
        return cache.get(key)
    r = subprocess.run(["git", "ls-remote", repo_url, f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"],
                       capture_output=True, text=True, timeout=30, env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin"})
    rows = dict(line.split("\t")[::-1] for line in r.stdout.splitlines() if "\t" in line)
    sha = rows.get(f"refs/tags/{ref}^{{}}") or rows.get(f"refs/tags/{ref}") or rows.get(f"refs/heads/{ref}")
    cache[key] = sha
    f.write_text(json.dumps(cache, indent=1))
    return sha


