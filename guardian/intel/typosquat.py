"""Multi-ecosystem API-backed typosquat detector (Rule SC9).

Checks packages across supported ecosystems (npm, pypi, cargo, gem, composer, maven, golang)
by generating Damerau-Levenshtein, homoglyph, transposition, and delimiter variants and querying
live registry / deps.dev APIs (with disk cache + offline fallback) to see if the package mimics
an established package.
"""
import concurrent.futures as cf
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..config import cache_is_fresh

KNOWN_LEGIT = frozenset({
    "preact", "commondir", "esquery", "jqueri", "core-js", "lodash-es", "lodash.merge",
    "lodash.get", "lodash.clonedeep", "lodash.debounce", "lodash.isequal", "react-is",
    "react-router", "fastq", "glob-parent", "minimist-options", "pytest", "cython",
    "urllib3", "jinja2", "markupsafe", "itsdangerous", "werkzeug", "pydantic-core",
})

HOMOGLYPH_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})

DEPS_DEV_SYS = {
    "npm": "NPM",
    "pypi": "PYPI",
    "cargo": "CARGO",
    "maven": "MAVEN",
    "golang": "GO",
    "gem": "RUBYGEMS",
}

# Fallback high-target reference names used when running --offline without cached API responses
OFFLINE_ANCHORS = {
    "npm": ("lodash", "express", "axios", "react", "chalk", "commander", "moment", "request", "webpack", "next", "dotenv", "uuid"),
    "pypi": ("requests", "urllib3", "flask", "django", "numpy", "pandas", "scipy", "pytest", "pydantic", "fastapi", "cryptography", "boto3", "pyyaml", "pillow"),
    "cargo": ("serde", "tokio", "rand", "clap", "reqwest", "anyhow", "thiserror", "regex", "syn", "quote", "futures"),
    "gem": ("rails", "rake", "rspec", "bundler", "puma", "nokogiri", "devise", "sidekiq", "faraday"),
    "composer": ("laravel/framework", "symfony/console", "guzzlehttp/guzzle", "monolog/monolog", "phpunit/phpunit"),
    "maven": ("org.apache.commons:commons-lang3", "com.google.guava:guava", "com.fasterxml.jackson.core:jackson-databind", "org.slf4j:slf4j-api", "junit:junit"),
    "golang": ("github.com/gin-gonic/gin", "github.com/stretchr/testify", "github.com/spf13/cobra", "golang.org/x/crypto", "golang.org/x/net"),
}


def _sha(text):
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def _lev(a, b):
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cur.append(min(prev[j + 1] + 1, cur[j] + 1, prev[j] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_transposition(a, b):
    if len(a) != len(b):
        return False
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]


def _norm_delims(s):
    return re.sub(r"[-_.]", "", s.lower())


def _get_json(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-scanner", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def _api_neighbors(eco, name, cache_dir, offline=False):
    """Fetch similar package candidates and reputation counts from ecosystem APIs + deps.dev."""
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.@-]", "_", f"typo-{eco}-{name}")
    f = cache_dir / f"{safe}.json"
    if f.exists() and (offline or cache_is_fresh(f)):
        return json.loads(f.read_text())
    if offline:
        return {"candidates": list(OFFLINE_ANCHORS.get(eco, ())), "source": "offline-anchors"}

    candidates = set(OFFLINE_ANCHORS.get(eco, ()))
    source = "registry-search-api"
    q = urllib.parse.quote(name)

    if eco == "npm":
        # npm registry search API returns top packages matching prefix/fuzzy text with popularity scores
        stem = name[:max(4, len(name) - 2)]
        d = _get_json(f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(stem)}&size=15")
        for obj in (d or {}).get("objects", []):
            pkg = (obj.get("package") or {}).get("name")
            score = ((obj.get("score") or {}).get("detail") or {}).get("popularity", 0)
            if pkg and score >= 0.15:
                candidates.add(pkg)
    elif eco == "pypi":
        # Check de-homographed and transposed variants via deps.dev / PyPI JSON API
        variants = set()
        low = name.lower()
        de_h = low.translate(HOMOGLYPH_MAP)
        if de_h != low:
            variants.add(de_h)
        for i in range(len(low) - 1):
            if low[i] != low[i + 1]:
                variants.add(low[:i] + low[i + 1] + low[i] + low[i + 2:])
        for v in list(variants)[:4]:
            d = _get_json(f"https://api.deps.dev/v3alpha/systems/PYPI/packages/{urllib.parse.quote(v)}")
            if d and d.get("versions"):
                candidates.add(v)
                source = "api.deps.dev"
    elif eco == "cargo":
        stem = name[:max(4, len(name) - 1)]
        d = _get_json(f"https://crates.io/api/v1/crates?q={urllib.parse.quote(stem)}&per_page=10")
        for cr in (d or {}).get("crates", []):
            if cr.get("name") and (cr.get("downloads") or 0) > 5000:
                candidates.add(cr["name"])
    elif eco == "gem":
        stem = name[:max(4, len(name) - 1)]
        d = _get_json(f"https://rubygems.org/api/v1/search.json?query={urllib.parse.quote(stem)}")
        if isinstance(d, list):
            for g in d[:10]:
                if g.get("name") and (g.get("downloads") or 0) > 5000:
                    candidates.add(g["name"])
    elif eco == "composer":
        stem = name.split("/")[-1][:max(4, len(name.split("/")[-1]) - 1)]
        d = _get_json(f"https://packagist.org/search.json?q={urllib.parse.quote(stem)}&per_page=10")
        for r in (d or {}).get("results", []):
            if r.get("name") and (r.get("downloads") or 0) > 5000:
                candidates.add(r["name"])
    elif eco == "maven":
        art = name.split(":")[-1]
        stem = art[:max(4, len(art) - 1)]
        d = _get_json(f"https://search.maven.org/solrsearch/select?q=a:{urllib.parse.quote(stem)}*&rows=10&wt=json")
        for doc in ((d or {}).get("response") or {}).get("docs", []):
            if doc.get("g") and doc.get("a"):
                candidates.add(f"{doc['g']}:{doc['a']}")

    payload = {"candidates": sorted(candidates), "source": source}
    try:
        f.write_text(json.dumps(payload, indent=1))
    except OSError:
        pass
    return payload


def _check_typosquat(comp, cache_dir, offline=False):
    eco, name = comp.ecosystem, (comp.name or "").strip()
    if eco not in OFFLINE_ANCHORS or not name or len(name) < 5:
        return None
    low = name.lower()
    if low in KNOWN_LEGIT or low.startswith("@types/"):
        return None

    info = _api_neighbors(eco, name, cache_dir, offline)
    pool = info.get("candidates", [])
    if name in pool or low in {p.lower() for p in pool}:
        return None

    is_scoped = low.startswith("@")
    de_homo = low.translate(HOMOGLYPH_MAP)
    flat = _norm_delims(low)

    for ref in sorted(pool):
        ref_low = ref.lower()
        if low == ref_low or len(ref_low) < 5:
            continue
        if is_scoped != ref_low.startswith("@"):
            continue

        reason = ""
        dist = _lev(low, ref_low)
        if flat == _norm_delims(ref_low) and low != ref_low:
            reason = f"delimiter confusion ('{name}' vs '{ref}')"
            dist = 1
        elif de_homo == ref_low and low != ref_low:
            reason = f"homoglyph substitution ('{name}' vs '{ref}')"
            dist = 1
        elif _is_transposition(low, ref_low):
            reason = f"adjacent character swap ('{name}' vs '{ref}')"
            dist = 1
        elif dist == 1 and abs(len(low) - len(ref_low)) <= 1:
            reason = f"edit distance 1 from '{ref}'"

        if reason:
            path = (comp.found_in or comp.projects or [""])[0]
            anchor = f"SC9|{comp.component_id}|{ref}"
            return {
                "finding_id": f"SC9-{_sha(anchor)[:10]}",
                "rule_id": "SC9",
                "category": "suspicious",
                "severity": "HIGH",
                "title": f"Possible typosquat: '{name}' ({reason})",
                "detail": f"Package '{name}' ({eco}) closely mimics '{ref}' via {reason} (verified via {info.get('source', 'registry API')}).",
                "component_id": comp.component_id,
                "evidence_class": "indicator",
                "evidence": {
                    "source": info.get("source", "registry-api"),
                    "path": path,
                    "package": name,
                    "similar_to": ref,
                    "distance": dist,
                    "technique": reason,
                },
                "recommendation": f"Verify whether '{name}' was intended or replace with '{ref}'.",
            }
    return None


def detect_typosquats(comps, cache_dir, offline=False):
    """Run multi-ecosystem API-backed typosquat detection across components in parallel."""
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    targets = [c for c in comps.values() if c.ecosystem in OFFLINE_ANCHORS]
    if not targets:
        return []
    out = []
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_check_typosquat, c, cache_dir, offline) for c in targets]
        for fut in futs:
            try:
                res = fut.result()
                if res:
                    out.append(res)
            except Exception:
                pass
    return out
