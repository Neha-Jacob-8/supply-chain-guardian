"""Read-only package intelligence: npm registry metadata and git ref -> SHA resolution (cached)."""
import json
import re
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.npmjs.org"


def registry_metadata(name, version, cache_dir, offline=False):
    cache_dir = Path(cache_dir); cache_dir.mkdir(parents=True, exist_ok=True)
    f = cache_dir / (re.sub(r"[^\w.@-]", "_", f"{name}@{version}") + ".json")
    if f.exists():
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


