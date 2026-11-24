"""Parallel source-code import crawler for shadow/phantom dependencies (Rule SC8)
and dynamic Python import-to-distribution resolution (`importlib.metadata` + `top_level.txt`).

When an imported third-party package is missing from manifests (or only present as a transitive
dependency), the crawler:
  1. Dynamically maps the import name to its package distribution name.
  2. Resolves any installed/transitive/latest version and checks OSV for CVEs or MAL-* advisories.
  3. Flags a security vulnerability if vulnerable/malicious, or emits a shadow-dependency finding
     (SC8) with a deterministic suggestion to pin & add it to requirements.txt / package.json.
"""
import concurrent.futures as cf
import glob
import hashlib
import importlib.metadata as importlib_meta
import os
import re
import sys
from pathlib import Path

from ..discovery.purl import normalize_name, purl as make_purl
from ..models import Component
from .osv import scan_components
from .registry import npm_packument, pypi_metadata

SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    "target", "vendor", "site-packages", "output", ".guardian", ".truststack",
    "fixtures", "__fixtures__", "testdata", "test-fixtures", "test_fixtures",
})

PY_STDLIB = getattr(sys, "stdlib_module_names", frozenset()) | {
    "typing_extensions", "__future__", "builtins",
}

NODE_BUILTIN = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib", "test",
})

# Fallback common aliases only used when package is not installed in any discoverable dist-info
FALLBACK_PY_IMPORT_TO_DIST = {
    "yaml": "pyyaml", "bs4": "beautifulsoup4", "pil": "pillow", "sklearn": "scikit-learn",
    "dateutil": "python-dateutil", "cv2": "opencv-python", "google": "protobuf",
    "jwt": "pyjwt", "dotenv": "python-dotenv", "crypto": "pycryptodome",
    "attr": "attrs", "msgpack": "msgpack-python",
}


def _sha(text):
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def dynamic_py_import_map(repo=None):
    """Build {import_module_lower: {normalized_dist_name}} dynamically from importlib.metadata and repo .venv dist-info."""
    mapping = {}
    for mod, dist in FALLBACK_PY_IMPORT_TO_DIST.items():
        mapping.setdefault(mod.lower(), set()).add(normalize_name("pypi", dist))
    try:
        for mod, dists in importlib_meta.packages_distributions().items():
            mapping.setdefault(mod.lower(), set()).update(normalize_name("pypi", d) for d in dists)
    except Exception:
        pass

    search_roots = []
    if repo:
        r = Path(repo)
        for vname in (".venv", "venv", "env"):
            if (r / vname).is_dir():
                search_roots.append(str(r / vname))
    for vroot in search_roots:
        sps = (
            glob.glob(os.path.join(vroot, "lib", "python*", "site-packages"))
            + glob.glob(os.path.join(vroot, "Lib", "site-packages"))
        )
        for sp in sps:
            for di in glob.glob(os.path.join(sp, "*.dist-info")):
                meta_path = os.path.join(di, "METADATA")
                top_path = os.path.join(di, "top_level.txt")
                if not os.path.exists(meta_path):
                    continue
                try:
                    text = Path(meta_path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                m = re.search(r"^Name:\s*(.+)$", text, re.M)
                if not m:
                    continue
                dist_norm = normalize_name("pypi", m.group(1).strip())
                if os.path.exists(top_path):
                    try:
                        lines = Path(top_path).read_text(encoding="utf-8", errors="replace").splitlines()
                    except OSError:
                        lines = []
                    for ln in lines:
                        mod = ln.strip().lower()
                        if mod:
                            mapping.setdefault(mod, set()).add(dist_norm)
                else:
                    mapping.setdefault(dist_norm.replace("-", "_"), set()).add(dist_norm)
    return mapping


def dist_to_py_modules(repo=None):
    """Inverse map: {normalized_dist_name: {import_module_names}} for reachability analysis."""
    inv = {}
    for mod, dists in dynamic_py_import_map(repo).items():
        for d in dists:
            inv.setdefault(d, set()).add(mod)
    return inv


def _installed_venv_versions(repo):
    """Discover installed package versions from repo .venv/*.dist-info/METADATA if present."""
    versions = {}
    if not repo:
        return versions
    r = Path(repo)
    for vname in (".venv", "venv", "env"):
        vroot = r / vname
        if not vroot.is_dir():
            continue
        sps = (
            glob.glob(os.path.join(str(vroot), "lib", "python*", "site-packages"))
            + glob.glob(os.path.join(str(vroot), "Lib", "site-packages"))
        )
        for sp in sps:
            for di in glob.glob(os.path.join(sp, "*.dist-info")):
                meta = Path(di) / "METADATA"
                if not meta.is_file():
                    continue
                try:
                    t = meta.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                nm = re.search(r"^Name:\s*(.+)$", t, re.M)
                vm = re.search(r"^Version:\s*(.+)$", t, re.M)
                if nm and vm:
                    versions[normalize_name("pypi", nm.group(1).strip())] = vm.group(1).strip()
    return versions


def _scan_py_file(path, rel, local_mods):
    hits = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    for lineno, line in enumerate(lines, 1):
        m = re.match(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
        if not m:
            continue
        mod = m.group(1)
        if mod in PY_STDLIB or mod.lower() in local_mods or mod.startswith("_"):
            continue
        hits.append(("pypi", mod, rel, lineno, line.strip()[:160]))
    return hits


def _scan_js_file(path, rel):
    hits = []
    pat = re.compile(r"""(?:import\s+(?:[^'"]+?\s+from\s+)?|require\s*\(\s*)['"]([^'"]+)['"]""")
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    for lineno, line in enumerate(lines, 1):
        if line.lstrip().startswith(("//", "/*", "*")):
            continue
        for m in pat.finditer(line):
            spec = m.group(1)
            if (
                spec.startswith((".", "/", "node:", "bun:", "deno:", "http:", "https:", "#", "~"))
                or not re.match(r"^(?:@[a-z0-9_.\-]+/)?[a-z0-9_.\-]+(?:/[a-zA-Z0-9_.\-]+)*$", spec)
            ):
                continue
            pkg = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
            if pkg in NODE_BUILTIN or pkg.split("/")[0] in NODE_BUILTIN:
                continue
            hits.append(("npm", pkg, rel, lineno, line.strip()[:160]))
    return hits


RUST_STD = frozenset({"std", "core", "alloc", "proc_macro", "test", "crate", "self", "super"})

JAVA_STD_PREFIXES = (
    "java.", "javax.", "jakarta.annotation.", "jdk.", "sun.", "com.sun.",
    "org.w3c.", "org.xml.", "org.ietf.", "org.omg.",
)

RUBY_STD = frozenset({
    "json", "yaml", "set", "uri", "net", "cgi", "csv", "date", "time", "digest",
    "erb", "fileutils", "find", "forwardable", "ipaddr", "logger", " monitor",
    "open3", "openssl", "optparse", "ostruct", "pathname", "pp", "pstore",
    "psych", "rinda", "securerandom", "shellwords", "singleton", "socket",
    "stringio", "strscan", " syslog", "tempfile", "thread", "thwait", "timeout",
    "tmpdir", "tsort", "un", "weakref", "webrick", "zlib", "rubygems", "bundler",
})


def _scan_rust_file(path, rel, local_mods):
    """Scan .rs files for `use <crate>::...` and `extern crate <crate>`."""
    hits = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    for lineno, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("//"):
            continue
        m = re.match(r"^(?:pub\s+)?(?:use\s+(?:::)?([A-Za-z_][A-Za-z0-9_]*)::|extern\s+crate\s+([A-Za-z_][A-Za-z0-9_]*))", s)
        if not m:
            continue
        crate = (m.group(1) or m.group(2)).lower()
        if crate in RUST_STD or crate in local_mods:
            continue
        hits.append(("cargo", crate, rel, lineno, s[:160]))
    return hits


def _scan_java_file(path, rel, local_packages):
    """Scan .java files for `import <group.package.Class>;`."""
    hits = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    for lineno, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith(("//", "/*", "*")):
            continue
        m = re.match(r"^import\s+(?:static\s+)?([a-zA-Z0-9_.]+)\s*;", s)
        if not m:
            continue
        imp = m.group(1)
        if imp.startswith(JAVA_STD_PREFIXES) or any(imp.startswith(lp) for lp in local_packages if lp):
            continue
        parts = imp.split(".")
        if len(parts) >= 3:
            # Use top 2 or 3 domain segments as group/package prefix (e.g. org.apache.commons or com.google.common)
            pkg_prefix = ".".join(parts[:3])
            hits.append(("maven", pkg_prefix, rel, lineno, s[:160]))
    return hits


def _scan_go_file(path, rel, module_prefix):
    """Scan .go files for third-party imports (paths with a domain dot like github.com/owner/repo)."""
    hits = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    in_block = False
    for lineno, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("//"):
            continue
        if s.startswith("import ("):
            in_block = True
            continue
        if in_block and s.startswith(")"):
            in_block = False
            continue
        m = None
        if in_block:
            m = re.search(r'"([^"]+)"', s)
        elif s.startswith("import "):
            m = re.search(r'"([^"]+)"', s)
        if not m:
            continue
        imp = m.group(1)
        first_seg = imp.split("/")[0]
        if "." not in first_seg:  # Go standard library packages do not have dots in first path segment
            continue
        if module_prefix and imp.startswith(module_prefix):
            continue
        parts = imp.split("/")
        mod_root = "/".join(parts[:3]) if first_seg in ("github.com", "gitlab.com", "bitbucket.org") and len(parts) >= 3 else imp
        hits.append(("golang", mod_root, rel, lineno, s[:160]))
    return hits


def _scan_ruby_file(path, rel):
    """Scan .rb files for `require '<gem>'`."""
    hits = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return hits
    for lineno, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"""^require\s+['"]([^'"]+)['"]""", s)
        if not m:
            continue
        spec = m.group(1)
        if spec.startswith((".", "/")) or spec.split("/")[0] in RUBY_STD:
            continue
        gem = spec.split("/")[0]
        hits.append(("gem", gem, rel, lineno, s[:160]))
    return hits


def crawl_shadow_dependencies(repo, inv, comps, cache_dir=None, offline=False):
    """Crawl source files (.py, .js/.ts, .rs, .java, .go, .rb) in parallel, find shadow/phantom imports,
    check OSV for vulnerabilities, and emit SC8 findings + optional OSV vulnerability findings."""
    repo = Path(repo)
    cache_dir = Path(cache_dir) if cache_dir else (repo / "output" / "cache")
    ecosystems = set((inv or {}).get("ecosystems", [])) or {c.ecosystem for c in comps.values()}

    direct_py = {normalize_name("pypi", c.name) for c in comps.values() if c.ecosystem == "pypi" and c.relationship == "direct"}
    trans_py = {normalize_name("pypi", c.name): c for c in comps.values() if c.ecosystem == "pypi" and c.relationship != "direct"}
    direct_npm = {c.name.lower() for c in comps.values() if c.ecosystem == "npm" and c.relationship == "direct"}
    trans_npm = {c.name.lower(): c for c in comps.values() if c.ecosystem == "npm" and c.relationship != "direct"}
    direct_cargo = {c.name.lower().replace("-", "_"): c for c in comps.values() if c.ecosystem == "cargo" and c.relationship == "direct"}
    trans_cargo = {c.name.lower().replace("-", "_"): c for c in comps.values() if c.ecosystem == "cargo" and c.relationship != "direct"}
    direct_maven = [c for c in comps.values() if c.ecosystem == "maven" and c.relationship == "direct"]
    trans_maven = [c for c in comps.values() if c.ecosystem == "maven" and c.relationship != "direct"]
    direct_go = {c.name.lower(): c for c in comps.values() if c.ecosystem == "golang" and c.relationship == "direct"}
    trans_go = {c.name.lower(): c for c in comps.values() if c.ecosystem == "golang" and c.relationship != "direct"}
    direct_gem = {c.name.lower().replace("-", "_"): c for c in comps.values() if c.ecosystem == "gem" and c.relationship == "direct"}
    trans_gem = {c.name.lower().replace("-", "_"): c for c in comps.values() if c.ecosystem == "gem" and c.relationship != "direct"}

    # Also read Cargo.toml direct dependencies if present so declared crates aren't falsely flagged when Cargo.lock is used
    cargo_toml = repo / "Cargo.toml"
    if cargo_toml.exists():
        try:
            import tomllib
            ct = tomllib.loads(cargo_toml.read_text(errors="replace"))
            for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
                for k in (ct.get(sec) or {}):
                    direct_cargo.setdefault(k.lower().replace("-", "_"), None)
            pkg_n = ((ct.get("package") or {}).get("name") or "").lower().replace("-", "_")
            if pkg_n:
                direct_cargo.setdefault(pkg_n, None)
        except Exception:
            pass

    go_module_prefix = ""
    if (repo / "go.mod").exists():
        m = re.search(r"^module\s+(\S+)", (repo / "go.mod").read_text(errors="replace"), re.M)
        if m:
            go_module_prefix = m.group(1).strip()

    py_files, js_files, rs_files, java_files, go_files, rb_files = [], [], [], [], [], []
    local_py_mods, local_rs_mods, local_java_pkgs = set(), set(), set()

    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        rel_dir = Path(root).relative_to(repo)
        if rel_dir != Path("."):
            local_py_mods.add(rel_dir.parts[0].lower())
        for d in dirs:
            local_py_mods.add(d.lower())
            local_rs_mods.add(d.lower().replace("-", "_"))
        for fname in files:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, repo).replace("\\", "/")
            stem = os.path.splitext(fname)[0].lower()
            if fname.endswith(".py"):
                local_py_mods.add(stem)
                if "pypi" in ecosystems or (repo / "requirements.txt").exists() or (repo / "pyproject.toml").exists():
                    py_files.append((full, rel))
            elif fname.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
                if "npm" in ecosystems or (repo / "package.json").exists():
                    js_files.append((full, rel))
            elif fname.endswith(".rs"):
                local_rs_mods.add(stem.replace("-", "_"))
                if "cargo" in ecosystems or cargo_toml.exists() or (repo / "Cargo.lock").exists():
                    rs_files.append((full, rel))
            elif fname.endswith(".java"):
                if "maven" in ecosystems or (repo / "pom.xml").exists():
                    java_files.append((full, rel))
                    try:
                        pm = re.search(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;", Path(full).read_text(errors="replace"), re.M)
                        if pm:
                            pts = pm.group(1).split(".")
                            local_java_pkgs.add(".".join(pts[:min(2, len(pts))]))
                    except OSError:
                        pass
            elif fname.endswith(".go") and not fname.endswith("_test.go"):
                if "golang" in ecosystems or (repo / "go.mod").exists():
                    go_files.append((full, rel))
            elif fname.endswith(".rb"):
                if "gem" in ecosystems or (repo / "Gemfile.lock").exists() or (repo / "Gemfile").exists():
                    rb_files.append((full, rel))

    if not any((py_files, js_files, rs_files, java_files, go_files, rb_files)):
        return []

    import_map = dynamic_py_import_map(repo) if py_files else {}
    venv_versions = _installed_venv_versions(repo) if py_files else {}

    raw_hits = []
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_scan_py_file, full, rel, local_py_mods) for full, rel in py_files]
        futs += [pool.submit(_scan_js_file, full, rel) for full, rel in js_files]
        futs += [pool.submit(_scan_rust_file, full, rel, local_rs_mods) for full, rel in rs_files]
        futs += [pool.submit(_scan_java_file, full, rel, local_java_pkgs) for full, rel in java_files]
        futs += [pool.submit(_scan_go_file, full, rel, go_module_prefix) for full, rel in go_files]
        futs += [pool.submit(_scan_ruby_file, full, rel) for full, rel in rb_files]
        for fut in futs:
            try:
                raw_hits.extend(fut.result())
            except Exception:
                pass

    def _maven_matches(comp_name, imp_prefix):
        g, _, a = comp_name.lower().partition(":")
        imp_l = imp_prefix.lower()
        return imp_l.startswith(g) or g.startswith(imp_l) or a.replace("-", "") in imp_l.replace(".", "")

    shadow_records = {}  # (eco, pkg_name) -> {import_name, rel, lineno, excerpt, kind, version, comp}
    for eco, imp_name, rel, lineno, excerpt in raw_hits:
        if eco == "pypi":
            mod_norm = normalize_name("pypi", imp_name)
            mapped_dists = import_map.get(imp_name.lower(), {mod_norm})
            if mapped_dists & direct_py:
                continue
            trans_hit = next((trans_py[d] for d in mapped_dists if d in trans_py), None)
            pkg_name = trans_hit.name if trans_hit else sorted(mapped_dists)[0]
            key = ("pypi", normalize_name("pypi", pkg_name))
            if key not in shadow_records:
                ver = (trans_hit.version if trans_hit else venv_versions.get(key[1], ""))
                shadow_records[key] = {
                    "eco": "pypi", "pkg": pkg_name, "import": imp_name,
                    "rel": rel, "lineno": lineno, "excerpt": excerpt,
                    "kind": "phantom (transitive-only)" if trans_hit else "undeclared shadow",
                    "version": ver, "existing_comp": trans_hit,
                }
        elif eco == "npm":
            low = imp_name.lower()
            if low in direct_npm:
                continue
            trans_hit = trans_npm.get(low)
            key = ("npm", low)
            if key not in shadow_records:
                ver = trans_hit.version if trans_hit else ""
                shadow_records[key] = {
                    "eco": "npm", "pkg": imp_name, "import": imp_name,
                    "rel": rel, "lineno": lineno, "excerpt": excerpt,
                    "kind": "phantom (transitive-only)" if trans_hit else "undeclared shadow",
                    "version": ver, "existing_comp": trans_hit,
                }
        elif eco == "cargo":
            norm = imp_name.lower().replace("-", "_")
            if norm in direct_cargo:
                continue
            trans_hit = trans_cargo.get(norm)
            pkg_name = trans_hit.name if trans_hit else imp_name
            key = ("cargo", pkg_name.lower())
            if key not in shadow_records:
                shadow_records[key] = {
                    "eco": "cargo", "pkg": pkg_name, "import": imp_name,
                    "rel": rel, "lineno": lineno, "excerpt": excerpt,
                    "kind": "phantom (transitive-only)" if trans_hit else "undeclared shadow",
                    "version": trans_hit.version if trans_hit else "",
                    "existing_comp": trans_hit,
                }
        elif eco == "maven":
            if any(_maven_matches(c.name, imp_name) for c in direct_maven):
                continue
            trans_hit = next((c for c in trans_maven if _maven_matches(c.name, imp_name)), None)
            pkg_name = trans_hit.name if trans_hit else f"{imp_name}:{imp_name.split('.')[-1]}"
            key = ("maven", pkg_name.lower())
            if key not in shadow_records:
                shadow_records[key] = {
                    "eco": "maven", "pkg": pkg_name, "import": imp_name,
                    "rel": rel, "lineno": lineno, "excerpt": excerpt,
                    "kind": "phantom (transitive-only)" if trans_hit else "undeclared shadow",
                    "version": trans_hit.version if trans_hit else "",
                    "existing_comp": trans_hit,
                }
        elif eco == "golang":
            low = imp_name.lower()
            if any(low == d or low.startswith(d + "/") for d in direct_go):
                continue
            trans_hit = next((c for d, c in trans_go.items() if low == d or low.startswith(d + "/")), None)
            pkg_name = trans_hit.name if trans_hit else imp_name
            key = ("golang", pkg_name.lower())
            if key not in shadow_records:
                shadow_records[key] = {
                    "eco": "golang", "pkg": pkg_name, "import": imp_name,
                    "rel": rel, "lineno": lineno, "excerpt": excerpt,
                    "kind": "phantom (transitive-only)" if trans_hit else "undeclared shadow",
                    "version": trans_hit.version if trans_hit else "",
                    "existing_comp": trans_hit,
                }
        elif eco == "gem":
            norm = imp_name.lower().replace("-", "_")
            if norm in direct_gem:
                continue
            trans_hit = trans_gem.get(norm)
            pkg_name = trans_hit.name if trans_hit else imp_name
            key = ("gem", pkg_name.lower())
            if key not in shadow_records:
                shadow_records[key] = {
                    "eco": "gem", "pkg": pkg_name, "import": imp_name,
                    "rel": rel, "lineno": lineno, "excerpt": excerpt,
                    "kind": "phantom (transitive-only)" if trans_hit else "undeclared shadow",
                    "version": trans_hit.version if trans_hit else "",
                    "existing_comp": trans_hit,
                }

    if not shadow_records:
        return []

    # Resolve latest version from registry cache/API if version is still unknown so OSV & pinning have an exact version
    probe_comps = {}
    for key, rec in shadow_records.items():
        if not rec["version"]:
            if rec["eco"] == "pypi":
                meta = pypi_metadata(rec["pkg"], cache_dir / "registry", offline=offline)
                if meta and not meta.get("__404"):
                    rec["version"] = meta.get("version") or ""
            elif rec["eco"] == "npm":
                meta = npm_packument(rec["pkg"], cache_dir / "registry", offline=offline)
                if meta and not meta.get("__404"):
                    rec["version"] = meta.get("latest") or ""
        cid = (rec["existing_comp"].component_id if rec["existing_comp"]
               else make_purl(rec["eco"], rec["pkg"], rec["version"] or None))
        rec["component_id"] = cid
        if rec["version"] and not rec["existing_comp"]:
            probe_comps[cid] = Component(
                component_id=cid, name=rec["pkg"], version=rec["version"],
                ecosystem=rec["eco"], relationship="direct", scope="prod",
                path=[f"file:{rec['rel']}", cid], resolution="declared-only",
                found_in=[rec["rel"]], projects=[rec["rel"]],
            )

    shadow_vulns_by_cid = {}
    if probe_comps:
        try:
            v_findings = scan_components(probe_comps, cache_dir / "osv", offline=offline)
            for vf in v_findings:
                shadow_vulns_by_cid.setdefault(vf["component_id"], []).append(vf)
        except Exception:
            pass

    MANIFEST_BY_ECO = {
        "pypi": "requirements.txt",
        "npm": "package.json",
        "cargo": "Cargo.toml",
        "maven": "pom.xml",
        "golang": "go.mod",
        "gem": "Gemfile",
    }

    findings = []
    for key, rec in sorted(shadow_records.items()):
        cid = rec["component_id"]
        eco, pkg, ver = rec["eco"], rec["pkg"], rec["version"]
        rel, lineno = rec["rel"], rec["lineno"]
        manifest = MANIFEST_BY_ECO.get(eco, "manifest")
        pin_cmd = (f"Add `{pkg}=={ver}` to {manifest}" if (eco == "pypi" and ver)
                   else f'Add `{pkg} = "{ver or "*"}"` to {manifest}' if eco == "cargo"
                   else f"Add `<dependency>` for `{pkg}` to {manifest}" if eco == "maven"
                   else f"Add `require {pkg} {ver}` to {manifest}" if eco == "golang"
                   else f"Add `gem '{pkg}'` to {manifest}" if eco == "gem"
                   else f'Add `"{pkg}": "{ver or "*"}"` to {manifest}' if eco == "npm"
                   else f"Add `{pkg}` to {manifest}")

        # Also check if existing transitive component already had OSV findings
        comp_obj = rec["existing_comp"] or probe_comps.get(cid)
        vulns = shadow_vulns_by_cid.get(cid, [])
        has_vuln = bool(vulns or (comp_obj and comp_obj.risk_status in ("vulnerable", "malicious")))
        is_mal = bool((comp_obj and comp_obj.risk_status == "malicious") or any(v.get("category") == "malicious" for v in vulns))

        if cid not in comps and comp_obj:
            comps[cid] = comp_obj

        if is_mal:
            sev = "CRITICAL"
            title = f"Malicious {rec['kind']} dependency '{pkg}' imported in {rel}:{lineno}"
            detail = (f"Source file {rel}:{lineno} imports '{rec['import']}' ({pkg}{'@' + ver if ver else ''}), "
                      f"which is NOT declared in {manifest} and matches a known MALICIOUS advisory on OSV!")
            fix = f"Remove '{rec['import']}' from {rel}:{lineno} immediately and audit the environment."
        elif has_vuln:
            advs = ", ".join(comp_obj.advisory_ids[:4]) if (comp_obj and comp_obj.advisory_ids) else "OSV advisory"
            sev = "HIGH"
            title = f"Vulnerable {rec['kind']} dependency '{pkg}' ({advs}) imported in {rel}:{lineno}"
            detail = (f"Source file {rel}:{lineno} directly imports '{rec['import']}' ({pkg}{'@' + ver if ver else ''}), "
                      f"which is missing from {manifest} and has known security vulnerabilities ({advs}).")
            fix = f"{pin_cmd} at a patched version ({comp_obj.fixed_version if comp_obj else 'latest'}) or remove the import."
        else:
            sev = "MEDIUM"
            title = f"Shadow/undeclared import '{pkg}' in {rel}:{lineno} missing from {manifest}"
            detail = (f"Source file {rel}:{lineno} imports '{rec['import']}' (resolved to {eco} package '{pkg}'"
                      f"{'@' + ver if ver else ''}), which is {rec['kind']} (not declared as a direct dependency in {manifest}).")
            fix = f"{pin_cmd} so the dependency is explicitly tracked and locked."

        anchor = f"SC8|{cid}|{rel}|{lineno}"
        findings.append({
            "finding_id": f"SC8-{_sha(anchor)[:10]}",
            "rule_id": "SC8",
            "category": "malicious" if is_mal else "suspicious",
            "severity": sev,
            "title": title,
            "detail": detail,
            "component_id": cid,
            "evidence_class": "indicator",
            "evidence": {
                "source": "crawler",
                "path": rel,
                "line": lineno,
                "sha256": _sha(rec["excerpt"]),
                "excerpt": rec["excerpt"],
                "import_name": rec["import"],
                "package": pkg,
                "ecosystem": eco,
                "resolved_version": ver or None,
                "shadow_kind": rec["kind"],
                "vulnerable": has_vuln,
            },
            "recommendation": fix,
        })
        for vf in vulns:
            findings.append(vf)
    return findings
