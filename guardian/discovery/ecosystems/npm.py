"""npm: package-lock.json (v2/v3, full graph), yarn.lock v1 (full graph), package.json alone (declared only)."""
import json
import re
from pathlib import Path

from ..graph import build_components
from ..lockfile import build_instance_edges, load_lockfile
from .base import ProjectGraph, assemble


def _remap(root_id, new_root, comps, adj):
    for c in comps.values():
        c.path = [new_root if x == root_id else x for x in c.path]
        c.parents = [new_root if x == root_id else x for x in c.parents]
    adj = {(new_root if k == root_id else k): v for k, v in adj.items()}
    return comps, adj


def parse_package_lock(repo, rel):
    data = load_lockfile(repo / rel)
    pk = data["packages"]
    edges, gaps = build_instance_edges(pk)
    name = data.get("name") or pk[""].get("name") or (repo / rel).parent.name
    version = data.get("version") or pk[""].get("version") or ""
    root_id, comps, adj, g2 = build_components(pk, edges, name, version or "0.0.0")
    new_root = f"project:{rel}"
    comps, adj = _remap(root_id, new_root, comps, adj)
    for c in comps.values():
        c.projects = [rel]
    return {"root": new_root, "name": name, "version": version, "ecosystem": "npm", "manifest": rel,
            "components": comps, "adjacency": adj, "gaps": gaps + g2}


def _direct_from_package_json(pg, pj_path, resolve):
    try:
        pj = json.loads(pj_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    for section, scope in (("dependencies", "prod"), ("optionalDependencies", "prod"), ("devDependencies", "dev")):
        for name, spec in (pj.get(section) or {}).items():
            cid = resolve(name, spec)
            if cid:
                pg.direct.setdefault(cid, scope)
    return pj


def parse_yarn_lock(repo, rel):
    text = (repo / rel).read_text(errors="replace")
    pj_path = (repo / rel).parent / "package.json"
    pj = json.loads(pj_path.read_text()) if pj_path.exists() else {}
    pg = ProjectGraph(rel, "npm", pj.get("name") or (repo / rel).parent.name, pj.get("version", ""))
    if "__metadata:" in text:
        pg.gap("unsupported_format", "Yarn Berry (v2+) lockfile is not parsed yet")
        return assemble(pg)
    entries, spec_to_id, cur = [], {}, None
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" "):
            specs = [s.strip().strip('"') for s in line.rstrip(":").split(",")]
            cur = {"specs": specs, "deps": {}, "section": None}
            entries.append(cur)
        elif cur is not None:
            s = line.strip()
            if line.startswith("    ") and cur["section"]:
                k, _, v = s.partition(" ")
                cur["deps"][k.strip('"')] = v.strip('"')
            elif s.endswith(":"):
                cur["section"] = s[:-1]
            else:
                cur["section"] = None
                k, _, v = s.partition(" ")
                cur[k] = v.strip('"')
    for e in entries:
        name = e["specs"][0].rsplit("@", 1)[0] if not e["specs"][0].startswith("@") else "@" + e["specs"][0][1:].rsplit("@", 1)[0]
        cid = pg.add(name, e.get("version", ""), source_url=e.get("resolved"), integrity=e.get("integrity"))
        e["id"] = cid
        for s in e["specs"]:
            spec_to_id[s] = cid
    for e in entries:
        for dep, rng in e["deps"].items():
            child = spec_to_id.get(f"{dep}@{rng}")
            if child:
                pg.edges.append((e["id"], child))
    _direct_from_package_json(pg, pj_path, lambda n, s: spec_to_id.get(f"{n}@{s}"))
    return assemble(pg)


def parse_package_json(repo, rel):
    pj_path = repo / rel
    try:
        pj = json.loads(pj_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    pg = ProjectGraph(rel, "npm", pj.get("name") or pj_path.parent.name, pj.get("version", ""))
    for section, scope in (("dependencies", "prod"), ("optionalDependencies", "prod"), ("devDependencies", "dev")):
        for name, spec in (pj.get(section) or {}).items():
            exact = spec if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", str(spec)) else ""
            cid = pg.add(name, exact, resolution="locked" if exact else "declared-only", spec=spec)
            pg.direct[cid] = scope
    if pg.packages:
        pg.gap("no_lockfile", f"{len(pg.packages)} declared npm dependencies without a lockfile: versions are "
                              "ranges and transitive dependencies are unknown")
    return assemble(pg)


def _pnpm_key(key):
    """'/@s/x@1.0.0(peer@2)' or '@s/x@1.0.0(peer@2)' -> ('@s/x', '1.0.0')."""
    base = key.lstrip("/").split("(")[0]
    name, _, ver = base.rpartition("@")
    return name, ver


def _pnpm_ver(name, ver):
    """Importer/dependency version -> (name, version) or None for workspace links; handles npm: aliases."""
    ver = str(ver).split("(")[0]
    if ver.startswith(("link:", "file:", "workspace:")):
        return None
    if ver.startswith("npm:"):
        return _pnpm_key(ver[4:])
    if ver.startswith("/"):
        return _pnpm_key(ver)
    return name, ver


def _fallback_pnpm_yaml(text):
    """Fallback parser for pnpm-lock.yaml when PyYAML is not installed."""
    root = {}
    stack = [(-1, root)]
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s.strip() or s.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        stripped = s.strip()
        if ":" not in stripped:
            continue
        k, _, v = stripped.partition(":")
        k, v = k.strip().strip("'\""), v.strip()
        if not isinstance(parent, dict):
            continue
        if not v:
            parent[k] = {}
            stack.append((indent, parent[k]))
        elif v == "{}":
            parent[k] = {}
        elif v.startswith("{") and v.endswith("}"):
            # Parse inline YAML flow map like {specifier: ^5.0.0, version: 5.0.0} or {resolution: {integrity: sha512-AAA}}
            inner = v[1:-1].strip()
            if "resolution:" in inner and "integrity:" in inner:
                m = re.search(r"integrity:\s*([^\s,}]+)", inner)
                parent[k] = {"resolution": {"integrity": m.group(1).strip("'\"") if m else None}}
            else:
                obj = {}
                for part in inner.split(","):
                    if ":" in part:
                        ik, _, iv = part.partition(":")
                        obj[ik.strip().strip("'\"")] = iv.strip().strip("'\"")
                parent[k] = obj
        else:
            parent[k] = v.strip("'\"")
    return [root]


def parse_pnpm_lock(repo, rel):
    """pnpm-lock.yaml v6-v9: one project per workspace importer, each with only the packages it reaches."""
    text = (repo / rel).read_text()
    try:
        import yaml
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except ImportError:
        docs = _fallback_pnpm_yaml(text)
    doc = max(docs, key=lambda d: len(d.get("packages") or {}) + len(d.get("importers") or {}), default={})
    packages, snapshots = doc.get("packages") or {}, doc.get("snapshots") or {}
    meta, edges = {}, {}
    for key, p in packages.items():
        name, ver = _pnpm_key(key)
        meta[(name, ver)] = {"integrity": ((p or {}).get("resolution") or {}).get("integrity"),
                             "has_install_script": bool((p or {}).get("requiresBuild"))}
    for key, p in (snapshots or packages).items():          # v9 edges live in snapshots, v6 in packages
        parent = _pnpm_key(key)
        for section in ("dependencies", "optionalDependencies"):
            for dn, dv in ((p or {}).get(section) or {}).items():
                child = _pnpm_ver(dn, dv)
                if child:
                    edges.setdefault(parent, set()).add(child)
    importers = doc.get("importers") or {".": {k: doc.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")}}
    base_dir = Path(rel).parent
    results = []
    for imp, spec in importers.items():
        man = str((base_dir / imp / "package.json")).replace("\\", "/")
        man = man[2:] if man.startswith("./") else man
        pj = repo / man
        try:
            name = json.loads(pj.read_text()).get("name") if pj.exists() else None
        except (OSError, json.JSONDecodeError):
            name = None
        pg = ProjectGraph(man, "npm", name or (imp if imp != "." else (repo / rel).parent.name))
        direct = {}
        for section, scope in (("dependencies", "prod"), ("optionalDependencies", "prod"), ("devDependencies", "dev")):
            for dn, dv in ((spec or {}).get(section) or {}).items():
                nv = _pnpm_ver(dn, dv["version"] if isinstance(dv, dict) else dv)
                if nv:
                    direct.setdefault(nv, scope)
        seen, stack = set(), list(direct)
        while stack:                                       # only packages this importer reaches
            nv = stack.pop()
            if nv in seen:
                continue
            seen.add(nv)
            stack.extend(edges.get(nv, ()))
        ids = {nv: pg.add(nv[0], nv[1], **(meta.get(nv) or {})) for nv in seen}
        for nv in seen:
            for ch in edges.get(nv, ()):
                if ch in ids:
                    pg.edges.append((ids[nv], ids[ch]))
        for nv, scope in direct.items():
            pg.direct[ids[nv]] = scope
        r = assemble(pg)
        for c in r["components"].values():
            c.found_in = [rel]
        if r["components"]:
            results.append(r)
    return results
