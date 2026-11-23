"""npm: package-lock.json (v2/v3, full graph), yarn.lock v1 (full graph), package.json alone (declared only)."""
import json
import re

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
