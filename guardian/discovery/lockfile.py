"""Part 1+2: read package-lock.json (v2/v3) and build instance-level edges."""
import json
from pathlib import Path
from ..models import CoverageGap

NM = "node_modules/"


def pkg_name(key: str) -> str:
    """'node_modules/a/node_modules/@s/b' -> '@s/b'"""
    return key[key.rfind(NM) + len(NM):]


def make_purl(name: str, version: str) -> str:
    n = name.replace("@", "%40", 1) if name.startswith("@") else name
    return f"pkg:npm/{n}@{version}"


def load_lockfile(path):
    data = json.loads(Path(path).read_text())
    if "packages" not in data:
        raise ValueError(f"lockfileVersion {data.get('lockfileVersion')} has no 'packages' map (need v2/v3)")
    return data


def resolve(from_key: str, name: str, packages: dict):
    """Node resolution: look in <from>/node_modules, then each ancestor's node_modules."""
    base = from_key
    while True:
        cand = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if cand in packages:
            return cand
        if not base:
            return None
        i = base.rfind("/node_modules/")
        base = base[:i] if i != -1 else ""


def build_instance_edges(packages: dict):
    """Returns ({parent_key: [child_key]}, [CoverageGap]). Root key is ''."""
    edges, gaps = {}, []
    for key, p in packages.items():
        required = {**p.get("dependencies", {})}
        optional = {**p.get("optionalDependencies", {}), **p.get("peerDependencies", {})}
        if key == "":
            required.update(p.get("devDependencies", {}))
        children = []
        for name in required:
            child = resolve(key, name, packages)
            if child is None:
                gaps.append(CoverageGap(key or "(root)", "unresolved_dependency",
                                        f"'{name}' is required but not found in lockfile"))
            else:
                children.append(child)
        for name in optional:  # optional/peer deps may legitimately be absent
            child = resolve(key, name, packages)
            if child is not None:
                children.append(child)
        edges[key] = children
    return edges, gaps
