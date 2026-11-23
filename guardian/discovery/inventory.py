"""Inventory: repo path -> inventory (components, graph, SBOM, matrix, gaps).
Deterministic; the Day 2 Discovery agent calls build_inventory() as a tool."""
from dataclasses import asdict
from pathlib import Path
from .lockfile import load_lockfile, build_instance_edges
from .graph import build_components
from .sbom import build_sbom
from ..models import CoverageGap

SUPPORTED = {"package-lock.json"}
KNOWN_UNSUPPORTED = {"yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "Pipfile.lock",
                     "pom.xml", "build.gradle", "go.mod", "Cargo.lock", "package.xml", "Gemfile.lock"}


def build_inventory(repo_path):
    repo = Path(repo_path)
    skip = {"node_modules", ".git"}
    files = [p for p in repo.rglob("*") if p.is_file() and not skip & set(p.relative_to(repo).parts)]
    gaps = [CoverageGap(str(p.relative_to(repo)), "unsupported_format", f"{p.name} not parsed yet")
            for p in files if p.name in KNOWN_UNSUPPORTED]
    locks = [p for p in files if p.name in SUPPORTED]
    if not locks:
        gaps.append(CoverageGap(".", "no_lockfile", "no package-lock.json found"))
        return {"components": {}, "gaps": gaps}
    lock = locks[0]   # single-project repos for now
    data = load_lockfile(lock)
    pk = data["packages"]
    edges, g1 = build_instance_edges(pk)
    root_name = data.get("name") or pk[""].get("name") or repo.name
    root_version = data.get("version") or pk[""].get("version") or "0.0.0"
    root_id, comps, adj, g2 = build_components(pk, edges, root_name, root_version)
    no_lic = sorted(c.component_id for c in comps.values() if not c.license)
    if no_lic:
        g2.append(CoverageGap(str(lock.relative_to(repo)), "missing_license",
                              f"{len(no_lic)} of {len(comps)} components have no license in the lockfile "
                              "(needs registry metadata to resolve)"))
    return {
        "repo": str(repo), "lockfile": str(lock.relative_to(repo)),
        "root": root_id, "components": comps, "adjacency": adj,
        "sbom": build_sbom(root_id, root_name, root_version, comps, adj),
        "gaps": [asdict(g) for g in gaps + g1 + g2],
        "extra_lockfiles": [str(p.relative_to(repo)) for p in locks[1:]],
    }
