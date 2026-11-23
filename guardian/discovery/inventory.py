"""Inventory: repo path -> components, dependency network, SBOM and coverage gaps, across all ecosystems.
Deterministic; the Discovery stage calls build_inventory() as a tool."""
from pathlib import Path

from ..models import CoverageGap
from .ecosystems import discover_projects
from .sbom import build_sbom


def _merge(a, b):
    """Same package used by two projects: keep the strongest classification and the shortest path."""
    a.relationship = "direct" if "direct" in (a.relationship, b.relationship) else a.relationship
    if b.scope == "prod" and a.scope != "prod":
        a.scope, a.path = "prod", b.path
    elif b.scope == a.scope and len(b.path) < len(a.path):
        a.path = b.path
    for attr in ("parents", "found_in", "projects"):
        setattr(a, attr, sorted(set(getattr(a, attr)) | set(getattr(b, attr))))
    for attr in ("source_url", "integrity", "license"):
        setattr(a, attr, getattr(a, attr) or getattr(b, attr))
    a.has_install_script = a.has_install_script or b.has_install_script


def build_inventory(repo_path):
    repo = Path(repo_path)
    results, gaps = discover_projects(repo)
    comps, adj = {}, {}
    for r in results:
        gaps += r["gaps"]
        for cid, c in r["components"].items():
            if cid in comps:
                _merge(comps[cid], c)
            else:
                comps[cid] = c
        for k, v in r["adjacency"].items():
            adj.setdefault(k, set()).update(v)
    projects = [{k: r[k] for k in ("root", "name", "version", "ecosystem", "manifest")} | {"components": len(r["components"])}
                for r in results]
    if not results:
        gaps.append(CoverageGap(".", "no_lockfile", "no supported manifest or lockfile found"))
    if len(results) == 1:
        root = results[0]["root"]
    else:
        root = f"repo:{repo.name}"
        adj[root] = {p["root"] for p in projects}
    no_lic = [c for c in comps.values() if not c.license and c.ecosystem in ("npm", "cargo", "composer")]
    if no_lic:
        gaps.append(CoverageGap(".", "missing_license", f"{len(no_lic)} of {len(comps)} components have no license "
                                                        "in their lockfile (needs registry metadata to resolve)"))
    adj = {k: sorted(v) for k, v in adj.items()}
    npm_locks = [p["manifest"] for p in projects if p["ecosystem"] == "npm" and p["manifest"].endswith(
        ("package-lock.json", "npm-shrinkwrap.json"))]
    return {
        "repo": str(repo), "root": root, "projects": projects,
        "lockfile": npm_locks[0] if npm_locks else None, "npm_lockfiles": npm_locks,
        "ecosystems": sorted({p["ecosystem"] for p in projects}),
        "components": comps, "adjacency": adj,
        "sbom": build_sbom(root, repo.name, projects, comps, adj),
        "gaps": [g.__dict__ for g in gaps],
    }
