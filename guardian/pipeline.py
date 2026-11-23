"""Day-1 discovery + detection pipeline (deterministic). Used by `scan` and by the Discovery agent."""
import json
from dataclasses import asdict
from pathlib import Path

from .discovery import build_inventory
from .discovery.matrix import matrix_rows, write_matrix
from .intel.detectors import run_detectors
from .intel.osv import scan_components

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def discover(repo, out, offline=False, history=20, no_vulns=False):
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    inv = build_inventory(repo)
    comps = inv["components"]
    (out / "coverage_gaps.json").write_text(json.dumps(inv["gaps"], indent=2))
    if not comps:
        return inv, comps, [], []
    findings = [] if no_vulns else scan_components(comps, out / "cache" / "osv", offline=offline)
    indicators, changes = run_detectors(repo, inv, comps, history)
    findings += indicators
    findings.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), -(f.get("cvss") or 0)))
    write_outputs(out, inv, comps, findings, changes)
    return inv, comps, findings, changes


def write_outputs(out, inv, comps, findings, changes):
    (out / "lockfile_changes.json").write_text(json.dumps(changes, indent=2))
    (out / "findings.json").write_text(json.dumps(findings, indent=2))
    (out / "sbom.cdx.json").write_text(json.dumps(inv["sbom"], indent=2))
    roots = [{"id": inv["root"], "type": "root", "name": inv["sbom"]["metadata"]["component"]["name"]}]
    roots += [{"id": p["root"], "type": "project", "name": p["name"], "ecosystem": p["ecosystem"], "manifest": p["manifest"]}
              for p in inv["projects"] if p["root"] != inv["root"]]
    nodes = roots + [
        {"id": c.component_id, "name": c.name, "version": c.version, "ecosystem": c.ecosystem,
         "relationship": c.relationship, "scope": c.scope, "risk_status": c.risk_status, "severity": c.severity,
         "cvss": c.cvss, "resolution": c.resolution} for c in comps.values()]
    edges = [{"source": s, "target": t} for s, ts in inv["adjacency"].items() for t in ts]
    (out / "graph.json").write_text(json.dumps({"nodes": nodes, "edges": edges}, indent=2))
    (out / "components.json").write_text(json.dumps([asdict(c) for c in comps.values()], indent=2))
    write_matrix(matrix_rows(comps), out)
    (out / "inventory.json").write_text(json.dumps({k: inv[k] for k in ("repo", "root", "projects", "ecosystems")}, indent=2))
