"""python -m guardian.cli scan <repo_path> [--out output]"""
import argparse, json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from .discovery import build_inventory
from .matrix import write_matrix, matrix_rows
from .vulns import scan_components


def main():
    ap = argparse.ArgumentParser(prog="guardian")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("repo"); s.add_argument("--out", default="output")
    s.add_argument("--no-vulns", action="store_true", help="skip the OSV stage")
    s.add_argument("--offline", action="store_true", help="use cached OSV data only")
    a = ap.parse_args()

    inv = build_inventory(a.repo)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    comps = inv["components"]
    (out / "coverage_gaps.json").write_text(json.dumps(inv["gaps"], indent=2))
    if not comps:
        print("No supported lockfile; see coverage_gaps.json"); return
    findings = []
    if not a.no_vulns:
        findings = scan_components(comps, out / "cache" / "osv", offline=a.offline)
        findings.sort(key=lambda f: -(f["cvss"] or 0))
    (out / "findings.json").write_text(json.dumps(findings, indent=2))
    (out / "sbom.cdx.json").write_text(json.dumps(inv["sbom"], indent=2))
    nodes = [{"id": inv["root"], "type": "root"}] + [
        {"id": c.component_id, "name": c.name, "version": c.version,
         "relationship": c.relationship, "scope": c.scope, "risk_status": c.risk_status,
         "severity": c.severity, "cvss": c.cvss} for c in comps.values()]
    edges = [{"source": s, "target": t} for s, ts in inv["adjacency"].items() for t in ts]
    (out / "graph.json").write_text(json.dumps({"nodes": nodes, "edges": edges}, indent=2))
    (out / "components.json").write_text(json.dumps([asdict(c) for c in comps.values()], indent=2))
    write_matrix(matrix_rows(comps), out)

    rel, scope = Counter(c.relationship for c in comps.values()), Counter(c.scope for c in comps.values())
    print(f"Repo: {inv['repo']}  lockfile: {inv['lockfile']}")
    print(f"Components (unique name@version): {len(comps)}")
    print(f"  direct: {rel['direct']}  transitive: {rel['transitive']}")
    print(f"  prod: {scope['prod']}  dev: {scope['dev']}")
    print(f"  with install scripts: {sum(c.has_install_script for c in comps.values())}")
    print(f"  non-registry sources: {sum(1 for c in comps.values() if c.source_url and 'registry.npmjs.org' not in c.source_url)}")
    print(f"Edges: {len(edges)}  coverage gaps: {len(inv['gaps'])}")
    if findings:
        vuln = [c for c in comps.values() if c.risk_status == "vulnerable"]
        vr, vs = Counter(c.relationship for c in vuln), Counter(c.scope for c in vuln)
        sev = Counter(f["severity"] for f in findings)
        print(f"Vulnerable components: {len(vuln)}  (direct {vr['direct']}, transitive {vr['transitive']}; "
              f"prod {vs['prod']}, dev {vs['dev']})")
        print(f"Advisories (component x advisory): {len(findings)}  "
              + "  ".join(f"{k}:{sev[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if sev[k]))
    print(f"Wrote: {', '.join(sorted(p.name for p in out.iterdir()))} -> {out}/")


if __name__ == "__main__":
    main()
