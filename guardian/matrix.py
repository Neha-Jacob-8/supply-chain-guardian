"""Part 5: Dependency Matrix (one row per unique component)."""
import csv, json

COLUMNS = ["component_id", "name", "version", "ecosystem", "relationship", "scope",
           "parent", "dependency_path", "source", "license", "has_install_script",
           "advisory_ids", "cvss", "severity", "affected_range", "fixed_version", "risk_status"]


def _short(cid):
    return cid.split("pkg:npm/", 1)[-1].replace("%40", "@")


def matrix_rows(comps):
    rows = []
    for c in sorted(comps.values(), key=lambda c: (c.relationship != "direct", c.name, c.version)):
        rows.append({
            "component_id": c.component_id, "name": c.name, "version": c.version,
            "ecosystem": c.ecosystem, "relationship": c.relationship, "scope": c.scope,
            "parent": _short(c.path[-2]) if len(c.path) > 1 else "",
            "dependency_path": " > ".join(_short(x) for x in c.path),
            "source": c.source_url or "", "license": c.license or "",
            "has_install_script": c.has_install_script,
            "advisory_ids": ";".join(c.advisory_ids), "cvss": c.cvss if c.cvss is not None else "",
            "severity": c.severity or "",
            "affected_range": c.affected_range or "", "fixed_version": c.fixed_version or "",
            "risk_status": c.risk_status,
        })
    return rows


def write_matrix(rows, out_dir):
    with open(out_dir / "matrix.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS); w.writeheader(); w.writerows(rows)
    (out_dir / "matrix.json").write_text(json.dumps(rows, indent=2))
