# Software Supply Chain Guardian

Agentic AI platform for software supply-chain security analysis (hackathon prototype).

Day 1 status: **discovery and dependency matrix**. A deterministic pipeline that turns a repository's
`package-lock.json` into a Dependency Matrix, CycloneDX SBOM, dependency graph and OSV-backed
vulnerability findings with evidence. The Day 2 agents will call it as a tool.

See [GUARDIAN_PLAN.md](GUARDIAN_PLAN.md) for the full architecture and plan.

## Requirements

- Python 3.10+ (standard library only, nothing to install)
- Network access to `api.osv.dev` for the first scan (later scans can run with `--offline`)

## Quick start

```bash
# sample target (intentionally vulnerable app); hooks disabled for safety
git -c core.hooksPath=/dev/null clone --depth 50 https://github.com/OWASP/NodeGoat.git targets/NodeGoat

python3 -m guardian.cli scan targets/NodeGoat            # live OSV lookups, cached to output/cache/osv
python3 -m guardian.cli scan targets/NodeGoat --offline  # cache only (demo mode)
python3 -m guardian.cli scan targets/NodeGoat --no-vulns # inventory only
```

## Outputs (`output/`)

| File | Contents |
|---|---|
| `matrix.csv` / `matrix.json` | Dependency Matrix: one row per unique `name@version` with ID (purl), ecosystem, direct/transitive, prod/dev, parent, full dependency path, source, license, advisory IDs, CVSS, severity, affected range, fixed version, risk status |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM with hashes, sources and the dependency tree |
| `graph.json` | Nodes and edges for visualisation |
| `findings.json` | One record per component × advisory, with CVSS vector, range, fix, dependency path and evidence (cached OSV record path + SHA-256) |
| `components.json` | Full component records |
| `coverage_gaps.json` | What could not be resolved and why |

## Code layout

| Module | Role |
|---|---|
| `guardian/lockfile.py` | Parse `package-lock.json` v2/v3; resolve each dependency the way Node does |
| `guardian/graph.py` | Collapse to unique components; direct/transitive, prod/dev, shortest paths |
| `guardian/sbom.py` | CycloneDX SBOM |
| `guardian/matrix.py` | Dependency Matrix CSV/JSON |
| `guardian/vulns.py` | OSV lookups, CVSS v3 scoring, affected range and fixed version |
| `guardian/discovery.py` | `build_inventory(repo_path)`: entry point the Discovery agent will call |
| `guardian/cli.py` | `scan` command |

## Known limitations

- Only npm `package-lock.json` (v2/v3) is parsed; other manifests are reported as coverage gaps.
- Many lockfiles omit licenses (706 of 1,091 components for NodeGoat); reported as a coverage gap.
- Vulnerabilities come from OSV only. Advisories without a CVSS v3 vector use the advisory's own severity label.
- Fixed versions come from OSV and are not yet checked for availability or compatibility.

## Safety

Target repositories are cloned with git hooks disabled and are never executed on the host.
Anything that installs or runs target code happens in Docker only.
