# Hackathon requirements and acceptance map

This document separates organizer instructions from implementation choices. The organizer requirements are
derived from the problem statement and the day-1/day-2 briefing transcript supplied with this project. The
implementation links below describe what can be demonstrated from this repository, not promises about an
external production deployment.

## Source interpretation

The brief's central objective is: know what is built, understand what can be trusted, prioritize risk in the
application context, recommend a safe change, validate it, and give a developer an actionable report. The brief
also explicitly asks for a working agentic prototype, architecture/orchestration explanation, open-source tool
choices, live demonstration, a guardian report, human involvement, and isolated experimentation.

The non-negotiable safety boundaries are: use an owned/public example application, do not attack production,
do not access private infrastructure without authorization, do not expose credentials, do not publish malicious
packages, and document the application, changes, and tools.

## Day 1 acceptance matrix

| Organizer expectation | Implementation | Evidence to show |
|---|---|---|
| Discover all relevant components | `guardian/discovery/` parses npm, pnpm, Yarn, Python, Go, Cargo, Ruby, PHP, Maven, ROS, and git dependency inputs; monorepos are merged into one inventory | `inventory.json`, `components.json`, dashboard overview |
| Distinguish direct/transitive and prod/dev | Graph assembly computes relationship, scope, shortest path, and project ownership | `matrix.csv`, matrix filters, component detail |
| Build dependency chain/graph | CycloneDX 1.5 SBOM plus `graph.json` with repository → project → package nodes and parent/child edges | dashboard dependency graph, `sbom.cdx.json` |
| Correlate trusted vulnerability information | Exact versions are queried against OSV; CVSS vectors/ranges/fixed versions are recorded; GHSA severity is used only as a documented fallback | `findings.json` vulnerability entries, OSV evidence URL |
| Detect non-CVE supply-chain indicators | Deterministic SC1–SC7, MT1, CT1–CT5, and CI1–CI4 detectors cover tampering, off-registry/moving refs, install scripts, floating specs, lockfile disagreement, unexpected additions/major jumps, maintenance, containers, and CI | `findings.json`, detector rule IDs, file/line/commit evidence |
| Present evidence, not generic prose | Every finding has evidence class and structured file/line/commit or OSV evidence; agent tool outputs are stored as hashed `EV-*` records | `evidence/`, `events.jsonl`, dashboard evidence drawer |
| Use genuine agent orchestration | Attack, Risk, and Defense agents have separate prompts, tools, schemas, budgets, hand-offs, and labelled fallbacks; the orchestrator owns stage transitions | `docs/architecture.md`, stage timeline, `run_state.json` |

## Day 2 acceptance matrix

| Organizer expectation | Implementation | Evidence to show |
|---|---|---|
| Prioritize in application context, not CVSS alone | Formula combines CVSS/severity, CISA KEV, EPSS, production exposure, package reachability/import usage, and directness; each factor is shown | priority rationale and risk factor breakdown |
| Explain suspicious changes | Red Team investigates high-scoring indicators and separates verified facts from inference; citations must resolve to stored evidence | investigation card and evidence IDs |
| Recommend safe remediation | Blue Team can select only deterministic candidates: exact file diff, fixed-version/provenance checks, compatibility notes, prerequisites, and rollback; unsupported fixes escalate | proposal table and diff view |
| Include a human in the loop | Pipeline pauses at `awaiting_approval`; CLI and dashboard/API record reviewer, timestamp, repository identity, diff hash, and base-file hashes | approval record in `run_state.json` and `events.jsonl` |
| Experiment safely | Generic repositories never run arbitrary Dockerfiles/Compose. Runtime execution requires an allowlisted profile and trusted remote identity; Compose host escapes are rejected; target code runs only in Docker | `guardian/validation/sandbox.py`, policy rejection test |
| Rebuild and test after a change | Approved patches are applied to a fresh copy; npm lockfiles regenerate in non-root `node:22-alpine` with `--ignore-scripts`; trusted profiles run declared unit commands and HTTP smoke checks | validation steps in `report.json` |
| Rescan after remediation | Validator independently rescans baseline and patched trees, reports resolved/remaining/introduced findings and SBOM component deltas | validation comparison in `report.json` and report.md |
| Give a complete developer report | Machine report includes identity, inventory, full components, full findings, priorities, investigations, proposals/approvals, validations, remaining/resolved risk, evidence index, cache mode, and coverage gaps | `report.json` + `report.md` |

## Demonstration target

OWASP NodeGoat is the documented public demonstration target. Its remote identity is explicitly allowlisted only
for the NodeGoat runtime profile. A different repository with a similar project name receives static-only
validation unless a new trusted profile is deliberately added and reviewed.

The baseline scan reproduced locally after the implementation changes:

- 1,091 unique components: 36 direct, 1,055 transitive; 380 production, 711 development.
- 313 OSV vulnerability findings across 131 vulnerable components.
- 68 deterministic supply-chain indicators, including the added history rules SC6 and SC7.
- 40 computed fix candidates; the rule-based Defense agent selected 8 patch proposals and routed 2 issues to escalation.

Counts are a scan snapshot. OSV, EPSS, KEV, registry data, repository history, and cache freshness can change the
numbers; use the generated report from the run being presented.

## Explicit non-goals and honest limitations

- Reachability is package/import-level, not function-level exploitability.
- Indicators are risk signals and evidence-backed hypotheses, not proof of compromise.
- Automatic patches cover selected npm and pinned Python cases; other ecosystems receive exact manual guidance.
- Runtime verification is stronger than static validation only when a trusted profile runs successfully. Static-only
  validation is deliberately reported as `partial`, never `verified`.
- No code is merged, pushed, deployed, or released automatically.
