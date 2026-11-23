# Software Supply Chain Guardian

Agentic AI platform for software supply-chain security analysis (hackathon prototype).

Day 1 status: **discovery, dependency matrix and detection**. A deterministic pipeline that turns a
repository into a Dependency Matrix, CycloneDX SBOM, dependency graph, OSV-backed vulnerability findings
and non-CVE supply-chain indicators (lockfile tampering, untrusted sources, containers, CI/CD), each with
evidence. The Day 2 agents will call it as a tool.

Docs: [architecture](docs/architecture.md) (all six flowcharts) · [Responsible AI & security note](docs/responsible-ai.md) · [demo script](docs/demo.md) · [original plan](docs/original-plan.md)

## Agentic pipeline (Day 2)

```
Guardian Orchestrator (state machine, shared RunState, audit trail in output/events.jsonl)
  1 Discovery     deterministic tools: inventory, SBOM, matrix, OSV, detectors, risk scores, fix candidates
  2 Attack agent  Red Team: read-only investigation of suspicious indicators (registry + git + file evidence)
  3 Risk agent    prioritises using the formula scores + investigations; explains, never re-scores
  4 Defense agent Blue Team: chooses among deterministic fix candidates; cannot invent fixes
    Human approval gate: nothing is applied without it
  5 Validation    independent, deterministic: apply in a copy, rebuild lockfile in Docker, rescan,
                  boot + login smoke test, compare with its own baseline -> verified / partial / failed
    Orchestrator re-plans when a fix fails (proposes an alternative, which again needs approval)
  Guardian Security Report: output/report.md + output/report.json
```

```bash
guardian run targets/NodeGoat                 # stops at the approval gate
guardian approve --ids FIX-...,FIX-...        # human decision (or --ids low / all, --reject)
guardian resume targets/NodeGoat              # independent validation + report
# options: --llm auto|claude|none   --approve low|all|none|<ids>   --no-smoke   --offline
```

Guardrails enforced in code: agents only have read-only tools; every tool call is stored as evidence
(`output/evidence/EV-*.json`); a submitted result is rejected unless every cited finding/evidence id exists and
every CVE/GHSA it mentions was reported by OSV (the agent gets the rejection and must correct itself); risk scores
come from `guardian/risk.py`, never from the LLM; the Defense agent can only pick candidate ids from
`guardian/remediation.py`; only the Validation step produces verdicts. LLM: `claude-opus-5-5` (override with
`GUARDIAN_MODEL`).

## Dashboard

Static dashboard in `frontend/` (overview, Dependency Matrix, graph, findings with evidence, lockfile history,
coverage gaps). It reads the files in `output/`:

```bash
guardian scan targets/NodeGoat          # or `guardian run ...`
python3 -m http.server 8000             # from the repo root
# open http://localhost:8000/frontend/
```

## Dashboard API

```bash
guardian serve --port 8000        # http://127.0.0.1:8000/docs for interactive API docs
```

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status`, `/api/overview` | run stage, counts |
| GET | `/api/matrix`, `/api/graph`, `/api/sbom` | Dependency Matrix (filters: `risk_status`, `scope`, `q`), graph, CycloneDX |
| GET | `/api/findings`, `/api/findings/{id}` | findings with `risk` breakdown (filters: `category`, `severity`, `rule_id`, `component`) |
| GET | `/api/investigations`, `/api/priorities`, `/api/proposals[/{id}]`, `/api/validations`, `/api/escalations` | agent outputs |
| GET | `/api/evidence/{EV-id}`, `/api/events?since=`, `/api/coverage`, `/api/changes` | evidence, audit trail, gaps, lockfile history |
| GET | `/api/report.md`, `/api/report.json` | Guardian Security Report |
| POST | `/api/runs` `{"target": "<path or GitHub URL>", "llm": "auto"}` | start a run (background) |
| POST | `/api/proposals/{id}/approval` `{"decision": "approve"}` | human approval |
| POST | `/api/resume` | validate approved fixes + report |

## Requirements

- Python 3.10+ (Day 1 pipeline: standard library only; LLM agents: `anthropic` SDK)
- Docker (validation only)
- Network access to `api.osv.dev` for the first scan (later scans can run with `--offline`)

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all]"          # [llm] Claude agents, [api] dashboard server; `pip install -e .` = stdlib-only pipeline
export ANTHROPIC_API_KEY=...     # optional: enables Claude agents; otherwise agents use labelled rule-based fallbacks
```

## Quick start

```bash
# GitHub URLs are cloned safely into targets/ (hooks disabled, no submodules); local paths also work
guardian scan https://github.com/OWASP/NodeGoat

guardian scan targets/NodeGoat            # live OSV lookups, cached to output/cache/osv
guardian scan targets/NodeGoat --offline  # cache only (demo mode)
guardian scan targets/NodeGoat --no-vulns # skip OSV
guardian scan targets/NodeGoat --history 0 # skip lockfile git history
```

### "What changed" demo

`scripts/seed_demo.py` creates a **local** branch `guardian-demo` in the target clone with one commit that
simulates a lockfile tamper (express's integrity hash replaced at the same version; body-parser pointed at a
`.example` mirror that cannot resolve). Nothing is pushed.

```bash
python3 scripts/seed_demo.py targets/NodeGoat     # creates and checks out guardian-demo
guardian scan targets/NodeGoat --offline
git -C targets/NodeGoat checkout master           # back to the original
```

### Tests

```bash
python -m unittest discover -s tests -t .
```

## Outputs (`output/`)

| File | Contents |
|---|---|
| `matrix.csv` / `matrix.json` | Dependency Matrix: one row per unique `name@version` with ID (purl), ecosystem, direct/transitive, prod/dev, parent, full dependency path, source, license, advisory IDs, CVSS, severity, affected range, fixed version, risk status |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM with hashes, sources and the dependency tree |
| `graph.json` | Nodes and edges for visualisation |
| `findings.json` | All findings. Vulnerabilities (`evidence_class: verified`): one per component × advisory with CVSS vector, range, fix, path and the cached OSV record + SHA-256. Indicators (`evidence_class: indicator`): rule ID, file/line or commit, excerpt, SHA-256 and recommendation |
| `lockfile_changes.json` | Per-commit lockfile change summary (added / removed / version changes / hash-algorithm upgrades) |
| `components.json` | Full component records |
| `coverage_gaps.json` | What could not be resolved and why |

## Package layout

```
guardian/
  cli.py, __main__.py        `guardian` command (scan | run | approve | resume)
  models.py                  shared data model (Component, CoverageGap)
  pipeline.py                Day 1 discovery + detection pipeline (used by `scan` and the Discovery stage)
  discovery/                 lockfile.py (npm lockfile, Node-style resolution), graph.py (paths, scope),
                             sbom.py (CycloneDX 1.5), matrix.py (Dependency Matrix), inventory.py (build_inventory)
  ingestion.py               validate GitHub URL + safe clone
  api.py                     FastAPI dashboard server (`guardian serve`)
  intel/                     osv.py (OSV + CVSS), detectors.py (SC/MT/CT/CI rules), risk.py (scoring, KEV/EPSS,
                             reachability), registry.py (npm registry metadata, git ref -> SHA)
  remediation/               candidates.py: deterministic fix candidates with diffs, compat notes, rollback
  validation/                sandbox.py: apply in a copy, Docker lockfile regen, rescan, boot + login smoke test
  reporting/                 report.py: report.json + report.md
  agents/                    orchestrator.py, base.py (agent loop + citation guardrail), llm.py (Claude / scripted),
                             state.py (RunState + evidence store), tools.py (read-only agent tools),
                             attack.py, risk_analyst.py, defense.py, common.py
  agents/prompts/*.md        agent system prompts (package data)
  policies/*.json            rule weights and end-of-life dates (package data, editable without code changes)
scripts/seed_demo.py         local "what changed" tamper demo
tests/                       unit tests (no network, no API key needed)
```

## Known limitations

- Only npm `package-lock.json` (v2/v3) is parsed; other manifests are reported as coverage gaps.
- Many lockfiles omit licenses (706 of 1,091 components for NodeGoat); reported as a coverage gap.
- Vulnerabilities come from OSV only. Advisories without a CVSS v3 vector use the advisory's own severity label.
- Fixed versions come from OSV and are not yet checked for availability or compatibility.
- Indicators are heuristics, not proof of compromise. SC1 compares hashes of the same algorithm only, so npm's
  sha1 to sha512 re-records are logged as benign changes, not findings.
- The end-of-life table in `detectors.py` is a static snapshot and needs refreshing.
- No typosquatting or dependency-confusion detection yet.

## Safety

Target repositories are cloned with git hooks disabled and are never executed on the host.
Anything that installs or runs target code happens in Docker only.
