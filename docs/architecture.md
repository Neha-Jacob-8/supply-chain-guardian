# Architecture

![Architecture overview](architecture.svg)

Software Supply Chain Guardian takes a repository from discovery to independently validated remediation.
Deterministic tools produce all evidence and all numbers; LLM agents investigate, prioritise and choose
among computed fixes; a human approves; an independent validator decides whether a fix worked.

## 1. System overview (flowchart)

```mermaid
flowchart LR
  User([User / Dashboard]) -->|REST| API[guardian serve<br/>FastAPI]
  CLI([guardian CLI]) --> ORCH
  API --> ORCH{{Guardian Orchestrator<br/>state machine}}
  ORCH <--> STATE[(RunState<br/>output/run_state.json)]
  ORCH --> AUDIT[(Audit trail<br/>output/events.jsonl)]
  ORCH --> ING[Ingestion<br/>safe clone]
  ING --> GH[(GitHub public repo)]
  ORCH --> DISC[Discovery + Detection<br/>deterministic]
  DISC --> OSV[(OSV API)]
  DISC --> INTEL[(CISA KEV, FIRST EPSS)]
  ORCH --> AGENTS[Attack / Risk / Defense agents]
  AGENTS -.->|tool use| LLM[[LLM providers<br/>Gemini keys x models, Claude,<br/>rule-based fallback]]
  AGENTS --> TOOLS[Read-only tools]
  TOOLS --> REG[(npm registry)]
  TOOLS --> EVID[(Evidence store<br/>output/evidence/EV-*.json)]
  AGENTS --> GATE{{Human approval}}
  GATE --> VAL[Validation agent<br/>deterministic]
  VAL --> POLICY{{Trusted profile + Compose policy}}
  POLICY --> DOCKER[[Docker sandbox]]
  ORCH --> REP[(Guardian Report<br/>report.md + report.json)]
```

## 2. Agentic workflow

```mermaid
flowchart TB
  START([repo URL or path]) --> D[1 Discovery<br/>inventory, SBOM, matrix,<br/>OSV, detectors, risk scores,<br/>fix candidates]
  D -->|no lockfile| GAP[stop: coverage gap reported]
  D --> Q{suspicious indicators<br/>score >= 40?}
  Q -->|yes| A[2 Attack agent<br/>Red Team, read-only]
  Q -->|no| R
  A --> R[3 Risk agent<br/>prioritise + explain]
  R --> B[4 Defense agent<br/>Blue Team: pick candidates]
  B --> H{{Human approval}}
  H -->|nothing approved| PAUSE[pause: report with pending proposals]
  H -->|approved| V[5 Validation agent<br/>independent]
  V -->|verified / partial| REP[Guardian Report]
  V -->|failed| O{Orchestrator:<br/>alternative candidate?}
  O -->|yes| H
  O -->|no| ESC[escalate to human]
  ESC --> REP
```

| Agent | Kind | Tools | Output | Cannot |
|---|---|---|---|---|
| Orchestrator | code (state machine) | all stages | stage transitions, decisions, retries | — |
| Discovery | deterministic pipeline | lockfile parser, OSV, detectors, risk formula, candidate generator | inventory, findings, scores, candidates | — |
| Attack (Red Team) | LLM agent | `get_finding`, `get_component`, `npm_registry_metadata`, `git_commit_info`, `read_file`, `check_import_usage`, `list_findings` | investigations: hypothesis, attack path, verified facts vs inferences, verdict | write anything, execute code |
| Risk Analysis | LLM agent | `get_finding`, `get_component`, `check_import_usage`, `list_findings`, `read_file` | ranked priorities with rationale | change a score |
| Defense (Blue Team) | LLM agent | `get_fix_options`, `get_finding`, `get_component`, `check_import_usage`, `read_file` | proposals (candidate ids), escalations | invent a fix, apply a fix, declare success |
| Validation | deterministic | identity-bound patch, independent rescan, allowlisted Docker profile, unit/HTTP checks | verdict per fix | never executes an untrusted repository runtime |

Every agent has a labelled rule-based fallback, so the pipeline completes without an API key.

## 3. Discovery and detection pipeline

```mermaid
flowchart TD
  A[all manifests and lockfiles<br/>npm, PyPI, Go, Cargo, RubyGems,<br/>Packagist, Maven, ROS, git] --> B[per-ecosystem parsers<br/>parent -> child edges]
  B --> C[unique name@version components<br/>direct/transitive, prod/dev, shortest path]
  C --> D[CycloneDX 1.5 SBOM]
  C --> E[Dependency Matrix CSV/JSON]
  C --> F[graph.json]
  C --> G[OSV querybatch + vuln records<br/>CVSS, range, fixed version]
  A --> H[Detectors SC1-SC7, MT1]
  REPO[Dockerfile, compose, workflows] --> I[Detectors CT1-CT5, CI1-CI4]
  GIT[git history of lockfile] --> H
  G --> S[Risk formula<br/>CVSS, KEV/EPSS, exposure, reachability]
  H --> S
  I --> S
  S --> X[Fix candidates<br/>upgrade, override, lockfile restore,<br/>SHA pin, base image]
```

## 4. Red Team investigation

```mermaid
flowchart TD
  A[indicators scored >= 40] --> B[plan next check]
  B --> C[read-only tool call]
  C --> E[(evidence EV-id stored)]
  E --> D{enough evidence?}
  D -->|no, budget left| B
  D -->|yes| F[hypothesis + attack path]
  F --> G[submit_result]
  G --> H{citation check:<br/>ids exist? advisories real?}
  H -->|rejected| B
  H -->|accepted| I[investigation stored]
```

## 5. Blue Team remediation

```mermaid
flowchart TD
  P[priorities] --> O[get_fix_options per priority]
  O --> C{candidate exists?}
  C -->|no| E[escalation for a human]
  C -->|yes| S[choose lowest change risk<br/>that closes the issue]
  S --> V{candidate_id valid?}
  V -->|no| X[dropped + logged]
  V -->|yes| R[proposal: rationale, compat, rollback,<br/>expected reduction = prediction]
  R --> H{{human approval}}
```

## 6. Validation

```mermaid
flowchart TD
  A[approved candidate] --> B[copy repo, bind identity + diff hashes<br/>refuse if files drifted]
  B --> C{package.json changed?}
  C -->|yes| D[Docker node:22: npm install<br/>--package-lock-only --ignore-scripts]
  C -->|no| E
  D --> E[rescan patched tree]
  E --> F[compare with validator's own baseline rescan<br/>resolved / remaining / introduced / SBOM diff]
  F --> G{trusted profile?}
  G -->|no| P[static-only evidence]
  G -->|yes| H[policy-check Compose, build + boot + unit command]
  H --> I[smoke: GET /login, POST /login -> /dashboard]
  P --> J{verdict}
  I --> J{verdict}
  J -->|all targets resolved, runtime evidence,<br/>no new high/critical| V[verified]
  J -->|static-only, targets remain,<br/>or new high/critical| P2[partial]
  J -->|fix breaks a working app| X[failed -> orchestrator re-plans]
```

## Evidence and approval points

- **Evidence**: OSV records (`output/cache/osv/*.json`, SHA-256 in each finding), file/line/commit excerpts for
  indicators, and every agent tool call (`output/evidence/EV-*.json`). Agents may only cite these ids.
- **Approval**: the orchestrator stops at `awaiting_approval`; `guardian approve` or
  `POST /api/proposals/{id}/approval` records the decision with time, reviewer, repository identity, exact diff
  hash, and base-file hashes in the audit trail. Resume refuses stale approvals.
- **Audit trail**: `output/events.jsonl` records every stage, decision, LLM step, tool call, rejected
  submission, approval and verdict.

## Code map

| Concern | Module |
|---|---|
| Ingestion | `guardian/ingestion.py` |
| Discovery | `guardian/discovery/` |
| Vulnerabilities, detectors, risk, registry | `guardian/intel/` |
| Fix candidates | `guardian/remediation/` |
| Agents, tools, state, orchestrator | `guardian/agents/` (prompts in `agents/prompts/`) |
| Validation | `guardian/validation/` |
| Report | `guardian/reporting/` |
| Policies (weights, EOL dates) | `guardian/policies/` |
| Ecosystem parsers | `guardian/discovery/ecosystems/` |
| API / CLI / web UI | `guardian/api.py`, `guardian/cli.py`, `guardian/web/` |
