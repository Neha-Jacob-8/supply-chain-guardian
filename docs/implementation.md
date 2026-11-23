# Implementation

How Software Supply Chain Guardian is built: components, data flow, agents, guardrails and test results.
For the picture see [architecture.svg](architecture.svg); for flowcharts see [architecture.md](architecture.md).

## 1. Technology

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | `tomllib`, typing; core uses the standard library plus PyYAML (pnpm only) |
| Vulnerability data | OSV.dev (`querybatch` + records), GHSA severity fallback | one source covering npm, PyPI, Go, crates.io, RubyGems, Packagist, Maven |
| Exploit intelligence | CISA KEV, FIRST EPSS | exploitability factor in the risk score |
| SBOM | CycloneDX 1.5 JSON (written directly) | standard, machine-readable |
| LLM | Gemini (REST, key + model fallback), Claude (Anthropic SDK, optional) | tool-use agents; provider chain with rule-based fallback |
| API | FastAPI + uvicorn | dashboard backend, background jobs |
| UI | static HTML/CSS/JS + force-graph (canvas) | no build step; served by the API |
| Sandbox | Docker (`node:22-alpine`, docker compose) | target code never runs on the host |
| CI | GitHub Actions (SHA-pinned actions, read-only token) | passes the Guardian's own CI rules |

## 2. Data flow

```
GitHub URL ─► ingestion (clone) ─► discovery (parsers → network) ─► OSV + detectors ─► risk scores ─► fix candidates
           ─► Attack agent ─► Risk agent ─► Defense agent ─► approval gate ─► Validation ─► report
```

All stages read and write one `RunState` through the orchestrator; every step is appended to `events.jsonl`.

## 3. Discovery (`guardian/discovery/`)

- `ecosystems/__init__.py` lists repository files with `git ls-files` (so `.gitignore`d folders are never scanned),
  skips fixtures/vendored code, applies precedence (a lockfile beats its manifest in the same folder) and parses
  each manifest with its ecosystem parser. One broken manifest becomes a coverage gap, not a failed scan.
- Parsers (`npm.py`, `python.py`, `others.py`) return a common `ProjectGraph`: packages keyed by purl, parent→child
  edges, direct dependencies with prod/dev scope. `base.assemble` computes direct/transitive, scope and the
  shortest dependency path (prod paths preferred for prod packages).
- `inventory.py` merges projects into one network (repo root → project roots → packages), keeps the strongest
  classification for packages shared by several projects, and builds the SBOM.
- npm lockfiles use Node's own resolution (nested `node_modules` first, then ancestors); pnpm builds one project per
  workspace importer containing only the packages it reaches.

## 4. Detection and scoring (`guardian/intel/`)

**Vulnerabilities** (`osv.py`): batched OSV queries for exact versions in OSV-covered ecosystems; records cached on
disk with SHA-256 (offline replay); CVSS v3 base score computed from the vector; affected range and fixed version
from the matching OSV range; severity from the GHSA alias when the native record has none.

**Indicators** (`detectors.py`), all deterministic with file/line/commit evidence:

| Rule | Detects |
|---|---|
| SC1 | lockfile integrity changed without a version change (git history; same hash algorithm only) |
| SC2 | dependency resolved outside the registry, or a git dependency on a moving branch |
| SC3 | packages that run install scripts (current and newly added) |
| SC4 | floating specs: `latest`, `*`, URL/git refs, unpinned Python requirements |
| SC5 | npm v2 lockfile sections disagree (npm ≤6 and ≥7 would install different code) |
| MT1 | packages deprecated by their maintainer |
| CT1–CT5 | image not digest-pinned, end-of-life runtime, root user, remote script piped to shell, `npm install` instead of `npm ci` |
| CI1–CI4 | actions not pinned to a SHA, missing `permissions:`, `pull_request_target`, untrusted event data in `run:` |

**Risk** (`risk.py`), 0–100, with a factor breakdown and confidence:
`40·CVSS/10 + (25 if in CISA KEV else 15·EPSS) + (15 prod / 3 dev) + reachability (15 direct & imported, 8 under an
imported direct dependency) + 5 if direct`. Indicators use rule weights from `policies/risk_weights.json`.
Reachability scans application code for imports (npm, Python, Go, Rust, Ruby); other ecosystems are marked
"not analysed", which lowers confidence instead of scoring zero.

## 5. Remediation candidates (`guardian/remediation/`)

Deterministic candidates with exact file diffs, compatibility notes and rollback: direct upgrades to the fixed
version (npm `package.json` per project, pinned `requirements.txt`), npm `overrides` for vulnerable transitive
packages, lockfile restore from official registry values (tamper fix), GitHub Actions pinned to resolved SHAs plus a
read-only `permissions:` block, supported base images. Fixed versions are checked against the registry. Ecosystems
without automatic patching get a manual instruction that is routed to human escalation.

## 6. Agents (`guardian/agents/`)

| Agent | Tools (read-only) | Produces |
|---|---|---|
| Attack (Red Team) | `get_finding`, `get_component`, `npm_registry_metadata`, `git_commit_info`, `read_file`, `check_import_usage`, `list_findings` | investigations: hypothesis, attack path, verified facts (with evidence ids), inferences, verdict, confidence |
| Risk analysis | `get_finding`, `get_component`, `check_import_usage`, `list_findings`, `read_file` | top-10 priorities with rationale and recommendation |
| Defense (Blue Team) | `get_fix_options`, `get_finding`, `get_component`, `check_import_usage`, `read_file` | proposals (candidate ids), escalations |

**Loop** (`base.py`): the model calls tools; each result is stored as evidence `EV-…` and returned with its id; the
agent finishes by calling `submit_result`. **Guardrails enforced in code:** the result must match its JSON schema;
every cited finding/evidence id must exist; every CVE/GHSA mentioned must have been reported by OSV; violations are
sent back as tool errors so the model corrects itself; a step budget bounds every run; file excerpts are
secret-redacted. The Defense agent can only return candidate ids produced by `remediation/`.

**Providers** (`llm.py`, `gemini.py`): a provider chain (Claude if configured, then Gemini). The Gemini backend walks
keys × models with per-error handling (invalid key → drop, 404 → skip model, 429 → next, 5xx → retry once). If a
provider fails, the agent restarts on the next one; if all fail, it runs a labelled rule-based fallback.

**Orchestrator** (`orchestrator.py`): stage machine, write permissions (only Validation produces verdicts),
re-planning when a fix fails validation (an alternative candidate, which again needs approval), routing of
patch-less fixes to escalation, and `resume` after human approval.

## 7. Validation (`guardian/validation/sandbox.py`)

Per approved fix: copy the repository, apply the diff (refusing if files drifted), regenerate the npm lockfile in
`node:22-alpine` with `--ignore-scripts`, rescan with the same tools, compare with the validator's own baseline
rescan (resolved / remaining / newly introduced findings, SBOM diff), then run the runtime check: a smoke profile
from `policies/smoke_profiles.json` (NodeGoat: boot with MongoDB, `GET /login`, `POST /login` → `/dashboard`), else a
`docker build`, else static only. Verdict: **verified** (targets resolved, app works, no new high/critical),
**partial**, or **failed** (the fix broke a working app). A baseline run proves the runtime check passes before any fix.

## 8. Interfaces

- **CLI** `guardian scan | run | approve | resume | serve`.
- **REST API** `/api/status, overview, matrix, graph, sbom, findings, investigations, priorities, proposals,
  validations, escalations, evidence/{id}, events, coverage, changes, inventory, report.md/json`;
  `POST /api/runs`, `POST /api/proposals/{id}/approval`, `POST /api/resume`.
- **Dashboard** (`guardian/web/`): URL input with live pipeline progress; overview; force-directed dependency
  network (path tracing with animated edges, prod-only and risky-paths filters); matrix with CSV export; findings
  with factor breakdown and evidence; agent outputs; remediation with diffs and approve/reject; validation timelines;
  live audit trail; report; coverage gaps.

## 9. Results

**OWASP NodeGoat** (primary target): 1,091 components (36 direct, 1,055 transitive; 380 prod), 131 vulnerable,
313 OSV advisories, 66 supply-chain indicators. Agents on Gemini: Red Team confirmed the unpinned `grunt-if` GitHub
dependency and end-of-life images with attack paths; every agent result passed the schema and citation checks.

**Validation**

| Fix | Verdict | Why |
|---|---|---|
| lockfile restore (planted tamper) | verified | 3/3 targets resolved, app boots, login works |
| `bson` override | verified | 2/2 targets resolved, no new findings |
| `express` 4.16.4 → 4.20.0 | verified | 2/2 resolved; 3 new low/medium transitive findings reported |
| `mongodb` 2.2.36 → 3.1.13 | **failed** | rescan said resolved, but the app crashed at startup (driver API change) |

**Coverage**: 20 public repositories scanned without errors (npm, pnpm monorepo, Poetry, uv, Pipenv, requirements,
Go, Cargo, RubyGems, Composer, Maven, Gradle → gap, CMake → gap, ROS, empty repo), 1–46 s each.

## 10. Tests

33 unit tests, no network or API key: lockfile resolution, CVSS maths, OSV range matching, every detector family
(including the sha1→sha512 false-positive fix), ecosystem parsers (pip-compile edges, Cargo, Go, Gemfile, pnpm
workspaces, monorepo merge, ROS/.repos), agent guardrails (invented ids rejected, schema violations corrected,
secrets redacted, path escape blocked), the LLM client request shape, and Gemini key/model fallback.
