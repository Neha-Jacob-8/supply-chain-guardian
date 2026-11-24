# Implementation notes

This document explains the implementation behind the requirements map. It is intentionally precise about what is
deterministic, what is model-assisted, and what is still a limitation.

## Technology choices

| Layer | Choice | Reason |
|---|---|---|
| Runtime | Python 3.11+ | standard library for core orchestration; PyYAML for Compose/pnpm data |
| Vulnerability intelligence | OSV.dev | exact-version queries with affected ranges, fixed versions, aliases and evidence URLs |
| Exploit intelligence | CISA KEV + FIRST EPSS | application-context prioritization beyond CVSS |
| SBOM | CycloneDX 1.5 JSON | portable machine-readable inventory |
| Agents | typed tool-use loops with Groq/Gemini/Claude providers and deterministic fallback | genuine role separation without making an LLM authoritative |
| API/UI | FastAPI/Uvicorn plus static HTML/CSS/JS | live run, evidence, graph, matrix and approval views without a frontend build step |
| Validation | Docker Engine/Desktop | target code is not executed on the host; lockfile generation uses `--ignore-scripts` |

## Deterministic discovery and detection

`guardian/pipeline.py` is the single Day-1 entry point. It builds the normalized inventory, writes the SBOM/graph/
matrix, queries OSV, runs non-CVE detectors, calculates risk scores, and generates candidate patches. A parser gap
is written to `coverage_gaps.json`; unknown data is never filled with a guess.

Supported inventory inputs include npm (`package-lock`, npm-shrinkwrap, pnpm workspaces, Yarn v1, package.json),
Python (Poetry, uv, Pipenv, requirements), Go, Cargo, RubyGems, Composer, Maven, ROS, and `.repos`/`.gitmodules`
declarations. Full dependency edges are available when a lockfile contains them; declared-only ecosystems are
labelled accordingly.

The detector catalog is:

| Rule | Signal |
|---|---|
| SC1 | lockfile integrity changed without a version change |
| SC2 | resolved package moved off the registry or to a moving branch |
| SC3 | install scripts execute package code |
| SC4 | floating manifest specs or unpinned URL/git references |
| SC5 | npm lockfile v2 legacy and `packages` sections disagree |
| SC6 | a new direct dependency appeared in lockfile history |
| SC7 | a direct dependency crossed a semantic-version major in lockfile history |
| MT1 | maintainer-deprecated package |
| CT1–CT5 | digest pinning, EOL image, root container, remote script, `npm install` versus `npm ci` |
| CI1–CI4 | mutable GitHub Actions, missing permissions, `pull_request_target`, untrusted event data in `run` |

Every indicator includes rule ID, severity, component (when applicable), path/line/commit, excerpt, SHA-256 and a
recommendation. Indicators are signals, not proof that a package is malicious.

## Risk formula

Vulnerability findings use:

`40 × CVSS/10 + exploitability + exposure + reachability + directness`

- exploitability is 25 for CISA KEV, otherwise `15 × EPSS` when available;
- exposure is 15 for production and 3 for development;
- reachability is 15 for a directly imported package and 8 for a transitive package under an imported direct parent;
- directness contributes 5.

Indicators use policy weights in `guardian/policies/risk_weights.json`, with production/dev exposure and a history
bonus where relevant. Each score stores factor points, explanations, confidence, and `computed_by: formula`.

## Agent contracts

The orchestrator is the only component that advances stages or persists a decision. Agents cannot call each other.

| Role | Reads | Writes |
|---|---|---|
| Attack/Red Team | findings, components, registry metadata, commits, imports, redacted files | hypotheses, attack paths, verified facts, inference, verdict |
| Risk | findings, components, imports, existing scores | ranked priorities and explanation; never score values |
| Defense/Blue Team | priorities, computed candidates, compatibility context | candidate IDs, rationale, rollback, escalation |
| Validator | approved candidate, fresh copy, rescan and trusted runtime | deterministic comparison and verdict |

The tool layer stores each call as `EV-<hash>.json`. Submission guardrails reject unknown IDs, unsupported
citations, malformed schemas, invented advisories, and out-of-repository paths. If a provider is unavailable or a
step budget expires, the report says `rule-based fallback, no LLM` rather than implying an LLM ran.

## Candidate and approval integrity

Candidate IDs are SHA-256-derived from the logical subject and exact unified diff. Each candidate also stores
`diff_sha256` and SHA-256 hashes of the original contents of every file it will touch. Proposals copy those hashes.
Approvals recorded by CLI, dashboard, or API include the target's canonical remote ID, commit, diff hash, base-file
hashes, reviewer and timestamp. `resume` reruns discovery and refuses stale identity, diff, or base-file state.

NodeGoat-only container migration candidates are gated to the canonical `owasp/nodegoat` remote. A repository that
merely contains `Dockerfile` or `docker-compose.yml` does not receive a target-specific NodeGoat patch.

## Independent validation

`guardian/validation/sandbox.py` is deliberately independent from the Defense agent. It copies the repository,
checks candidate base content, applies the exact old/new pairs, and (for npm manifest changes) runs lockfile-only
installation in a non-root `node:22-alpine` container with scripts disabled. It then builds a fresh baseline and
patched inventory using the same OSV/detector code and computes:

- target findings resolved and remaining;
- newly introduced findings and newly introduced high/critical findings;
- before/after vulnerable-component counts;
- SBOM component additions/removals;
- trusted runtime/test evidence, when a profile exists.

Runtime execution is fail-closed. Only a project-name plus trusted-remote profile in `guardian/policies/
smoke_profiles.json` may run. Before Compose starts, the policy rejects host namespaces, privileged mode,
capabilities/devices/security options, host sockets, outside-repository mounts/build contexts, interpolated host
paths, and outside env/config/secret files. Unknown repositories are rescanned statically and receive `partial`,
not `verified`. Compose invocation supports either the `docker-compose` v2 plugin or `docker compose`. The NodeGoat
profile installs development dependencies with `--ignore-scripts` inside the running container before executing its
unit command, because the application image is intentionally production-only.

## Report schema

`report.json` has schema version `1.0` and includes the identity, run configuration/cache policy, complete inventory,
serialized components, all findings, risk breakdown, priorities, investigations, proposals and approval bindings,
escalations, baseline/runtime scope, validation comparisons, lockfile history, coverage gaps, evidence index, and
remaining/resolved risk. `report.md` presents the same story for a developer and explicitly states when runtime
evidence was not available.

## Verification performed

The repository currently passes 44 tests with the optional test dependencies installed. The suite covers parsers,
CVSS/range matching, every detector family, redaction, candidate hashing, CI permissions placement, Compose safety,
static-only verdict semantics, missing runtime binaries, agent schemas/guardrails, and LLM request shape. `compileall`
also passes. A live rule-based NodeGoat run reproduced the current inventory and produced a complete report; exact
vulnerability counts are a time-dependent intelligence snapshot.
