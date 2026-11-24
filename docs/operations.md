# Operations and reproducible runbook

## Prerequisites

- Python 3.11 or newer.
- Git.
- Docker Engine/Desktop plus Docker Compose v2 (`docker compose` or the standalone `docker-compose` plugin) for
  lockfile regeneration and the allowlisted NodeGoat runtime profile.
- Network access for a fresh OSV/registry/EPSS/KEV lookup, unless the required cache is already present.
- Optional: Groq, Anthropic, or Gemini credentials. Without credentials, all agents use labelled deterministic fallbacks.

Install from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
```

The core scanner only needs PyYAML. The `all` extra adds the optional Claude SDK, FastAPI, and Uvicorn dashboard
dependencies. Put credentials in a git-ignored `.env`; never paste them into a report or commit them.

For Groq, create separate keys in the Groq console and fill the four numbered slots in `.env`:

```dotenv
GROQ_API_KEY_1=...
GROQ_API_KEY_2=...
GROQ_API_KEY_3=...
GROQ_API_KEY_4=...
```

The `groq` backend rotates keys on authentication/rate-limit errors, tries the next configured model when a model is
unavailable, retries transient service failures, and then falls back to the next provider or the labelled rule-based
agent. Guardian cannot create Groq keys; they must be created by the account owner at `console.groq.com`.

## Day 1 scan

```bash
guardian scan https://github.com/OWASP/NodeGoat --out output
```

The command safely accepts public `https://github.com/<owner>/<repo>` URLs, disables Git hooks, disables credential
prompts, avoids submodule recursion, and reuses a matching local clone without overwriting local work. It writes:

| File | Purpose |
|---|---|
| `inventory.json` | repository, projects, ecosystems, and coverage gaps |
| `components.json` | complete normalized component records |
| `matrix.csv` / `matrix.json` | direct/transitive, prod/dev, parent path, source, license, advisories and risk |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM |
| `graph.json` | dependency nodes and edges |
| `findings.json` | OSV vulnerabilities and deterministic indicators |
| `lockfile_changes.json` | lockfile history and commit evidence |
| `coverage_gaps.json` | unresolved/unsupported inputs; the scanner does not guess |

Useful options:

```bash
guardian scan <repo-or-local-path> --history 20       # compare recent lockfile commits
guardian scan <repo> --offline                         # replay cache; never silently fetch
guardian scan <repo> --no-vulns                        # discovery/detectors only
```

Online intelligence caches are refreshed when older than `GUARDIAN_CACHE_TTL_SECONDS` (default 86,400 seconds).
`--offline` permits stale replay but fails clearly when a required record is missing.

## Full agentic run

```bash
guardian run https://github.com/OWASP/NodeGoat --out output --llm none --approve none
```

Use `--llm auto` for configured providers, or `--llm groq` to use the Groq key pool explicitly; `--llm none` is deterministic and presentation-safe. `--approve none`
demonstrates the approval pause without applying anything. A normal run proceeds:

`discover → investigate → analyze → remediate → awaiting_approval → validate → report`

If no proposal is approved, the run stops safely and still writes a report. The output directory is not a merge
workspace; it is an audit artifact.

## Approval and resume

Review proposal IDs and diffs in the dashboard or `report.md`, then approve only the changes you understand:

```bash
guardian approve --out output --ids FIX-abc123,FIX-def456
guardian resume targets/NodeGoat --out output --llm none
```

The approval is bound to:

- canonical remote identity and commit;
- exact candidate `diff_sha256`;
- SHA-256 hashes of every candidate base file.

If the checkout or candidate changes, resume refuses to validate and asks for fresh approval. Every candidate has
compatibility notes and a rollback instruction. No command writes back to the target repository.

## Dashboard/API

```bash
guardian serve --out output --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. The API exposes overview, inventory, matrix, graph, SBOM, findings, investigations,
priorities, proposals, validations, escalations, evidence, events, coverage, changes, and both report formats.
`POST /api/proposals/{candidate_id}/approval` records a human decision; `POST /api/resume` continues a saved run.

## Validation contract

For each approved candidate the independent validator:

1. copies the target while excluding `.git` and `node_modules`;
2. refuses a patch if a candidate base file has drifted;
3. regenerates npm lockfiles in `node:22-alpine` as UID 1000 with `--ignore-scripts`, never on the host;
4. rescans the unmodified copy and patched copy with the same deterministic tools;
5. computes resolved, remaining, introduced, and high/critical introduced findings plus SBOM component deltas;
6. runs a trusted profile's dependency setup (scripts disabled), unit command and HTTP checks, then tears down
   Compose resources.

`verified` requires all targeted findings resolved, no introduced high/critical finding, successful trusted runtime
evidence, and a working baseline comparison. `partial` means the change is statically assessed or still has
remaining risk. `failed` means a previously working runtime was broken (or a prerequisite such as lockfile
regeneration failed). Static-only validation is never upgraded to `verified`.

## Runtime safety policy

The validator does not execute arbitrary repository Dockerfiles or Compose files. A runtime profile must match both
the project name and a trusted remote ID in `guardian/policies/smoke_profiles.json`. Before any trusted Compose run,
the validator rejects privileged/host namespace settings, capabilities/devices/security options, host socket or
outside-repository mounts, outside build contexts, interpolated host paths, and outside env/config/secret files.
Unknown or untrusted repositories receive a static rescan and an explicit `partial` verdict.

## Evidence and audit files

- `events.jsonl`: stage transitions, decisions, agent calls, approvals, validation verdicts.
- `evidence/EV-*.json`: canonical tool output, arguments, and SHA-256.
- `run_state.json`: resumable state, identity, proposals, approval bindings, and validations.
- `candidates_files.json`: exact candidate new-file contents (the candidate object itself retains old/new pairs in memory).
- `report.json`: stable machine-readable schema (`schema_version: 1.0`).
- `report.md`: human-readable developer report with remaining risk and limitations.

## Troubleshooting

| Symptom | Action |
|---|---|
| No supported manifest/lockfile | Read `coverage_gaps.json`; select a repository with a supported ecosystem or add a parser deliberately. |
| Offline run lacks a record | Re-run online once to warm the same `output/cache/` directory, then retry with `--offline`. |
| Docker validation fails | Inspect the recorded `regenerate_lockfile`, `build_and_boot`, or `sandbox_policy` step. A failed prerequisite is not silently treated as verified. |
| Resume refuses | The target commit, remote identity, proposal diff, or base file changed. Re-run discovery and obtain fresh approval. |
| Agent provider unavailable | Use `--llm none`; the report labels the deterministic fallback and the core evidence/scoring still work. |
| Runtime profile not selected | Confirm the project name and canonical remote ID; do not bypass the allowlist for an untrusted repository. |
