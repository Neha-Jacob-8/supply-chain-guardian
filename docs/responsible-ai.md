# Responsible AI and Security Note

## Where AI is used

| Step | AI? | What the AI does | What it cannot do |
|---|---|---|---|
| Ingestion, inventory, SBOM, matrix | No | — | — |
| Vulnerability detection | No | — | Vulnerabilities come only from OSV |
| Supply-chain indicators | No | — | Indicators come from documented rules (`guardian/intel/detectors.py`) |
| Risk score | No | — | Scores come from a formula (`guardian/intel/risk.py`, weights in `policies/`) |
| Attack agent (Red Team) | Yes | Chooses which read-only checks to run; writes hypotheses and attack paths | Execute code, write files, attempt exploitation |
| Risk agent | Yes | Orders priorities and explains them | Change a score |
| Defense agent (Blue Team) | Yes | Chooses among computed fix candidates; explains trade-offs | Invent a fix, apply it, or declare it successful |
| Validation | No | — | Verdicts come from build, test and rescan results |

Models: Groq (ordered key/model fallback), Gemini (default order `gemini-3.5-flash` → `gemini-flash-latest` → lite
models, with ordered key fallback) and/or `claude-opus-5-5` via the Anthropic Messages API. The audit trail records
which provider, model and key number answered.
Without credentials every agent runs a labelled rule-based fallback, and the report states which mode ran.

## How hallucinations are controlled

1. **Grounded tools only.** Agents see the repository only through typed, read-only tools. Each tool result is
   saved as evidence with an id (`EV-…`) and a SHA-256.
2. **Citation check in code.** A submitted result is rejected unless every cited `finding_id`/`evidence_id`
   exists and every CVE/GHSA id it mentions was actually reported by OSV for this project. The rejection is
   returned to the agent, which must correct itself (covered by `tests/test_agents.py`).
3. **Facts vs inference.** Investigations separate `verified_facts` (each with evidence ids) from `inferences`;
   the report labels findings `verified` (OSV), `indicator` (rule) or AI inference.
4. **No AI numbers.** Scores, severities and verdicts are computed, never generated.
5. **Closed action space.** The Defense agent can only return candidate ids produced by
   `guardian/remediation/`; any other id is dropped and logged.
6. **Bounded loops.** Each agent has a step budget; on exhaustion or refusal the orchestrator falls back to rules
   and records why.

## Which actions need human approval

- **Every remediation** (not only risky ones) must be approved before validation touches it.
- Nothing is ever merged, pushed, deployed or released. Output is a diff plus rollback instructions.
- When a fix fails validation, the orchestrator may propose an alternative, which again needs approval.

## How source code, credentials and secrets are protected

- Repositories are cloned from `https://github.com/` only, with git hooks disabled, no submodule recursion,
  no credential prompts and `protocol.file.allow=never`; a matching existing clone is never overwritten.
- Repository code is never executed on the host. Lockfile regeneration uses `--ignore-scripts` inside
  `node:22-alpine` as UID 1000. Runtime builds are allowlisted by project name plus canonical remote identity,
  and Compose host escapes are rejected before startup. Trusted test dependency setup also uses `--ignore-scripts`;
  only the declared unit/HTTP checks execute in the container. Unknown repositories are static-only; containers are
  torn down after a trusted check.
- File excerpts given to the LLM pass through redaction for assignment-style API/access/secret/token/password/private
  keys, bearer values, token prefixes, and PEM blocks; `read_file` refuses paths outside the repository. Only
  bounded excerpts, never whole repositories, are sent to the LLM.
- Data sent to external services: package names/versions (OSV, npm registry), CVE ids (EPSS), and code
  excerpts (Groq / Gemini / Claude APIs, only in LLM mode). Repository secrets are redacted first. API keys live in a
  git-ignored `.env`, are sent only as request headers, and never appear in logs, events or reports.
- The demo tamper (`scripts/seed_demo.py`) is a local commit on a local branch pointing at a reserved
  `.example` domain; nothing is published to any registry.

## Known limitations

- Reachability is package-level (is the package imported), not function-level.
- Depth varies by ecosystem: full graphs from lockfiles, declared-only for Maven/ROS/manifests without locks;
  every unresolved part is reported as a coverage gap rather than guessed.
- Indicators are heuristics and can produce false positives (one was found and fixed: npm's sha1 to sha512
  re-records); they are labelled as indicators, not proof.
- The end-of-life table is a static snapshot.
- The smoke test checks login only; it is evidence that a fix did not break the app's core path, not full
  test coverage.
- Online intelligence is cached with a one-day default TTL; offline mode intentionally replays stale cache and
  labels the run. Refresh the cache before presenting current vulnerability counts.
