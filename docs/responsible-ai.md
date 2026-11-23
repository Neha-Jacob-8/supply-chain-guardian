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

Model: `claude-opus-5-5` via the Anthropic Messages API with adaptive thinking and server-side refusal fallback.
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
  no credential prompts and `protocol.file.allow=never`.
- Repository code is never executed on the host. Lockfile regeneration uses `--ignore-scripts` inside
  `node:22-alpine`; the app is built and booted only inside Docker containers, which are removed afterwards.
- File excerpts given to the LLM pass through a secret-redaction filter; `read_file` refuses paths outside the
  repository. Only excerpts, never whole repositories, are sent to the LLM.
- Data sent to external services: package names/versions (OSV, npm registry), CVE ids (EPSS), and code
  excerpts (Claude API, only in LLM mode). No credentials are sent anywhere.
- The demo tamper (`scripts/seed_demo.py`) is a local commit on a local branch pointing at a reserved
  `.example` domain; nothing is published to any registry.

## Known limitations

- Reachability is package-level (is the package imported), not function-level.
- Only npm `package-lock.json` is analysed deeply; other ecosystems are reported as coverage gaps.
- Indicators are heuristics and can produce false positives (one was found and fixed: npm's sha1 to sha512
  re-records); they are labelled as indicators, not proof.
- The end-of-life table is a static snapshot.
- The smoke test checks login only; it is evidence that a fix did not break the app's core path, not full
  test coverage.
