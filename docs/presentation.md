# Presentation runbook for tomorrow

## One-sentence pitch

Supply Chain Guardian is an evidence-first multi-agent security team: deterministic discovery builds the SBOM and
dependency graph, Red/Risk/Blue agents investigate and prioritize in application context, a human approves a
bounded diff, and an independent validator rescans and tests it before reporting what remains.

## What to prepare before the room

1. Install the project and verify Docker.
2. Run one online scan to warm OSV/registry/EPSS/KEV caches.
3. Run the deterministic demo once with `--llm none`; keep the generated output directory as a fallback.
4. If Docker is available, approve one low-risk proposal in a disposable output directory and capture its validation
   comparison. If Docker is unavailable, present the recorded static-only `partial` behavior honestly; do not call
   it verified.
5. Start the dashboard locally and keep the terminal visible for stage transitions.

Suggested preparation:

```bash
pip install -e ".[all]"
guardian run https://github.com/OWASP/NodeGoat --out demo-output --llm none --approve none
guardian serve --out demo-output --host 127.0.0.1 --port 8000
```

For a controlled history demonstration, use the local-only tamper seeder in a disposable clone:

```bash
python3 scripts/seed_demo.py targets/NodeGoat
guardian run targets/NodeGoat --out demo-tamper-output --llm none --approve none --no-smoke
```

The seeder creates a local branch only, uses a reserved `.example` mirror URL, and never publishes anything. Reset
the clone afterward with `git -C targets/NodeGoat checkout <original-branch>` and remove the demo branch only when
you are certain it contains no user work.

## Seven-minute live flow

### 1. Frame the problem (45 seconds)

Say: “A CVE list is not a decision. We need to know whether the component is direct or transitive, production or
development, reachable in application code, introduced by a suspicious change, and whether a proposed fix actually
works.” Point to the four-stage story: discover → reason → approve → validate.

### 2. Show the architecture (45 seconds)

Open `docs/architecture.md` or the architecture SVG. Emphasize that tools produce facts and numbers, agents
interpret those facts, and the orchestrator prevents agents from writing code or declaring success.

### 3. Day 1 discovery (60 seconds)

Open Overview and Matrix:

- 1,091 components in the current NodeGoat snapshot;
- direct/transitive and production/development split;
- full graph and CycloneDX SBOM;
- coverage gaps instead of guessed values.

Click a package and trace its parent path. Then open one OSV finding and one non-CVE indicator.

### 4. Evidence and investigation (75 seconds)

Open the findings and Agents views. Show:

- OSV record, affected range, fixed version, CVSS and evidence URL;
- indicator evidence such as an off-registry moving branch or EOL container image;
- Red Team verified facts with evidence IDs separated from inference;
- audit events showing tool calls and guardrail checks.

Say: “The LLM can propose a hypothesis, but it cannot invent a finding ID, CVE, evidence ID, score, or verdict.”

### 5. Day 2 prioritization (60 seconds)

Open the top priority's factor breakdown. Explain the difference between a high-CVSS unused dev package and a
reachable production dependency. Point out exposure, import reachability, directness, EPSS/KEV, and the deterministic
formula score.

### 6. Remediation and approval (60 seconds)

Open a proposal diff. Show its exact files, compatibility notes, prerequisites, rollback, and candidate hash. Explain
that Blue Team chooses only a computed candidate; it cannot invent a patch. Approve one low-risk change and leave a
second one rejected or pending to demonstrate human control.

### 7. Independent validation and report (90 seconds)

Open the validation card and call out the sequence: fresh copy → safe lockfile regeneration → baseline rescan →
patched rescan → SBOM diff → trusted unit/HTTP checks → teardown. Show `verified`, `partial`, or `failed` according
to the evidence. Finish on `report.md` and `report.json`: remaining risk, resolved targets, introduced findings,
coverage gaps, approvals, identity, and evidence index.

## Claims to avoid

- Do not say “all vulnerabilities are fixed” because a scan is clean only for the scanned snapshot and data sources.
- Do not call static-only validation verified.
- Do not claim function-level exploitability; reachability is package/import-level.
- Do not say the LLM computed scores or applied a patch; both are false.
- Do not run a random repository's Dockerfile during the demo; unknown targets are intentionally static-only.
- Do not show credentials, private repositories, production systems, or a real malicious package.

## Likely judge questions

**Why is this agentic instead of a prompt over scanner output?** Each specialist has a role, typed tools, a bounded
loop, a structured result, evidence citations, and a hand-off. The orchestrator can run without an LLM but labels
that fallback, so the evidence pipeline remains reproducible.

**Why not sort by CVSS?** The risk formula includes production exposure, import reachability, dependency path,
directness, EPSS, and CISA KEV. The report shows every factor and confidence.

**Can the model make a dangerous change?** No. It can only select a candidate generated by deterministic code. A
human approves each proposal, and the validator applies it only to a fresh copy after drift/hash checks.

**What does “verified” mean?** Targets disappeared in the validator's rescan, no high/critical finding was introduced,
the trusted runtime/test checks passed, and the baseline comparison is recorded. Otherwise the result is partial or
failed.

**What happens when no safe automatic fix exists?** The issue is escalated with a manual recommendation and remains
in the report's remaining-risk section.

**How do you protect secrets and the host?** File excerpts are redacted before LLM calls; GitHub ingestion disables
hooks/prompts/submodules; runtime is allowlisted, policy-checked Docker only; and no target changes are merged or
deployed.

## Closing sentence

“Guardian does not replace engineering judgment. It makes the judgment faster and safer by connecting evidence,
context, approval, and independent proof in one auditable loop.”
