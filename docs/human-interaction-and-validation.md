# Human Interaction & Validation Guide

A concise reference for every **human-in-the-loop control** and **independent validation mechanism** in Supply Chain Guardian, mapped directly to the source files where each feature lives.

---

## 1. Human Interaction Points

### A. Remediation Approval Gate (Approve / Reject Fixes)
No remediation patch is written to a repository without explicit human approval (unless the user intentionally checks the top-bar **Auto-Mitigate & Merge** toggle).
- **Identity & Diff Binding:** Each approval records the reviewer, timestamp, repository commit SHA, `diff_sha256`, and `base_files_sha256`. If the repository changes before validation runs, stale approvals are rejected and pending proposals are marked `superseded`.
- **Where the code lives:**
  - CLI (`guardian approve --ids ...`): [`guardian/cli.py`](../guardian/cli.py)
  - Orchestrator gate & drift verification (`approval_gate`, `resume`): [`guardian/agents/orchestrator.py`](../guardian/agents/orchestrator.py)
  - REST API (`POST /api/proposals/{candidate_id}/approval`): [`guardian/api.py`](../guardian/api.py)
  - Web UI (**Remediation** tab Approve / Reject buttons): [`guardian/web/index.html`](../guardian/web/index.html), [`guardian/web/app.js`](../guardian/web/app.js)

### B. Human Warning Bypass / Risk Waiver
After inspecting a finding's evidence and risk breakdown, a human reviewer can dismiss/bypass a warning (e.g., an accepted internal release or false positive) with a documented reason, and restore it at any time.
- **Audit Trail:** Saved in `.guardian/policy.json` and cryptographically logged as a `finding_waived` / `finding_unwaived` block in `.guardian/ledger.jsonl`.
- **Where the code lives:**
  - Waiver persistence & ledger logging (`waive_finding`, `unwaive_finding`, `apply_waivers`): [`guardian/integrity.py`](../guardian/integrity.py)
  - Pipeline waiver annotation: [`guardian/pipeline.py`](../guardian/pipeline.py)
  - CLI (`guardian waive <repo> <finding_id> "<reason>"`): [`guardian/cli.py`](../guardian/cli.py)
  - REST API (`POST /api/findings/{finding_id}/waive`): [`guardian/api.py`](../guardian/api.py)
  - Web UI (**Findings** detail pane Bypass / Restore buttons): [`guardian/web/app.js`](../guardian/web/app.js)

### C. Developer Cryptographic Signing (Merkle Baseline)
When a legitimate developer edits source code, they bless the change using their secret signing key (`GUARDIAN_SIGNING_KEY` in `.env` or entered in the dashboard). Any unsigned edit (such as a malicious `postinstall` script or unauthorized git rebase) is flagged as `IT1` with the exact tampered chunk and line number.
- **Where the code lives:**
  - 4096-byte Merkle baseline & HMAC signing (`create_baseline`, `run_watch`, `verify_ledger`): [`guardian/integrity.py`](../guardian/integrity.py)
  - CLI (`guardian baseline`, `guardian watch`, `guardian verify-ledger`): [`guardian/cli.py`](../guardian/cli.py)
  - REST API (`GET /api/integrity`, `POST /api/integrity/baseline`): [`guardian/api.py`](../guardian/api.py)
  - Web UI (**Overview → Cryptographic Integrity** passphrase input & Sign button): [`guardian/web/index.html`](../guardian/web/index.html), [`guardian/web/app.js`](../guardian/web/app.js)

### D. Autonomous Mode Toggle (Top-Bar Auto-Mitigate & Merge)
Users can opt in to full autonomous mode from the top bar (`Auto-Mitigate & Merge` checkbox) or CLI (`--auto-merge`), allowing Guardian to automatically test and merge passing fixes without manual per-card clicks.
- **Where the code lives:**
  - CLI (`--auto-merge`): [`guardian/cli.py`](../guardian/cli.py)
  - REST API (`POST /api/runs` with `auto_merge`, `POST /api/auto-mitigate`): [`guardian/api.py`](../guardian/api.py)
  - Web UI (top header toggle): [`guardian/web/index.html`](../guardian/web/index.html), [`guardian/web/app.js`](../guardian/web/app.js)

---

## 2. Independent Validation & Safe Application

The Defense (Blue Team) agent can **never** mark its own fix as successful. Every approved fix is checked independently in an isolated copy of the repository.

### A. Docker Sandbox Validation (`guardian/validation/sandbox.py`)
1. Copies the repository to `output/validation/<candidate_id>` and applies the approved patch.
2. If `package.json` changed, regenerates `package-lock.json` inside a non-root Docker container (`node:22-alpine`, `--ignore-scripts`).
3. Runs an independent baseline rescan vs. patched rescan (`resolved`, `remaining`, `introduced_high`, and `sbom_diff`).
4. For allowlisted repositories (defined in [`guardian/policies/smoke_profiles.json`](../guardian/policies/smoke_profiles.json)), enforces a Compose host-escape policy (`compose_policy_violations`), boots the app in Docker Compose, and runs unit tests + HTTP smoke checks.
5. Assigns a deterministic verdict: **`verified`**, **`partial`** (e.g., static-only), or **`failed`** (if a working app breaks).

### B. Auto-Mitigation: Test Env, LLM Test Generation & Auto-Merge (`guardian/validation/auto_mitigate.py`)
1. Applies the patch in an isolated sandbox copy (`output/validation/automitigate_<candidate_id>`).
2. Discovers existing unit tests (`discover_existing_tests`) or generates a lightweight smoke test (`_guardian_smoke_test.py` / `_guardian_smoke_test.js`) using `GEMINI_API_FOR_TESTING` (with a deterministic fallback template).
3. Provisions an isolated test environment (`_prepare_test_environment`: `.guardian_test_env` Python venv or `--ignore-scripts` npm install).
4. Runs the test suite; if exit code is `0`, auto-merges the patched files into the repository and re-signs the Merkle baseline & hash-chained ledger.

### C. Safe Local Branch Application (`guardian/remediation/apply.py`)
- Writes eligible fixes (`verified`, or `partial` static-only fixes with a clean rescan and zero new high/critical findings) onto a new local git branch `guardian/remediation-<timestamp>`, one commit per fix, with git hooks disabled (never pushed automatically).
- Exports `output/remediation.patch` (`GET /api/remediation.patch`) for pull-request review.

---

## 3. Quick File Map

| Concern | Source Files | Tests |
|---|---|---|
| Approval Gate & Orchestration | [`guardian/agents/orchestrator.py`](../guardian/agents/orchestrator.py), [`guardian/agents/state.py`](../guardian/agents/state.py) | [`tests/test_apply.py`](../tests/test_apply.py) |
| Human Warning Bypass & Merkle Signing | [`guardian/integrity.py`](../guardian/integrity.py), [`guardian/agents/integrity_agent.py`](../guardian/agents/integrity_agent.py) | [`tests/test_upgrades.py`](../tests/test_upgrades.py) |
| Docker Sandbox Validation | [`guardian/validation/sandbox.py`](../guardian/validation/sandbox.py), [`guardian/policies/smoke_profiles.json`](../guardian/policies/smoke_profiles.json) | [`tests/test_day2_safety.py`](../tests/test_day2_safety.py) |
| Auto-Mitigation & Test Generation | [`guardian/validation/auto_mitigate.py`](../guardian/validation/auto_mitigate.py), [`guardian/agents/gemini.py`](../guardian/agents/gemini.py) | [`tests/test_upgrades.py`](../tests/test_upgrades.py) |
| Local Branch Apply & Patch Export | [`guardian/remediation/apply.py`](../guardian/remediation/apply.py), [`guardian/reporting/report.py`](../guardian/reporting/report.py) | [`tests/test_apply.py`](../tests/test_apply.py) |
| CLI, REST API & Web Dashboard | [`guardian/cli.py`](../guardian/cli.py), [`guardian/api.py`](../guardian/api.py), [`guardian/web/index.html`](../guardian/web/index.html), [`guardian/web/app.js`](../guardian/web/app.js) | — |
