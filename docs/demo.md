# Demo script (about 7 minutes)

**Story:** "Show us how the Guardian takes a finding from detection to verified remediation."

## Before the demo

```bash
pip install -e ".[all]"
cp .env.example .env                                  # add GEMINI_API_KEYS
guardian scan https://github.com/OWASP/NodeGoat       # clones into targets/, warms caches
python3 scripts/seed_demo.py targets/NodeGoat         # local tamper commit on branch guardian-demo (never pushed)
docker pull node:22-alpine && docker pull mongo:4.4   # avoid pulls during the demo
guardian serve                                        # http://127.0.0.1:8000
```

Validation takes about 3 minutes per fix: run it once beforehand and keep the `output/` folder as a fallback.
Every lookup is cached under `output/cache/`, so `--offline` works if the network fails.

## 1. Any repository (1 min)

Paste `https://github.com/OWASP/NodeGoat` (or any public repo) into the dashboard and press **Analyse**.
The pipeline bar shows Discover → Investigate → Analyze → Remediate → Approval live.

## 2. Discover (1 min)

**Overview**: 1,091 components, direct vs transitive, prod vs dev, coverage gaps.
**Dependency network**: force-directed graph; click `minimist@0.0.10` to trace its path from the root
(animated edges); switch to **Risky paths**.

## 3. Detect (1 min)

**Findings**: OSV advisories labelled VERIFIED with CVSS and fixed version; indicators labelled INDICATOR:
the planted commit (SC1 express integrity changed with no version bump, SC2 body-parser moved off the registry,
SC5 lockfile sections disagree), EOL `node:12-alpine`, unpinned actions. Open one to show the risk factor breakdown
and the evidence (file/line or commit, SHA-256).

## 4. Investigate and prioritise (1.5 min)

**Agents**: Red Team investigations with attack paths, verified facts (click an evidence id) separated from
inference; Risk agent priorities with rationale. **Activity**: the audit trail, including any submission the
guardrail rejected (invented CVE or missing field) and the model's correction.

## 5. Remediate and approve (1 min)

**Remediation**: proposals with change risk, compatibility, rollback and **View diff**. Approve the lockfile
restore, the bson override and the mongodb upgrade, then **Run independent validation**.

## 6. Validate (1.5 min)

| Fix | Verdict | Point to make |
|---|---|---|
| Lockfile restore | verified | non-CVE finding closed; integrity matches the registry; app boots, login works |
| bson override | verified | transitive CVEs closed, nothing new |
| mongodb 2 → 3 | **failed** | the rescan alone said "resolved"; the app crashed at boot. Only independent validation caught it |

## 7. Report (30 s)

**Report**: findings with evidence, priorities, proposals and approvals, validation, remaining risk, coverage gaps.
Download JSON for the machine-readable version.

## Reset

```bash
git -C targets/NodeGoat checkout master && git -C targets/NodeGoat branch -D guardian-demo
```
