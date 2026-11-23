# Demo script (about 7 minutes)

**Story:** "Show us how the Guardian takes a finding from detection to verified remediation."

## Before the demo (do once, takes ~15 min)

```bash
pip install -e ".[all]"
export ANTHROPIC_API_KEY=...                         # optional; without it agents run rule-based fallbacks
guardian scan https://github.com/OWASP/NodeGoat      # clones into targets/, warms OSV/KEV/EPSS caches
python3 scripts/seed_demo.py targets/NodeGoat        # local tamper commit on branch guardian-demo
docker pull node:22-alpine && docker pull mongo:4.4  # avoid pulls during the demo
```

Network fallback: every lookup is cached under `output/cache/`; add `--offline` if wifi fails.

## 1. Discover (1 min)

```bash
guardian run targets/NodeGoat
```
Show the printed stages and `output/report.md` header: 1,091 components (36 direct, 1,055 transitive),
CycloneDX SBOM, Dependency Matrix (`output/matrix.csv`), graph, coverage gaps.

## 2. Detect (1.5 min)

- Vulnerabilities: 131 vulnerable components, 313 OSV advisories (verified evidence, cached record + SHA-256).
- "What changed": the planted commit `chore: refresh lockfile` → **SC1** express integrity changed without a
  version change, **SC2** body-parser moved off the registry, **SC5** lockfile sections disagree.
- Containers/CI: EOL `node:12-alpine`, unpinned actions, missing `permissions:`.

## 3. Investigate + prioritise (1.5 min)

- Red Team: compares the lockfile with the official npm registry → verdict `confirmed_risk`, with evidence ids.
- Risk: priority table with factor breakdown, e.g. underscore 75 = CVSS 9.8 + prod + imported by
  `config/config.js`; minimist lower because its parent `forever` is not imported.
- Point out: scores are formula, the LLM only explains; claims citing unknown ids are rejected.

## 4. Remediate + approve (1 min)

Proposals table: lockfile restore (low risk), bson override (low), express upgrade (medium), mongodb major
upgrade (high). Approve live:

```bash
guardian approve --ids <FIX-LOCK-...>,<FIX-OVR-...>,<FIX-VULN-mongodb...>
guardian resume targets/NodeGoat
```
(or click approve in the dashboard → `POST /api/proposals/{id}/approval`, then `POST /api/resume`)

## 5. Validate (1.5 min; ~3 min per fix, pre-record if short on time)

| Fix | Expected verdict | Why it matters |
|---|---|---|
| Lockfile restore | verified | non-CVE finding closed; integrity now matches the registry; app boots, login works |
| bson override | verified | transitive CVEs closed, no new findings |
| mongodb 2 → 3 | **failed** | rescan alone said "resolved, nothing new"; the app crashed at boot (driver API change). Only the independent validator caught it; the orchestrator escalates |

## 6. Report (30 s)

`output/report.md` / `report.json`: findings with evidence, priorities, proposals with approval status,
validation steps, before/after counts, SBOM diff, remaining risk, coverage gaps. Audit trail in
`output/events.jsonl`.

## Reset

```bash
git -C targets/NodeGoat checkout master
git -C targets/NodeGoat branch -D guardian-demo
```
