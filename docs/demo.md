# Live demo script (7–10 minutes)

Use [presentation.md](presentation.md) for the complete talk track and judge questions. This page is the short
operator checklist.

## Prepare

```bash
pip install -e ".[all]"
guardian run https://github.com/OWASP/NodeGoat --out demo-output --llm none --approve none
guardian serve --out demo-output --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Keep `demo-output/report.md` and `demo-output/report.json` ready as a fallback.
Refresh the online cache before presenting current counts; use `--offline` only when explicitly demonstrating cache
replay.

## Flow

1. **Problem (45 s):** a CVE list does not say whether a package is reachable, production, direct, or safely fixable.
2. **Architecture (45 s):** deterministic tools produce facts; Red/Risk/Blue agents interpret them; a human approves;
   an independent validator decides.
3. **Discovery (60 s):** show 1,091 components in the current NodeGoat snapshot, direct/transitive and prod/dev
   split, SBOM, graph, matrix, and coverage gaps.
4. **Evidence (75 s):** show an OSV advisory and an indicator such as off-registry `grunt-if` or an EOL image; open
   the file/line/commit evidence and the Red Team fact/inference split.
5. **Prioritization (60 s):** open a factor breakdown showing CVSS plus KEV/EPSS, exposure, reachability and
   directness.
6. **Remediation (60 s):** open a deterministic diff with compatibility notes, prerequisites and rollback; approve
   one proposal and reject/leave another pending.
7. **Validation/report (90 s):** show fresh-copy patching, lockfile-only Docker regeneration, independent rescan,
   SBOM diff, trusted unit/HTTP checks (when allowlisted), and the final remaining-risk section.

## Optional local tamper story

Run this only on a disposable clone:

```bash
python3 scripts/seed_demo.py targets/NodeGoat
guardian run targets/NodeGoat --out demo-tamper-output --llm none --approve none --no-smoke
```

The seeder creates a local branch and points one resolved URL at a reserved `.example` domain; it never publishes a
package. Reset the checkout to its original branch after the demonstration.

## Important wording

Say “static-only validation is partial” when no trusted profile ran. Say “verified” only when the report contains
runtime evidence, all targeted findings are resolved, and no high/critical finding was introduced. Do not claim all
vulnerabilities are fixed, function-level exploitability is known, or that an LLM applied a patch.
