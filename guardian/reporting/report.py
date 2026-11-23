"""Guardian Security Report: report.json (machine-readable) + report.md (human-readable)."""
import json
from collections import Counter
from dataclasses import asdict

from ..config import cache_ttl_seconds


def write(state):
    s = state
    comps = s.comps.values()
    vuln = [f for f in s.findings if f["category"] == "vulnerability"]
    ind = [f for f in s.findings if f["category"] != "vulnerability"]
    validated_resolved = {
        finding_id
        for validation in s.validations
        for finding_id in (validation.get("comparison") or {}).get("resolved", [])
    }
    remaining = [f for f in s.findings if f["finding_id"] not in validated_resolved]
    run_config = getattr(s, "run_config", {}) or {}
    baseline = getattr(s, "baseline_smoke", None)
    data = {
        "schema_version": "1.0",
        "repo": str(s.repo), "identity": getattr(s, "identity", {}), "llm_mode": s.llm_mode,
        "inventory": {"components": len(s.comps), **Counter(c.relationship for c in comps),
                      **{f"scope_{k}": v for k, v in Counter(c.scope for c in comps).items()},
                      "projects": s.inventory.get("projects", []), "ecosystems": s.inventory.get("ecosystems", [])},
        "components": [asdict(c) for c in sorted(s.comps.values(), key=lambda x: x.component_id)],
        "findings": {"vulnerabilities": len(vuln), "indicators": len(ind),
                     "by_risk_severity": Counter(s.risk[f["finding_id"]]["severity"] for f in s.findings) if s.risk else {},
                     "items": s.findings},
        "risk_summary": getattr(s, "risk_summary", ""), "priorities": s.priorities,
        "investigations": s.investigations,
        "proposals": [{k: v for k, v in p.items() if k != "diff"} | {"approval": s.approvals.get(p["candidate_id"])}
                      for p in s.proposals],
        "escalations": getattr(s, "escalations", []),
        "baseline_smoke": baseline, "validations": s.validations,
        "validation_scope": {
            "runtime_profiles": sorted({(v.get("comparison") or {}).get("runtime_check", "static only")
                                         for v in s.validations}),
            "runtime_validated_candidates": sum(bool((v.get("comparison") or {}).get("runtime_validated"))
                                                 for v in s.validations),
            "baseline_runtime_validated": bool(baseline and baseline.get("runtime_validated")),
        },
        "cache_policy": {"offline": run_config.get("offline"), "ttl_seconds": cache_ttl_seconds()},
        "lockfile_changes": s.changes, "coverage_gaps": s.gaps,
        "evidence_index": s.evidence,
        "remaining_risk": [
            {"finding_id": f["finding_id"], "title": f["title"],
             "risk": s.risk.get(f["finding_id"], {}), "category": f["category"]}
            for f in remaining
        ],
        "resolved_risk": [{"finding_id": finding_id} for finding_id in sorted(validated_resolved)],
    }
    (s.out / "report.json").write_text(json.dumps(data, indent=2, default=str))

    L = [f"# Guardian Security Report", "", f"- Repository: `{s.repo}`",
         f"- Agents ran with: **{'LLM: ' + s.llm_mode if s.llm_mode != 'none' else 'rule-based fallback, no LLM'}** "
         f"(per-agent mode is shown with each priority/investigation)",
         f"- Components: {len(s.comps)} ({data['inventory'].get('direct', 0)} direct, {data['inventory'].get('transitive', 0)} transitive; "
         f"{data['inventory'].get('scope_prod', 0)} prod, {data['inventory'].get('scope_dev', 0)} dev)",
         f"- Findings: {len(vuln)} vulnerability advisories (verified, OSV) + {len(ind)} supply-chain indicators (rule-based)", ""]
    if data["risk_summary"]:
        L += ["## Assessment", "", data["risk_summary"], ""]
    L += ["## Validation scope", "",
          f"- Intelligence mode: **{'offline cache replay' if run_config.get('offline') else 'online with cache refresh'}** "
          f"(cache TTL: {cache_ttl_seconds()} seconds).",
          f"- Trusted runtime profiles used: **{', '.join(data['validation_scope']['runtime_profiles']) or 'none (static-only)'}**."]
    if baseline:
        status = "pass" if baseline.get("ok") is True else "fail" if baseline.get("ok") is False else "not run"
        L.append(f"- Baseline runtime check: **{status}**; runtime evidence is {'present' if baseline.get('runtime_validated') else 'not present'}.")
    else:
        L.append("- Baseline runtime check: **not run** (no approved candidate reached validation).")
    L.append("")
    L += ["## Priorities", "", "| # | Issue | Score | Recommendation | Why |", "|---|---|---|---|---|"]
    for p in s.priorities:
        top = max(p["finding_ids"], key=lambda i: s.risk[i]["score"]) if p["finding_ids"] else None
        sc = s.risk[top]["score"] if top else "-"
        L.append(f"| {p['rank']} | {p['headline']} | {sc} | {p['recommendation']}{' (escalate)' if p.get('escalate') else ''} "
                 f"| {p.get('rationale', '')[:220].replace('|', '/')} |")
    L += ["", "## Red Team investigations", ""]
    for i in s.investigations:
        L += [f"### {i['title']} — {i['verdict']} (confidence {i['confidence']})", "", f"*Hypothesis:* {i['hypothesis']}", ""]
        if i.get("attack_path"):
            L += ["*Attack path:* " + " → ".join(i["attack_path"]), ""]
        L += ["**Verified facts** (tool evidence):"] + [f"- {v['claim']} `[{', '.join(v['evidence_ids'])}]`" for v in i["verified_facts"]]
        if i.get("inferences"):
            L += ["", "**AI/heuristic inference** (not verified):"] + [f"- {x}" for x in i["inferences"]]
        L.append("")
    L += ["## Proposed remediations", "", "| Candidate | Change | Risk | Approval | Validation |", "|---|---|---|---|---|"]
    verdicts = {v["candidate_id"]: v["verdict"] for v in s.validations}
    for p in s.proposals:
        ap = s.approvals.get(p["candidate_id"], {}).get("status", "pending")
        L.append(f"| `{p['candidate_id']}` | {p['summary']} | {p['change_risk']} | {ap} | {verdicts.get(p['candidate_id'], 'not run')} |")
    for e in getattr(s, "escalations", []):
        L.append(f"| — | Escalated: {e['reason']} ({len(e['finding_ids'])} findings) | — | human decision | — |")
    if s.validations:
        L += ["", "## Validation (independent)", ""]
        bs = getattr(s, "baseline_smoke", None)
        if bs:
            status = "pass" if bs.get("ok") is True else "fail" if bs.get("ok") is False else "not run (no trusted runtime profile)"
            L += [f"Baseline runtime check on the unmodified app: **{status}**", ""]
        for v in s.validations:
            L += [f"### `{v['candidate_id']}` — **{v['verdict']}**", "", v["summary"], ""]
            L += [f"- {st['name']}: {'ok' if st.get('rc') == 0 else 'FAILED'} {st.get('detail', '')}" for st in v["steps"]]
            c = v.get("comparison")
            if c:
                L += [f"- targeted findings resolved: {len(c['resolved'])}/{c['targets']}; remaining: {len(c['remaining'])}",
                      f"- findings before → after: {c['before']['findings']} → {c['after']['findings']}; "
                      f"vulnerable components {c['before']['vulnerable_components']} → {c['after']['vulnerable_components']}",
                      f"- SBOM diff: +{c['sbom_diff']['added_count']} / -{c['sbom_diff']['removed_count']} components; "
                      f"newly introduced findings: {c['introduced_count']} (high/critical: {len(c['introduced_high'])})"]
            L.append("")
    L += ["## Remaining risk", "",
          f"- Open findings at report time: **{len(remaining)}** ({len(vuln)} vulnerability findings and {len(ind)} indicators were observed at scan time; "
          f"{len(validated_resolved)} finding(s) were resolved by validation evidence)."]
    if remaining:
        L += ["", "| Severity | Finding | Title |", "|---|---|---|"]
        ranked = sorted(remaining, key=lambda f: -(s.risk.get(f["finding_id"], {}).get("score", 0)))[:20]
        for finding in ranked:
            risk = s.risk.get(finding["finding_id"], {})
            L.append(f"| {risk.get('severity', finding.get('severity', 'UNKNOWN'))} | `{finding['finding_id']}` | "
                     f"{finding['title'].replace('|', '/')} |")
        if len(remaining) > len(ranked):
            L.append(f"| ... | ... | {len(remaining) - len(ranked)} additional finding(s) are in `report.json`. |")
    L.append("")
    L += ["## What changed (lockfile history)", ""] + [
        f"- `{c['commit']}` {c.get('date', '')} {c.get('subject', '')}: +{c.get('added', '?')} / -{c.get('removed', '?')} / "
        f"~{c.get('version_changed', '?')}" + (f", {c['hash_algorithm_upgrades']} hash-algorithm upgrades (benign)" if c.get("hash_algorithm_upgrades") else "")
        for c in s.changes[:10]]
    L += ["", "## Coverage gaps and limitations", ""] + [f"- {g['kind']}: {g['detail']}" for g in s.gaps] + [
        "- Package-level reachability only (is the package imported), not function-level.",
        "- Vulnerabilities come from OSV; indicators are heuristics, not proof of compromise.",
        "- Every remediation needs human approval; nothing is merged or deployed automatically.", ""]
    (s.out / "report.md").write_text("\n".join(L))
    return ["report.json", "report.md"]
