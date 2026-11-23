"""Attack agent (Red Team): read-only investigation of suspicious supply-chain indicators."""
import json

from . import prompts
from . import tools as T
from .base import Agent
from .common import _arr, _obj, _s, risk_items


class AttackAgent(Agent):
    name = "attack_agent"
    tool_names = ["get_finding", "get_component", "npm_registry_metadata", "git_commit_info", "read_file",
                  "check_import_usage", "list_findings"]
    max_steps = 24
    system = prompts.system("attack")
    result_schema = _obj({"investigations": _arr(_obj({
        "finding_ids": _arr({"type": "string"}),
        "title": _s("short name of the issue"),
        "hypothesis": _s("what an attacker could do"),
        "attack_path": _arr({"type": "string"}, "ordered steps from entry point to impact"),
        "verified_facts": _arr(_obj({"claim": _s("fact shown by a tool"), "evidence_ids": _arr({"type": "string"})})),
        "inferences": _arr({"type": "string"}, "your reasoning, not verified"),
        "verdict": {"type": "string", "enum": ["confirmed_risk", "likely_benign", "needs_human_review"]},
        "confidence": {"type": "number"}}))})

    def candidates(self, state):
        return [i for i in risk_items(state) if i["rule"] != "VULN" and i["score"] >= 40][:10]

    def task(self, state):
        rows = [{k: i[k] for k in ("title", "score", "finding_ids")} for i in self.candidates(state)]
        return ("Investigate these supply-chain indicators. For lockfile integrity/source changes, compare the "
                "lockfile with the official registry record and inspect the commit that introduced the change. For "
                "CI/container issues, read the relevant file lines. Group related findings. One investigation per "
                f"issue.\n\nCandidates:\n{json.dumps(rows, indent=1)}")

    def fallback(self, state):
        out = []
        for item in self.candidates(state):
            f = state.by_id[item["top_finding"]]
            facts = [{"claim": f["title"] + (": " + f.get("detail", "") if f.get("detail") else ""),
                      "evidence_ids": [f["finding_id"]]}]
            verdict, inf = "confirmed_risk", []
            c = state.comps.get(f.get("component_id"))
            if f["rule_id"] in ("SC1", "SC2") and c and "github.com" not in (c.source_url or ""):
                meta, eid = T.call(state, "npm_registry_metadata", {"package": c.name, "version": c.version})
                if eid and not meta.get("error"):
                    ok = meta.get("integrity_matches_lockfile") and meta.get("resolved_matches_registry")
                    facts.append({"claim": f"Registry integrity matches lockfile: {meta.get('integrity_matches_lockfile')}; "
                                           f"resolved matches registry: {meta.get('resolved_matches_registry')}",
                                  "evidence_ids": [eid]})
                    verdict = "likely_benign" if ok else "confirmed_risk"
                commit = f["evidence"].get("commit")
                if commit:
                    info, eid2 = T.call(state, "git_commit_info", {"commit": commit})
                    if eid2 and not info.get("error"):
                        facts.append({"claim": f"Introduced by {info['commit'][:10]} by {info['author']}: \"{info['subject']}\"",
                                      "evidence_ids": [eid2]})
            if c and c.scope == "dev":
                inf.append("Dev-only package: affects developer/CI machines, not the shipped app.")
            out.append({"finding_ids": item["finding_ids"], "title": item["title"],
                        "hypothesis": f.get("detail") or f["title"], "attack_path": [],
                        "verified_facts": facts, "inferences": inf, "verdict": verdict,
                        "confidence": 0.7 if len(facts) > 1 else 0.5})
        return {"investigations": out}
