"""Defense agent (Blue Team): chooses among deterministic fix candidates; cannot invent or validate fixes."""
import json

from . import prompts
from . import tools as T
from .base import Agent
from .common import _arr, _obj, _s, risk_items


class DefenseAgent(Agent):
    name = "defense_agent"
    tool_names = ["get_fix_options", "get_finding", "get_component", "check_import_usage", "read_file"]
    max_steps = 20
    system = prompts.system("defense")
    result_schema = _obj({
        "proposals": _arr(_obj({"candidate_id": _s("from get_fix_options"), "finding_ids": _arr({"type": "string"}),
                                "rationale": _s("why this fix"), "expected_risk_reduction": _s("prediction only"),
                                "compat_assessment": _s("what could break"), "rollback": _s("how to undo"),
                                "order": {"type": "integer"}})),
        "escalations": _arr(_obj({"finding_ids": _arr({"type": "string"}), "reason": _s("why a human must decide")}))})

    def task(self, state):
        pr = [{k: p[k] for k in ("rank", "headline", "finding_ids", "recommendation")} for p in state.priorities]
        return ("Propose remediations for these priorities (call get_fix_options for each). Order proposals so "
                f"prerequisites come first.\n\nPriorities:\n{json.dumps(pr, indent=1)[:12000]}")

    def run_llm(self, state, llm, task):
        res = super().run_llm(state, llm, task)
        if res is None:
            return None
        valid = {c["candidate_id"] for c in state.candidates}
        bad = [p["candidate_id"] for p in res.get("proposals", []) if p["candidate_id"] not in valid]
        if bad:
            state.log(self.name, "invalid_candidates_dropped", {"candidate_ids": bad})
            res["proposals"] = [p for p in res["proposals"] if p["candidate_id"] in valid]
        return res

    def fallback(self, state):
        rank = {"low": 0, "medium": 1, "high": 2}
        props, esc, used = [], [], set()
        for p in state.priorities:
            opts = [c for c in state.candidates if set(p["finding_ids"]) & set(c["closes"]) and c["action"] != "escalate"]
            opts.sort(key=lambda c: (rank[c["change_risk"]], -len(c["closes"])))
            if not opts:
                esc.append({"finding_ids": p["finding_ids"], "reason": "No deterministic fix candidate closes this issue."})
                continue
            c = opts[0]
            if c["candidate_id"] in used:
                continue
            used.add(c["candidate_id"])
            props.append({"candidate_id": c["candidate_id"], "finding_ids": sorted(set(p["finding_ids"]) & set(c["closes"])),
                          "rationale": f"Lowest-risk candidate for priority {p['rank']}: {c['summary']}",
                          "expected_risk_reduction": f"Should close {len(c['closes'])} finding(s) (prediction)",
                          "compat_assessment": c["compat_notes"], "rollback": c["rollback"], "order": len(props) + 1})
        return {"proposals": props, "escalations": esc}
