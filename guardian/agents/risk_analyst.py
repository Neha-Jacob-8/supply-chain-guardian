"""Risk Analysis agent: prioritises using formula scores and investigations; never re-scores."""
import json

from . import prompts
from . import tools as T
from .base import Agent
from .common import _arr, _obj, _s, risk_items


class RiskAgent(Agent):
    name = "risk_agent"
    tool_names = ["get_finding", "get_component", "check_import_usage", "list_findings", "read_file"]
    max_steps = 20
    system = prompts.system("risk")
    result_schema = _obj({"summary": _s("2-3 sentence overall assessment"), "priorities": _arr(_obj({
        "rank": {"type": "integer"}, "finding_ids": _arr({"type": "string"}), "headline": _s("one line"),
        "rationale": _s("why this rank, citing the factors"), "evidence_ids": _arr({"type": "string"}),
        "recommendation": {"type": "string", "enum": ["fix_now", "fix_soon", "monitor", "accept"]},
        "escalate": {"type": "boolean"}}))})

    def task(self, state):
        items = [{k: i[k] for k in ("title", "score", "finding_ids")} | {"factors": state.risk[i["top_finding"]]["factors"]}
                 for i in risk_items(state)[:20]]
        inv = [{k: v["finding_ids"] if k == "finding_ids" else v[k] for k in ("title", "verdict", "finding_ids")}
               for v in state.investigations]
        return ("Produce the top 10 priorities (rank 1 = most urgent). You may verify reachability or context with "
                "tools before ranking. Use only finding_ids from the list.\n\n"
                f"Scored items (formula):\n{json.dumps(items, indent=1)[:12000]}\n\nRed Team investigations:\n{json.dumps(inv, indent=1)}")

    def fallback(self, state):
        pr = []
        for rank, i in enumerate(risk_items(state)[:10], 1):
            fac = state.risk[i["top_finding"]]["factors"]
            why = "; ".join(f"{k} +{v['points']} ({v['why']})" for k, v in fac.items())
            sev = state.risk[i["top_finding"]]["severity"]
            pr.append({"rank": rank, "finding_ids": i["finding_ids"], "headline": i["title"],
                       "rationale": f"Formula score {i['score']}: {why}", "evidence_ids": [],
                       "recommendation": {"CRITICAL": "fix_now", "HIGH": "fix_now", "MEDIUM": "fix_soon"}.get(sev, "monitor"),
                       "escalate": False})
        return {"summary": "Ranked by the deterministic risk formula (no LLM review).", "priorities": pr}
