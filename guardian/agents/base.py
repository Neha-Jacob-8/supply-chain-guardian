"""Agent loop: the model plans, calls read-only tools, and finishes by calling `submit_result`.

Guardrails enforced in code (not in the prompt):
  * every finding_id / evidence_id the agent cites must exist in the run state;
  * every CVE/GHSA id it mentions must be one OSV actually reported;
  * a failed check is returned to the model as a tool error so it can correct itself;
  * a step budget bounds every run.
"""
import json
import re

from . import tools as T

ADVISORY = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b")
SUBMIT = "submit_result"


def _walk_ids(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("evidence_ids", "finding_ids", "cites") and isinstance(v, list):
                out.extend(str(x) for x in v)
            elif k in ("finding_id", "evidence_id") and isinstance(v, str):
                out.append(v)
            else:
                _walk_ids(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_ids(v, out)


def check_citations(state, result):
    ids = []
    _walk_ids(result, ids)
    known = state.known_ids()
    bad_ids = sorted({i for i in ids if i not in known})
    mentioned = set(ADVISORY.findall(json.dumps(result)))
    bad_adv = sorted(mentioned - state.known_advisories())
    errors = []
    if bad_ids:
        errors.append(f"These ids do not exist in the run state: {bad_ids[:10]}. Cite only finding_ids from "
                      "list_findings/get_finding or evidence_ids returned by your tool calls.")
    if bad_adv:
        errors.append(f"These advisory ids were not reported by OSV for this project: {bad_adv[:10]}. Remove them.")
    if not ids:
        errors.append("Your result cites no finding_ids or evidence_ids. Every claim must be backed by evidence.")
    return errors


class Agent:
    name = "agent"
    system = ""
    tool_names = []
    result_schema = {}
    max_steps = 14

    def submit_spec(self):
        return {"name": SUBMIT, "description": "Submit your final structured result. Call exactly once when done.",
                "strict": True, "input_schema": self.result_schema}

    def run_llm(self, state, llm, task):
        tools = T.specs(self.tool_names) + [self.submit_spec()]
        messages = [{"role": "user", "content": task}]
        nudged = False
        for step in range(self.max_steps):
            r = llm.step(self.system, messages, tools)
            state.log(self.name, "llm_step", {"step": step, "stop_reason": r.stop_reason, "usage": r.usage,
                                              "tools": [u.name for u in r.tool_uses], "text": r.text[:300]})
            messages.append({"role": "assistant", "content": r.content})
            if r.stop_reason == "refusal":
                state.log(self.name, "refusal", {})
                return None
            if not r.tool_uses:
                if nudged:
                    return None
                nudged = True
                messages.append({"role": "user", "content": f"Call {SUBMIT} with your structured result now."})
                continue
            results, final = [], None
            for u in r.tool_uses:
                if u.name == SUBMIT:
                    errors = check_citations(state, u.input)
                    state.log(self.name, "submit", {"accepted": not errors, "errors": errors})
                    if errors:
                        results.append({"type": "tool_result", "tool_use_id": u.id, "is_error": True,
                                        "content": "Rejected: " + " ".join(errors)})
                    else:
                        final = u.input
                        results.append({"type": "tool_result", "tool_use_id": u.id, "content": "accepted"})
                    continue
                out, eid = T.call(state, u.name, u.input)
                state.log(self.name, "tool_call", {"tool": u.name, "args": u.input, "evidence_id": eid,
                                                   "error": out.get("error") if isinstance(out, dict) else None})
                body = json.dumps({"evidence_id": eid, "result": out}, default=str)
                if len(body) > T.MAX_CHARS:
                    body = body[:T.MAX_CHARS] + '..." [truncated]'
                results.append({"type": "tool_result", "tool_use_id": u.id, "content": body,
                                **({"is_error": True} if eid is None else {})})
            if final is not None:
                return final
            messages.append({"role": "user", "content": results})
        state.log(self.name, "budget_exhausted", {"max_steps": self.max_steps})
        return None

    def run(self, state, llm, **kw):
        """LLM mode when available; otherwise the deterministic fallback (clearly labelled)."""
        if llm is not None:
            try:
                res = self.run_llm(state, llm, self.task(state, **kw))
                if res is not None:
                    return {**res, "mode": f"llm:{llm.name}"}
                state.log(self.name, "fallback", {"reason": "no accepted result from LLM"})
            except Exception as e:
                state.log(self.name, "fallback", {"reason": f"{type(e).__name__}: {e}"})
        return {**self.fallback(state, **kw), "mode": "rule-based (no LLM)"}

    def task(self, state, **kw):
        raise NotImplementedError

    def fallback(self, state, **kw):
        raise NotImplementedError
