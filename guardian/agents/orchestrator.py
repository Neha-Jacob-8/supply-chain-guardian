"""Guardian Orchestrator: owns the workflow, the shared state and every stage transition.

  discover -> investigate (Attack) -> analyze (Risk) -> remediate (Defense)
           -> awaiting_approval (human) -> validate (independent) -> report

Agents never call each other; they read/write RunState through the orchestrator, which records
each handoff and decision in events.jsonl. Write permissions are enforced here: the Defense agent
can only produce proposals, and only the Validation agent can produce verdicts.
"""
import json
import time

from .. import pipeline
from ..intel import risk
from ..remediation import build_candidates
from ..reporting import write_report
from ..validation import baseline_smoke, validate
from .llm import get_llm
from .attack import AttackAgent
from .defense import DefenseAgent
from .risk_analyst import RiskAgent
from .state import RunState

MAX_RETRIES = 2


class Orchestrator:
    def __init__(self, repo, out, llm_mode="auto", offline=False, history=20, smoke=True):
        self.state = RunState(repo, out)
        self.offline, self.history, self.smoke = offline, history, smoke
        try:
            self.llm = get_llm(llm_mode)
        except Exception as e:
            self.llm = None
            self.state.log("orchestrator", "decision", {"what": "LLM unavailable, agents use rule-based fallback", "why": str(e)})
        self.state.llm_mode = self.llm.name if self.llm else "none"

    def _stage(self, name):
        self.state.stage = name
        self.state.log("orchestrator", "stage", {"stage": name})
        print(f"[{name}]")

    def decide(self, what, why, **extra):
        self.state.log("orchestrator", "decision", {"what": what, "why": why, **extra})
        print(f"  decision: {what} ({why})")

    # ---------- stages ----------

    def discover(self):
        s = self.state
        self._stage("discover")
        inv, comps, findings, changes = pipeline.discover(s.repo, s.out, self.offline, self.history)
        if not comps:
            self.decide("stop", "no supported lockfile; see coverage_gaps.json")
            return False
        s.inventory, s.comps, s.changes, s.gaps = inv, comps, changes, inv["gaps"]
        s.set_findings(findings)
        s.risk, s.usage = risk.score_all(findings, comps, s.repo, s.out / "cache" / "intel", self.offline)
        for f in findings:            # additive field for the dashboard
            f["risk"] = s.risk[f["finding_id"]]
        pipeline.write_outputs(s.out, inv, comps, findings, changes)
        s.candidates = build_candidates(s.repo, comps, findings, s.out / "cache", self.offline)
        print(f"  {len(comps)} components, {len(findings)} findings, {len(s.candidates)} fix candidates")
        return True

    def investigate(self):
        agent = AttackAgent()
        if not agent.candidates(self.state):
            self.decide("skip Red Team", "no suspicious indicator scored >= 40")
            return
        self._stage("investigate")
        res = agent.run(self.state, self.llm)
        self.state.investigations = [dict(i, mode=res["mode"]) for i in res["investigations"]]
        print(f"  {len(self.state.investigations)} investigations ({res['mode']})")

    def analyze(self):
        self._stage("analyze")
        res = RiskAgent().run(self.state, self.llm)
        valid = set(self.state.by_id)
        self.state.priorities = [dict(p, finding_ids=[i for i in p["finding_ids"] if i in valid], mode=res["mode"])
                                 for p in res["priorities"]]
        self.state.risk_summary = res.get("summary", "")
        print(f"  {len(self.state.priorities)} priorities ({res['mode']})")

    def remediate(self):
        self._stage("remediate")
        res = DefenseAgent().run(self.state, self.llm)
        by_id = {c["candidate_id"]: c for c in self.state.candidates}
        self.state.proposals = [dict(p, mode=res["mode"], change_risk=by_id[p["candidate_id"]]["change_risk"],
                                     summary=by_id[p["candidate_id"]]["summary"], diff=by_id[p["candidate_id"]]["diff"])
                                for p in res["proposals"] if p["candidate_id"] in by_id]
        self.state.escalations = res.get("escalations", [])
        for p in self.state.proposals:
            self.state.approvals.setdefault(p["candidate_id"], {"status": "pending"})
        print(f"  {len(self.state.proposals)} proposals, {len(self.state.escalations)} escalations ({res['mode']})")

    def approval_gate(self, approve=None, interactive=False):
        """approve: None (keep saved decisions), 'all', 'low', 'none', or a list of candidate ids."""
        self._stage("awaiting_approval")
        s = self.state
        for p in s.proposals:
            cid, cur = p["candidate_id"], s.approvals.get(p["candidate_id"], {"status": "pending"})
            decision = None
            if approve == "all" or (isinstance(approve, list) and cid in approve):
                decision = "approved"
            elif approve == "low":
                decision = "approved" if p["change_risk"] == "low" else None
            elif approve == "none":
                decision = "rejected"
            elif interactive and cur["status"] == "pending":
                print(f"\n  {cid} [{p['change_risk']} risk] {p['summary']}\n    why: {p['rationale'][:200]}")
                ans = input("  approve? [y/N] ").strip().lower()
                decision = "approved" if ans == "y" else "rejected"
            if decision:
                s.approvals[cid] = {"status": decision, "by": "human reviewer", "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
                s.log("human", "approval", {"candidate_id": cid, "status": decision})
        n = sum(1 for p in s.proposals if s.approvals[p["candidate_id"]]["status"] == "approved")
        pending = sum(1 for p in s.proposals if s.approvals[p["candidate_id"]]["status"] == "pending")
        print(f"  approved {n}, pending {pending}")
        return n

    def validate(self):
        self._stage("validate")
        s = self.state
        by_id = {c["candidate_id"]: c for c in s.candidates}
        if self.smoke:
            s.baseline_smoke = baseline_smoke(s)
            print(f"  baseline smoke test on unmodified app: {'pass' if s.baseline_smoke['ok'] else 'FAIL'}")
            if not s.baseline_smoke["ok"]:
                self.decide("judge smoke results relative to baseline",
                            "the unmodified app already fails to build/boot; a fix that makes it pass is an improvement")
        queue = [p["candidate_id"] for p in s.proposals if s.approvals.get(p["candidate_id"], {}).get("status") == "approved"]
        tried = set()
        while queue:
            cid = queue.pop(0)
            tried.add(cid)
            res = validate(s, by_id[cid], smoke=self.smoke,
                           baseline_ok=(s.baseline_smoke or {}).get("ok", True))
            s.validations.append(res)
            print(f"  {cid}: {res['verdict']}  ({by_id[cid]['summary'][:70]})")
            if res["verdict"] == "failed":
                alt = self._alternative(by_id[cid], tried)
                if alt and sum(1 for v in s.validations if v["candidate_id"] in tried) <= MAX_RETRIES + len(tried):
                    self.decide("propose alternative fix", f"{cid} failed validation", alternative=alt["candidate_id"])
                    s.proposals.append({"candidate_id": alt["candidate_id"], "finding_ids": alt["closes"],
                                        "rationale": f"Alternative after {cid} failed validation", "summary": alt["summary"],
                                        "change_risk": alt["change_risk"], "diff": alt["diff"], "mode": "orchestrator retry",
                                        "expected_risk_reduction": "", "compat_assessment": alt["compat_notes"],
                                        "rollback": alt["rollback"], "order": len(s.proposals) + 1})
                    s.approvals[alt["candidate_id"]] = {"status": "pending"}
                else:
                    self.decide("escalate", f"{cid} failed validation and no alternative candidate exists")

    def _alternative(self, cand, tried):
        risk_rank = {"low": 0, "medium": 1, "high": 2}
        alts = [c for c in self.state.candidates if c["candidate_id"] not in tried and c["action"] != "escalate"
                and set(c["closes"]) & set(cand["closes"]) and c["candidate_id"] not in self.state.approvals]
        return min(alts, key=lambda c: risk_rank[c["change_risk"]]) if alts else None

    def finish(self):
        self._stage("report")
        paths = write_report(self.state)
        self.state.stage = "done"
        self.state.save()
        print(f"  wrote {', '.join(paths)}")

    # ---------- entry points ----------

    def run(self, approve=None, interactive=False):
        if not self.discover():
            return self.finish()
        self.investigate()
        self.analyze()
        self.remediate()
        approved = self.approval_gate(approve, interactive)
        self.state.save()
        if not approved:
            self.decide("pause for human approval", "no remediation is approved; nothing is applied")
            print(f"  review {self.state.out}/report.md, then: python -m guardian.cli approve --ids <id,...> ; "
                  f"python -m guardian.cli resume {self.state.repo}")
            return self.finish()
        self.validate()
        self.finish()

    def resume(self):
        """Rebuild the deterministic state, restore agent outputs and human decisions, continue."""
        saved = json.loads((self.state.out / "run_state.json").read_text())
        if not self.discover():
            return self.finish()
        s = self.state
        s.investigations, s.priorities = saved["investigations"], saved["priorities"]
        s.proposals, s.approvals = saved["proposals"], saved["approvals"]
        s.risk_summary = saved.get("risk_summary", "")
        s.escalations = saved.get("escalations", [])
        s.log("orchestrator", "resume", {"approved": [k for k, v in s.approvals.items() if v["status"] == "approved"]})
        if self.approval_gate() == 0:
            self.decide("stop", "still nothing approved")
            return self.finish()
        self.validate()
        self.finish()
