"""Guardian Orchestrator: owns the workflow, the shared state and every stage transition.

  discover -> investigate (Attack) -> analyze (Risk) -> remediate (Defense)
           -> awaiting_approval (human) -> validate (independent) -> apply (verified only) -> report

Agents never call each other; they read/write RunState through the orchestrator, which records
each handoff and decision in events.jsonl. Write permissions are enforced here: the Defense agent
can only produce proposals, and only the Validation agent can produce verdicts.
"""
import json
import time

from .. import pipeline
from ..ingestion import repository_identity
from ..intel import risk
from ..remediation import apply_verified, build_candidates
from ..remediation.apply import eligible
from ..reporting import write_report
from ..validation import baseline_smoke, validate
from .llm import get_llm
from .attack import AttackAgent
from .defense import DefenseAgent
from .integrity_agent import IntegrityAgent
from .risk_analyst import RiskAgent
from .state import RunState

MAX_RETRIES = 2


class Orchestrator:
    def __init__(self, repo, out, llm_mode="auto", offline=False, history=20, smoke=True):
        self.state = RunState(repo, out)
        self.offline, self.history, self.smoke = offline, history, smoke
        self.state.run_config = {"offline": offline, "history": history, "smoke": smoke}
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
        s.identity = repository_identity(s.repo)
        # Ensure initial signed 4096-byte Merkle baseline + hash-chained ledger exist automatically
        if not (s.repo / ".guardian" / "baseline.json").exists() and not (s.repo / ".truststack" / "baseline.json").exists():
            from ..integrity import create_baseline
            try:
                create_baseline(s.repo, signer="guardian-initial-scan")
            except Exception:
                pass
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
        int_agent = IntegrityAgent()
        has_attack = bool(agent.candidates(self.state))
        has_integrity = bool(int_agent.candidates(self.state))
        if not has_attack and not has_integrity:
            self.decide("skip Red Team", "no suspicious indicator scored >= 40")
            return
        self._stage("investigate")
        invs = []
        mode = "none"
        if has_attack:
            res = agent.run(self.state, self.llm)
            mode = res["mode"]
            invs.extend(dict(i, mode=res["mode"]) for i in res["investigations"])
        if has_integrity:
            ires = int_agent.run(self.state, self.llm)
            mode = ires["mode"] if mode == "none" else mode
            invs.extend(dict(i, mode=f"integrity ({ires['mode']})") for i in ires["investigations"])
        self.state.investigations = invs
        print(f"  {len(self.state.investigations)} investigations ({mode})")

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
                                     summary=by_id[p["candidate_id"]]["summary"], diff=by_id[p["candidate_id"]]["diff"],
                                     diff_sha256=by_id[p["candidate_id"]].get("diff_sha256"),
                                     base_files_sha256=by_id[p["candidate_id"]].get("base_files_sha256", {}),
                                     requires=by_id[p["candidate_id"]].get("requires", []),
                                     needs_lockfile_regen=by_id[p["candidate_id"]].get("needs_lockfile_regen", False))
                                for p in res["proposals"] if p["candidate_id"] in by_id]
        self.state.escalations = res.get("escalations", [])
        # candidates without a patch (manual upgrades, no fix published) go to a human, not to approval/validation
        manual = [p for p in self.state.proposals if by_id[p["candidate_id"]]["action"] == "escalate" or not by_id[p["candidate_id"]]["files"]]
        for p in manual:
            c = by_id[p["candidate_id"]]
            escalation = {"finding_ids": p["finding_ids"], "reason": f"{c['summary']}. {c['compat_notes']}"}
            key = (tuple(sorted(escalation["finding_ids"])), escalation["reason"])
            existing = {(tuple(sorted(e.get("finding_ids", []))), e.get("reason", ""))
                        for e in self.state.escalations}
            if key not in existing:
                self.state.escalations.append(escalation)
        if manual:
            self.decide("route manual fixes to escalation", f"{len(manual)} proposal(s) have no patch to validate")
        self.state.proposals = [p for p in self.state.proposals if p not in manual]
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
                s.approvals[cid] = {
                    "status": decision,
                    "by": "human reviewer",
                    "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "repo_identity": s.identity,
                    "diff_sha256": p.get("diff_sha256"),
                    "base_files_sha256": p.get("base_files_sha256", {}),
                }
                s.log("human", "approval", {"candidate_id": cid, "status": decision})
        n = sum(1 for p in s.proposals if s.approvals[p["candidate_id"]]["status"] == "approved")
        pending = sum(1 for p in s.proposals if s.approvals[p["candidate_id"]]["status"] == "pending")
        print(f"  approved {n}, pending {pending}")
        return n

    def validate(self):
        self._stage("validate")
        s = self.state
        by_id = {c["candidate_id"]: c for c in s.candidates}
        validated = {v["candidate_id"] for v in s.validations}
        approved = [p["candidate_id"] for p in s.proposals if s.approvals.get(p["candidate_id"], {}).get("status") == "approved"
                    and p["candidate_id"] not in validated]
        gone = [c for c in approved if c not in by_id]
        if gone:
            self.decide("skip validation", "the repository changed and these fixes no longer apply", candidates=gone)
        queue = [c for c in approved if c in by_id]
        if queue and self.smoke:
            s.baseline_smoke = baseline_smoke(s)
            status = "pass" if s.baseline_smoke["ok"] is True else "FAIL" if s.baseline_smoke["ok"] is False else "not available"
            print(f"  baseline runtime check on unmodified app: {status}")
            if s.baseline_smoke["ok"] is False:
                self.decide("judge smoke results relative to baseline",
                            "the unmodified app already fails to build/boot; a fix that makes it pass is an improvement")
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

    def apply(self):
        """Write validated fixes to the target repository (local branch, one commit per fix, never pushed)."""
        s = self.state
        by_id = {c["candidate_id"]: c for c in s.candidates}
        if not any(eligible(v) and v["candidate_id"] in by_id for v in s.validations):
            return
        self._stage("apply")
        recs = apply_verified(s, by_id)
        for r in recs:
            print(f"  {r['candidate_id']}: {r['status']}  {r.get('commit') or ''} {r['detail']}")
        not_applied = [v["candidate_id"] for v in s.validations if not eligible(v)]
        if not_applied:
            self.decide("do not apply", "failed, runtime-failing or incomplete fixes are never written to the repository",
                        candidates=not_applied)
        if any(r["status"] == "applied" for r in recs):
            stale = [p["candidate_id"] for p in s.proposals if s.approvals.get(p["candidate_id"], {}).get("status") == "pending"]
            for cid in stale:
                s.approvals[cid] = {"status": "superseded", "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "reason": "the repository changed when fixes were applied; re-run the analysis"}
            if stale:
                self.decide("supersede pending proposals", "approvals are bound to the analysed commit and the "
                            "applied fixes created new commits; re-run the analysis for the remaining fixes",
                            candidates=stale)

    def _alternative(self, cand, tried):
        risk_rank = {"low": 0, "medium": 1, "high": 2}
        alts = [c for c in self.state.candidates if c["candidate_id"] not in tried and c["action"] != "escalate"
                and set(c["closes"]) & set(cand["closes"]) and c["candidate_id"] not in self.state.approvals]
        return min(alts, key=lambda c: risk_rank[c["change_risk"]]) if alts else None

    def auto_mitigate(self, candidate_ids=None, auto_merge=True):
        """Run LLM/fallback test discovery/generation in sandbox and auto-merge passing candidates."""
        from ..validation.auto_mitigate import auto_mitigate_candidate
        self._stage("validate")
        s = self.state
        by_id = {c["candidate_id"]: c for c in s.candidates}
        targets = candidate_ids or [
            p["candidate_id"] for p in s.proposals
            if s.approvals.get(p["candidate_id"], {}).get("status") == "approved"
        ]
        results = []
        for cid in targets:
            if cid not in by_id or not by_id[cid].get("files"):
                continue
            res = auto_mitigate_candidate(s, by_id[cid], llm=self.llm, auto_merge=auto_merge)
            s.validations = [v for v in s.validations if v["candidate_id"] != cid] + [res]
            if not res.get("merged"):
                s.approvals[cid] = {"status": "pending", "reason": "Auto-merge did not complete; requires human Approve / Reject"}
            results.append(res)
            print(f"  auto-mitigate {cid}: {res['verdict']} (merged={res['merged']})")
        return results

    def finish(self):
        from ..integrity import append_ledger_record
        self._stage("report")
        paths = write_report(self.state, llm=self.llm)
        self.state.stage = "done"
        self.state.save()
        if (self.state.repo / ".guardian" / "ledger.jsonl").exists():
            try:
                append_ledger_record(self.state.repo, {
                    "event": "run_completed",
                    "repo": str(self.state.repo),
                    "findings": len(self.state.findings),
                    "validations": len(self.state.validations),
                })
            except Exception:
                pass
        print(f"  wrote {', '.join(paths)}")

    # ---------- entry points ----------

    def run(self, approve=None, interactive=False, auto_merge=False):
        for stale in ("events.jsonl", "report.md", "report.json"):   # a new run starts a new audit trail
            (self.state.out / stale).unlink(missing_ok=True)
        self.state.log("orchestrator", "run_started", {"repo": str(self.state.repo), "llm": self.state.llm_mode})
        if not self.discover():
            return self.finish()
        self.investigate()
        self.analyze()
        self.remediate()
        approved = self.approval_gate("all" if (auto_merge and approve is None) else approve, interactive)
        self.state.save()
        if not approved:
            self.decide("pause for human approval", "no remediation is approved; nothing is applied")
            print(f"  review {self.state.out}/report.md, then: python -m guardian.cli approve --ids <id,...> ; "
                  f"python -m guardian.cli resume {self.state.repo}")
            return self.finish()
        if auto_merge:
            self.auto_mitigate(auto_merge=True)
        else:
            self.validate()
            self.apply()
        self.finish()

    def resume(self):
        """Rebuild the deterministic state, restore agent outputs and human decisions, continue."""
        saved = json.loads((self.state.out / "run_state.json").read_text())
        if not self.discover():
            return self.finish()
        s = self.state
        expected_identity = saved.get("identity")
        if not expected_identity:
            raise RuntimeError("saved run has no repository identity; fresh approval is required")
        for key in ("remote_id", "commit"):
            if expected_identity.get(key) != s.identity.get(key):
                raise RuntimeError(f"repository {key} changed since approval; rerun and approve the new candidate")
        current = {c["candidate_id"]: c for c in s.candidates}
        for old in saved.get("proposals", []):
            new = current.get(old["candidate_id"])
            if not new or new.get("diff_sha256") != old.get("diff_sha256") or \
                    new.get("base_files_sha256", {}) != old.get("base_files_sha256", {}):
                raise RuntimeError(f"candidate {old['candidate_id']} changed since approval; fresh approval is required")
        for cid, approval in saved.get("approvals", {}).items():
            if approval.get("status") == "approved" and \
                    (approval.get("repo_identity", {}).get("commit") != s.identity.get("commit") or
                     approval.get("diff_sha256") != current.get(cid, {}).get("diff_sha256")):
                raise RuntimeError(f"approval for {cid} is not bound to the current commit/diff")
        s.investigations, s.priorities = saved["investigations"], saved["priorities"]
        s.proposals, s.approvals = saved["proposals"], saved["approvals"]
        s.risk_summary = saved.get("risk_summary", "")
        s.escalations = saved.get("escalations", [])
        s.validations, s.applied = saved.get("validations", []), saved.get("applied", [])
        s.baseline_smoke = saved.get("baseline_smoke")
        s.log("orchestrator", "resume", {"approved": [k for k, v in s.approvals.items() if v["status"] == "approved"]})
        if self.approval_gate() == 0:
            self.decide("stop", "still nothing approved")
            return self.finish()
        self.validate()
        self.apply()
        self.finish()
