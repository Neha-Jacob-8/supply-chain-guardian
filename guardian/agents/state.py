"""Shared run state: the only channel between agents (via the orchestrator)."""
import hashlib
import json
import time
from pathlib import Path

from ..ingestion import repository_identity


class RunState:
    STAGES = ["discover", "investigate", "analyze", "remediate", "awaiting_approval", "validate", "report", "done"]

    def __init__(self, repo, out_dir):
        self.repo, self.out = Path(repo), Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "evidence").mkdir(exist_ok=True)
        self.stage = "discover"
        self.inventory = {}
        self.comps = {}
        self.findings = []
        self.by_id = {}
        self.changes, self.gaps = [], []
        self.risk, self.usage = {}, {}
        self.investigations, self.priorities = [], []
        self.candidates, self.proposals = [], []
        self.approvals, self.validations = {}, []
        self.evidence = {}
        self.events = []
        self.llm_mode = "none"
        self.risk_summary, self.escalations, self.baseline_smoke = "", [], None
        self.identity = repository_identity(self.repo)
        self.run_config = {"offline": None, "history": None, "smoke": None}

    # ---- audit trail ----
    def log(self, actor, kind, detail):
        ev = {"t": round(time.time(), 3), "stage": self.stage, "actor": actor, "kind": kind, "detail": detail}
        self.events.append(ev)
        with open(self.out / "events.jsonl", "a") as f:
            f.write(json.dumps(ev, default=str) + "\n")

    def add_evidence(self, tool, args, result):
        body = json.dumps({"tool": tool, "args": args, "result": result}, default=str, sort_keys=True)
        eid = "EV-" + hashlib.sha256(body.encode()).hexdigest()[:10]
        if eid not in self.evidence:
            path = self.out / "evidence" / f"{eid}.json"
            path.write_text(body)
            self.evidence[eid] = {"evidence_id": eid, "kind": "tool_output", "tool": tool, "args": args,
                                  "path": str(path), "sha256": hashlib.sha256(body.encode()).hexdigest()}
        return eid

    def set_findings(self, findings):
        self.findings = findings
        self.by_id = {f["finding_id"]: f for f in findings}

    def known_ids(self):
        return set(self.by_id) | set(self.evidence)

    def known_advisories(self):
        s = set()
        for f in self.findings:
            if f["category"] == "vulnerability":
                s.add(f["advisory_id"]); s.update(f.get("aliases", []))
        return s

    def save(self):
        data = {k: getattr(self, k) for k in ("stage", "changes", "gaps", "risk", "investigations", "priorities",
                                              "proposals", "approvals", "validations", "llm_mode",
                                              "risk_summary", "escalations", "baseline_smoke", "identity")}
        data["run_config"] = self.run_config
        data["repo"] = str(self.repo)
        data["candidates"] = [{k: v for k, v in c.items() if k != "files"} for c in self.candidates]
        data["evidence"] = self.evidence
        (self.out / "run_state.json").write_text(json.dumps(data, indent=2, default=str))
        (self.out / "candidates_files.json").write_text(json.dumps(
            {c["candidate_id"]: {p: new for p, (old, new) in c["files"].items()} for c in self.candidates}))
