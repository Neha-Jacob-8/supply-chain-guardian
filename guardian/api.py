"""HTTP API for the dashboard (FastAPI). Serves the latest run in one output directory.

  guardian serve [--out output] [--port 8000]

Reads:  /api/status /api/overview /api/matrix /api/graph /api/sbom /api/findings[/{id}]
        /api/coverage /api/changes /api/investigations /api/priorities /api/proposals[/{id}]
        /api/validations /api/applied /api/remediation.patch /api/evidence/{id} /api/events /api/report(.md|.json)
Writes: POST /api/runs (start a run), POST /api/proposals/{id}/approval, POST /api/resume
Runs execute in a background thread, one at a time. Approval is the only way a fix reaches validation.
"""
import json
import threading
import time
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

WEB = Path(__file__).parent / "web"


class RunRequest(BaseModel):
    target: str                       # local path, owner/repo, or https://github.com/<owner>/<repo>
    llm: str = "auto"                 # auto | gemini | claude | none
    offline: bool = False
    smoke: bool = True
    auto_merge: bool = False


class ResumeRequest(BaseModel):
    llm: str = "auto"
    offline: bool = False
    smoke: bool = True


class ApprovalRequest(BaseModel):
    decision: str                     # approve | reject
    comment: str = ""


class AutoMitigateRequest(BaseModel):
    llm: str = "auto"
    auto_merge: bool = True
    save_test: bool = False


class BaselineSignRequest(BaseModel):
    key: str | None = None
    signer: str = "developer (dashboard)"


class WaiveFindingRequest(BaseModel):
    reason: str = "Verified safe / accepted risk by human reviewer"
    action: str = "waive"             # waive | unwaive
    by: str = "human reviewer (dashboard)"


class GitHubPRRequest(BaseModel):
    app_id: str | None = None
    pem_path: str | None = None
    installation_id: str | None = None


def create_app(out_dir="output"):
    out = Path(out_dir)
    app = FastAPI(title="Supply Chain Guardian API", version="0.2.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    job = {"thread": None, "kind": None, "started": None, "error": None}
    lock = threading.Lock()

    def load(name, default=None):
        p = out / name
        if not p.exists():
            if default is not None:
                return default
            raise HTTPException(404, f"{name} not available yet; start a run first")
        return json.loads(p.read_text())

    def running():
        return job["thread"] is not None and job["thread"].is_alive()

    def start(kind, fn):
        with lock:
            if running():
                raise HTTPException(409, f"a {job['kind']} is already running")

            def wrapped():
                try:
                    fn()
                    job["error"] = None
                except Exception as e:  # surfaced via /api/status
                    job["error"] = f"{type(e).__name__}: {e}"
            job.update(kind=kind, started=time.time(), error=None, phase=None, thread=threading.Thread(target=wrapped, daemon=True))
            job["thread"].start()
        return {"started": kind}

    # ---------- control ----------

    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/api/status")
    def status():
        st = load("run_state.json", {})
        approvals = st.get("approvals", {})
        return {"running": running(), "job": job["kind"], "phase": job.get("phase"), "error": job["error"],
                "stage": st.get("stage"), "repo": st.get("repo"), "target": job.get("repo"), "llm_mode": st.get("llm_mode"),
                "approvals": Counter(v["status"] for v in approvals.values())}

    @app.post("/api/runs")
    def start_run(req: RunRequest):
        from .agents.orchestrator import Orchestrator
        from .ingestion import parse_github_url, resolve_target
        target = req.target.strip()
        if not Path(target).is_dir():
            try:
                parse_github_url(target)           # validate now; clone in the background job
            except ValueError as e:
                raise HTTPException(400, str(e))

        def job_fn():
            job["phase"] = "cloning"
            repo = str(resolve_target(target))
            job["repo"], job["phase"] = repo, "running"
            Orchestrator(repo, out, req.llm, req.offline, smoke=req.smoke).run(
                approve="all" if req.auto_merge else None,
                interactive=False,
                auto_merge=req.auto_merge,
            )
        job["repo"] = target
        return start("run", job_fn) | {"target": target}

    @app.post("/api/resume")
    def resume(req: ResumeRequest):
        from .agents.orchestrator import Orchestrator
        st = load("run_state.json")
        if not any(v["status"] == "approved" for v in st.get("approvals", {}).values()):
            raise HTTPException(400, "no proposal is approved")
        o = Orchestrator(st["repo"], out, req.llm, req.offline, smoke=req.smoke)
        return start("resume", o.resume)

    @app.post("/api/proposals/{candidate_id}/approval")
    def approve(candidate_id: str, req: ApprovalRequest):
        if running():
            raise HTTPException(409, "wait for the current job to finish")
        if req.decision not in ("approve", "reject"):
            raise HTTPException(400, "decision must be approve or reject")
        f = out / "run_state.json"
        st = load("run_state.json")
        proposal = next((p for p in st["proposals"] if p["candidate_id"] == candidate_id), None)
        if proposal is None:
            raise HTTPException(404, "unknown proposal")
        if st["approvals"].get(candidate_id, {}).get("status") == "superseded":
            raise HTTPException(409, "fixes were applied since this proposal was made; re-run the analysis")
        st["approvals"][candidate_id] = {"status": "approved" if req.decision == "approve" else "rejected",
                                         "by": "human reviewer (dashboard)", "comment": req.comment,
                                         "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                         "repo_identity": st.get("identity"),
                                         "diff_sha256": proposal.get("diff_sha256"),
                                         "base_files_sha256": proposal.get("base_files_sha256", {})}
        f.write_text(json.dumps(st, indent=2))
        with open(out / "events.jsonl", "a") as ev:
            ev.write(json.dumps({"t": time.time(), "stage": "awaiting_approval", "actor": "human", "kind": "approval",
                                 "detail": {"candidate_id": candidate_id, "status": st["approvals"][candidate_id]["status"]}}) + "\n")
        return st["approvals"][candidate_id]

    @app.post("/api/auto-mitigate")
    def auto_mitigate_all(req: AutoMitigateRequest):
        if running():
            raise HTTPException(409, "wait for the current job to finish")
        from .agents.orchestrator import Orchestrator
        st = load("run_state.json")
        repo = st.get("repo")
        if not repo or not Path(repo).is_dir():
            raise HTTPException(400, "no active repository run")

        def job_fn():
            job["repo"], job["phase"] = repo, "auto-mitigating"
            o = Orchestrator(repo, out, req.llm, offline=bool((st.get("run_config") or {}).get("offline")))
            o.run(approve="all", interactive=False, auto_merge=req.auto_merge)
        return start("auto-mitigate", job_fn)

    @app.post("/api/proposals/{candidate_id}/auto-mitigate")
    def auto_mitigate(candidate_id: str, req: AutoMitigateRequest):
        if running():
            raise HTTPException(409, "wait for the current job to finish")
        from .agents.llm import get_llm
        from .agents.state import RunState
        from .models import Component
        from .validation.auto_mitigate import auto_mitigate_candidate

        st_data = load("run_state.json")
        files_map = load("candidates_files.json", {})
        cand = next((c for c in st_data.get("candidates", []) if c["candidate_id"] == candidate_id), None)
        if cand is None:
            raise HTTPException(404, "unknown candidate")
        cand = dict(cand)
        # Reconstruct (old, new) tuples for candidate files
        repo_p = Path(st_data["repo"])
        c_files = {}
        for rel_p, new_txt in (files_map.get(candidate_id) or {}).items():
            old_txt = (repo_p / rel_p).read_text(encoding="utf-8") if (repo_p / rel_p).exists() else ""
            c_files[rel_p] = (old_txt, new_txt)
        cand["files"] = c_files

        state_obj = RunState(repo_p, out)
        for c_dict in load("components.json", []):
            state_obj.comps[c_dict["component_id"]] = Component(**c_dict)
        try:
            llm_inst = get_llm(req.llm)
        except Exception:
            llm_inst = None

        res = auto_mitigate_candidate(state_obj, cand, llm=llm_inst, auto_merge=req.auto_merge, save_generated_test=req.save_test)
        st_data["approvals"][candidate_id] = {
            "status": "approved",
            "by": "auto-mitigate (dashboard)",
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "repo_identity": st_data.get("identity"),
            "diff_sha256": cand.get("diff_sha256"),
        }
        st_data["validations"] = [v for v in st_data.get("validations", []) if v["candidate_id"] != candidate_id] + [res]
        (out / "run_state.json").write_text(json.dumps(st_data, indent=2, default=str))
        return res

    @app.get("/api/integrity")
    def integrity_status():
        from .integrity import run_watch, verify_ledger
        st = load("run_state.json", {})
        repo = st.get("repo")
        if not repo or not Path(repo).is_dir():
            return {"has_baseline": False, "has_ledger": False}
        repo_p = Path(repo)
        has_base = (repo_p / ".guardian" / "baseline.json").exists()
        has_led = (repo_p / ".guardian" / "ledger.jsonl").exists()
        anomalies = []
        if has_base:
            try:
                anomalies = run_watch(repo_p, interval=0, rounds=1, full_check_every=1)
            except Exception as e:
                anomalies = [{"status": "error", "detail": str(e)}]
        led_ok, led_msg, led_info = verify_ledger(repo_p) if has_led else (True, "No ledger yet", None)
        return {
            "repo": str(repo_p),
            "has_baseline": has_base,
            "baseline_ok": has_base and len(anomalies) == 0,
            "anomalies": anomalies,
            "has_ledger": has_led,
            "ledger_ok": led_ok,
            "ledger_message": led_msg,
            "ledger_detail": led_info,
        }

    @app.post("/api/integrity/baseline")
    def sign_baseline(req: BaselineSignRequest):
        from .integrity import create_baseline
        st = load("run_state.json", {})
        repo = st.get("repo")
        if not repo or not Path(repo).is_dir():
            raise HTTPException(400, "No active repository to baseline")
        doc = create_baseline(repo, signing_key=req.key, signer=req.signer)
        return {"ok": True, "files": len(doc.get("files", {})), "hmac": doc.get("hmac"), "created_at": doc.get("created_at")}

    # ---------- reads ----------

    @app.get("/api/overview")
    def overview():
        comps, findings = load("components.json"), load("findings.json")
        st = load("run_state.json", {})
        vuln = [f for f in findings if f["category"] == "vulnerability"]
        return {
            "repo": st.get("repo"), "stage": st.get("stage"), "llm_mode": st.get("llm_mode"),
            "components": len(comps), "relationship": Counter(c["relationship"] for c in comps),
            "scope": Counter(c["scope"] for c in comps), "risk_status": Counter(c["risk_status"] for c in comps),
            "advisories": len(vuln), "indicators": len(findings) - len(vuln),
            "by_category": Counter(f["category"] for f in findings),
            "by_risk_severity": Counter((f.get("risk") or {}).get("severity", "UNSCORED") for f in findings),
            "coverage_gaps": len(load("coverage_gaps.json", [])),
            "proposals": len(st.get("proposals", [])), "validations": Counter(v["verdict"] for v in st.get("validations", [])),
        }

    @app.get("/api/matrix")
    def matrix(risk_status: str = "", scope: str = "", q: str = "", limit: int = Query(2000, le=5000)):
        rows = load("matrix.json")
        rows = [r for r in rows if (not risk_status or r["risk_status"] == risk_status) and
                (not scope or r["scope"] == scope) and (not q or q.lower() in r["name"].lower())]
        return {"total": len(rows), "rows": rows[:limit]}

    @app.get("/api/inventory")
    def inventory():
        return load("inventory.json", {})

    @app.get("/api/graph")
    def graph():
        return load("graph.json")

    @app.get("/api/sbom")
    def sbom():
        return load("sbom.cdx.json")

    @app.get("/api/findings")
    def findings(category: str = "", severity: str = "", rule_id: str = "", component: str = "",
                 limit: int = Query(500, le=5000)):
        fs = load("findings.json")
        fs = [f for f in fs if (not category or f["category"] == category) and (not rule_id or f["rule_id"] == rule_id)
              and (not severity or (f.get("risk") or {}).get("severity", f.get("severity")) == severity)
              and (not component or component in (f.get("component_id") or ""))]
        fs.sort(key=lambda f: -((f.get("risk") or {}).get("score") or 0))
        return {"total": len(fs), "findings": fs[:limit]}

    @app.get("/api/findings/{finding_id:path}")
    def finding(finding_id: str):
        for f in load("findings.json"):
            if f["finding_id"] == finding_id:
                return f
        raise HTTPException(404, "unknown finding")

    @app.post("/api/findings/{finding_id:path}/waive")
    def waive(finding_id: str, req: WaiveFindingRequest):
        from .integrity import unwaive_finding, waive_finding
        st = load("run_state.json", {})
        repo = st.get("repo") or load("inventory.json", {}).get("repo")
        if not repo or not Path(repo).is_dir():
            raise HTTPException(400, "No active repository")
        fs = load("findings.json")
        target = next((f for f in fs if f["finding_id"] == finding_id), None)
        if target is None:
            raise HTTPException(404, "unknown finding")
        if req.action == "unwaive":
            unwaive_finding(repo, finding_id, by=req.by)
            target.pop("waived", None)
            target.pop("waiver", None)
        else:
            w = waive_finding(repo, finding_id, reason=req.reason, by=req.by)
            target["waived"] = True
            target["waiver"] = w
        (out / "findings.json").write_text(json.dumps(fs, indent=2))
        with open(out / "events.jsonl", "a") as ev:
            ev.write(json.dumps({"t": time.time(), "stage": st.get("stage", "done"), "actor": "human",
                                 "kind": "waive_finding", "detail": {"finding_id": finding_id, "action": req.action, "reason": req.reason}}) + "\n")
        return target

    @app.get("/api/coverage")
    def coverage():
        return load("coverage_gaps.json", [])

    @app.get("/api/changes")
    def changes():
        return load("lockfile_changes.json", [])

    for key in ("investigations", "priorities", "validations", "escalations", "applied"):
        app.add_api_route(f"/api/{key}", (lambda k: lambda: load("run_state.json", {}).get(k, []))(key), methods=["GET"])

    @app.get("/api/proposals")
    def proposals():
        st = load("run_state.json", {})
        from .remediation.apply import eligible
        verdicts = {v["candidate_id"]: v["verdict"] for v in st.get("validations", [])}
        applicable = {v["candidate_id"] for v in st.get("validations", []) if eligible(v)}
        applied = {a["candidate_id"]: a for a in st.get("applied", [])}
        return [{k: v for k, v in p.items() if k != "diff"} | {"approval": st["approvals"].get(p["candidate_id"]),
                                                              "verdict": verdicts.get(p["candidate_id"]),
                                                              "applied": applied.get(p["candidate_id"]),
                                                              "applicable": p["candidate_id"] in applicable}
                for p in st.get("proposals", [])]

    @app.get("/api/proposals/{candidate_id}")
    def proposal(candidate_id: str):
        st = load("run_state.json")
        for p in st.get("proposals", []):
            if p["candidate_id"] == candidate_id:
                return p | {"approval": st["approvals"].get(candidate_id),
                            "validation": next((v for v in st.get("validations", []) if v["candidate_id"] == candidate_id), None)}
        raise HTTPException(404, "unknown proposal")

    @app.get("/api/evidence/{evidence_id}")
    def evidence(evidence_id: str):
        p = out / "evidence" / f"{evidence_id}.json"
        if not evidence_id.startswith("EV-") or not p.exists():
            raise HTTPException(404, "unknown evidence id")
        return json.loads(p.read_text())

    @app.get("/api/events")
    def events(since: float = 0):
        p = out / "events.jsonl"
        if not p.exists():
            return []
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        return [r for r in rows if r["t"] > since][-500:]

    @app.get("/api/report.md", response_class=PlainTextResponse)
    def report_md():
        p = out / "report.md"
        if not p.exists():
            raise HTTPException(404, "report not available yet")
        return p.read_text()

    @app.get("/api/remediation.patch", response_class=PlainTextResponse)
    def remediation_patch():
        p = out / "remediation.patch"
        if not p.exists():
            raise HTTPException(404, "no fix has been applied yet")
        return p.read_text()

    @app.get("/api/report.json")
    def report_json():
        return load("report.json")

    @app.get("/api/report.pdf")
    def report_pdf():
        from .reporting.pdf import markdown_to_pdf_bytes
        pdf_path = out / "report.pdf"
        if pdf_path.exists():
            data = pdf_path.read_bytes()
        else:
            md_path = out / "report.md"
            if not md_path.exists():
                raise HTTPException(404, "report not available yet")
            data = markdown_to_pdf_bytes(md_path.read_text())
        return Response(
            content=data,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="guardian-security-report.pdf"'},
        )

    @app.post("/api/report/pr")
    def raise_github_pr(req: GitHubPRRequest):
        if running():
            raise HTTPException(409, "wait for the current job to finish")
        from .remediation.github_pr import create_remediation_pr
        st = load("run_state.json", {})
        repo = st.get("repo") or load("inventory.json", {}).get("repo")
        if not repo or not Path(repo).is_dir():
            raise HTTPException(400, "No active repository found")
        try:
            res = create_remediation_pr(
                repo, out, app_id=req.app_id, pem_path=req.pem_path, installation_id=req.installation_id
            )
        except Exception as e:
            raise HTTPException(400, str(e))
        st["pull_request"] = res
        (out / "run_state.json").write_text(json.dumps(st, indent=2, default=str))
        if (out / "report.json").exists():
            rj = json.loads((out / "report.json").read_text())
            rj["pull_request"] = res
            (out / "report.json").write_text(json.dumps(rj, indent=2, default=str))
        with open(out / "events.jsonl", "a") as ev:
            ev.write(json.dumps({
                "t": time.time(), "stage": "report", "actor": "github_app",
                "kind": "pull_request_created", "detail": res,
            }) + "\n")
        return res

    if WEB.is_dir():
        app.mount("/ui", StaticFiles(directory=WEB, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        def root():
            return RedirectResponse("/ui/")
    return app


def serve(out_dir="output", host="127.0.0.1", port=8000):
    import uvicorn
    from .config import load_dotenv
    load_dotenv()
    uvicorn.run(create_app(out_dir), host=host, port=port)
