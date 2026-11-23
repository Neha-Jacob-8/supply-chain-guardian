"""Independent Validation agent (deterministic; no LLM authority over the verdict).

For one approved candidate:
  1. copy the repo (no .git, no node_modules) and apply the candidate's file changes
  2. if package.json changed: regenerate package-lock.json in Docker (--ignore-scripts, lockfile v2)
  3. rescan the patched tree with the same tools, and compare with a baseline rescan of the original
     made by this validator (not Block 3's earlier output) -> resolved / remaining / introduced
  4. optional: build + boot the app with docker compose and run a login smoke test
Verdict: verified | partial | failed. Target code only ever runs inside containers.
"""
import hashlib
import http.client
import json
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

from ..discovery import build_inventory
from ..intel.detectors import run_detectors
from ..intel.osv import scan_components
from ..intel.registry import registry_metadata

SMOKE_USER, SMOKE_PASS = "user1", "User1_123"   # NodeGoat's seeded demo account (artifacts/db-reset.js)
SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _run(cmd, cwd=None, timeout=900):
    t = time.time()
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return {"cmd": " ".join(cmd), "rc": r.returncode, "seconds": round(time.time() - t, 1),
            "log_tail": (r.stdout + r.stderr)[-2500:]}


def _key(f, comps):
    c = comps.get(f.get("component_id")) if f.get("component_id") else None
    subject = c.name if c else f["evidence"].get("path")
    return f"{f['rule_id']}|{f.get('advisory_id', '')}|{subject}"


def scan_tree(path, cache_dir):
    inv = build_inventory(path)
    comps = inv["components"]
    findings = scan_components(comps, cache_dir) if comps else []
    ind, _ = run_detectors(path, inv["lockfile"], comps, history=0) if comps else ([], [])
    return comps, findings + ind


def _copy(repo, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(repo, dst, ignore=shutil.ignore_patterns(".git", "node_modules"))
    return dst


def baseline(state):
    if getattr(state, "_baseline", None) is None:
        work = _copy(state.repo, state.out / "validation" / "baseline")
        comps, findings = scan_tree(work, state.out / "cache" / "osv")
        state._baseline = (comps, findings, {_key(f, comps): f for f in findings})
        state.log("validation_agent", "baseline_rescan", {"findings": len(findings)})
    return state._baseline


def _http(method, path, body=None, port=4000):
    conn = http.client.HTTPConnection("localhost", port, timeout=10)
    headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}
    conn.request(method, path, body=body, headers=headers)
    r = conn.getresponse()
    return r.status, r.getheader("Location"), r.read()[:200]


def smoke_test(work, project):
    steps = []
    up = _run(["docker", "compose", "-p", project, "up", "-d", "--build"], cwd=work, timeout=900)
    up["name"] = "build_and_boot"; steps.append(up)
    try:
        if up["rc"] != 0:
            return steps, False
        status = None
        for _ in range(40):
            try:
                status, _, _ = _http("GET", "/login")
                if status == 200:
                    break
            except OSError:
                pass
            time.sleep(3)
        steps.append({"name": "smoke_get_login", "rc": 0 if status == 200 else 1, "detail": f"GET /login -> {status}"})
        if status != 200:
            logs = _run(["docker", "compose", "-p", project, "logs", "--tail", "30", "web"], cwd=work)
            steps.append({"name": "app_logs", "rc": 0, "log_tail": logs["log_tail"]})
            return steps, False
        body = urllib.parse.urlencode({"userName": SMOKE_USER, "password": SMOKE_PASS})
        st, loc, _ = _http("POST", "/login", body)
        ok = st in (301, 302, 303) and (loc or "").endswith("/dashboard")
        steps.append({"name": "smoke_login", "rc": 0 if ok else 1, "detail": f"POST /login -> {st} Location={loc}"})
        return steps, ok
    finally:
        _run(["docker", "compose", "-p", project, "down", "-v", "--remove-orphans"], cwd=work, timeout=300)


def validate(state, cand, smoke=True, baseline_ok=True):
    cid = cand["candidate_id"]
    work = _copy(state.repo, state.out / "validation" / cid)
    steps = []
    for path, (old, new) in cand["files"].items():
        cur = (work / path).read_text() if (work / path).exists() else ""
        if cur != old:
            steps.append({"name": "apply_patch", "rc": 1, "detail": f"{path} changed since the candidate was built"})
            return _result(state, cand, steps, None, "failed")
        (work / path).write_text(new)
    steps.append({"name": "apply_patch", "rc": 0, "detail": f"{len(cand['files'])} file(s)"})

    if cand.get("needs_lockfile_regen"):
        r = _run(["docker", "run", "--rm", "--memory", "2g", "--user", "1000:1000", "-e", "HOME=/tmp",
                  "-v", f"{work.resolve()}:/app", "-w", "/app", "node:22-alpine",
                  "npm", "install", "--package-lock-only", "--ignore-scripts", "--lockfile-version", "2",
                  "--no-audit", "--no-fund"], timeout=900)
        r["name"] = "regenerate_lockfile"; steps.append(r)
        if r["rc"] != 0:
            return _result(state, cand, steps, None, "failed")

    b_comps, b_findings, b_keys = baseline(state)
    a_comps, a_findings = scan_tree(work, state.out / "cache" / "osv")
    a_keys = {_key(f, a_comps): f for f in a_findings}
    steps.append({"name": "rescan", "rc": 0, "detail": f"{len(a_findings)} findings after vs {len(b_findings)} before"})

    # targets: what the candidate claimed to close
    targets = [state.by_id[i] for i in cand["closes"] if i in state.by_id]
    resolved, remaining = [], []
    for f in targets:
        if f["evidence"].get("source") == "git":      # history finding: check the lockfile now matches the registry
            c = state.comps.get(f["component_id"])
            meta = registry_metadata(c.name, c.version, state.out / "cache" / "registry") if c else None
            ac = next((x for x in a_comps.values() if c and x.name == c.name and x.version == c.version), None)
            ok = bool(meta and ac and ac.integrity == meta["dist"]["integrity"] and ac.source_url == meta["dist"]["tarball"])
        else:
            ok = _key(f, state.comps) not in a_keys
        (resolved if ok else remaining).append(f["finding_id"])
    introduced = [k for k in a_keys if k not in b_keys]
    intro_high = [k for k in introduced if SEV.get(a_keys[k].get("severity"), 0) >= 3]
    summary = {
        "before": {"findings": len(b_findings), "vulnerable_components": sum(c.risk_status == "vulnerable" for c in b_comps.values())},
        "after": {"findings": len(a_findings), "vulnerable_components": sum(c.risk_status == "vulnerable" for c in a_comps.values())},
        "sbom_diff": {"added": sorted(set(a_comps) - set(b_comps))[:50], "removed": sorted(set(b_comps) - set(a_comps))[:50],
                      "added_count": len(set(a_comps) - set(b_comps)), "removed_count": len(set(b_comps) - set(a_comps))},
        "targets": len(targets), "resolved": resolved, "remaining": remaining,
        "introduced": introduced[:50], "introduced_count": len(introduced), "introduced_high": intro_high[:20],
    }

    smoke_ok = None
    if smoke:
        project = "gv" + hashlib.sha1(cid.encode()).hexdigest()[:8]
        s_steps, smoke_ok = smoke_test(work, project)
        steps += s_steps
    if summary is not None:
        summary["smoke"] = {"baseline_ok": baseline_ok, "after_ok": smoke_ok}
    if smoke and smoke_ok is False and baseline_ok:
        verdict = "failed"                      # the fix broke a working app
    elif smoke and smoke_ok is False:
        verdict = "partial"                     # app was already broken and still is
    elif remaining or intro_high or not targets:
        verdict = "partial"
    else:
        verdict = "verified"
    return _result(state, cand, steps, summary, verdict)


def _result(state, cand, steps, summary, verdict):
    res = {"candidate_id": cand["candidate_id"], "summary": cand["summary"], "verdict": verdict,
           "steps": steps, "comparison": summary, "validated_by": "validation_agent (deterministic)"}
    state.log("validation_agent", "verdict", {"candidate_id": cand["candidate_id"], "verdict": verdict})
    return res


def baseline_smoke(state):
    """Prove the smoke test passes on the unmodified app, so a failure later means something."""
    work = _copy(state.repo, state.out / "validation" / "baseline_app")
    steps, ok = smoke_test(work, "gvbaseline")
    state.log("validation_agent", "baseline_smoke", {"ok": ok})
    return {"ok": ok, "steps": steps}
