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
from ..policies import load as load_policy

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
    ind, _ = run_detectors(path, inv, comps, history=0) if comps else ([], [])
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


def smoke_profile(state):
    """The runtime check for this repo: a named profile, a plain Docker build, or None (static only)."""
    names = {p.get("name") for p in (state.inventory or {}).get("projects", [])}
    for prof in load_policy("smoke_profiles.json")["profiles"]:
        if names & set(prof["match"].get("project_names", [])):
            return prof
    if (state.repo / "Dockerfile").exists():
        return {"name": "docker build", "build_only": True}
    return None


def runtime_check(work, project, prof):
    """Returns (steps, ok). ok is None when no runtime check applies."""
    if prof is None:
        return [{"name": "runtime_check", "rc": 0, "detail": "no Dockerfile or smoke profile: static validation only"}], None
    if prof.get("build_only"):
        r = _run(["docker", "build", "--pull=false", "-t", f"{project}:check", "."], cwd=work, timeout=1200)
        r["name"] = "docker_build"
        _run(["docker", "image", "rm", "-f", f"{project}:check"], timeout=120)
        return [r], r["rc"] == 0
    steps = []
    up = _run(["docker", "compose", "-p", project, "up", "-d", "--build"], cwd=work, timeout=900)
    up["name"] = "build_and_boot"; steps.append(up)
    try:
        if up["rc"] != 0:
            return steps, False
        ok = True
        for i, chk in enumerate(prof["checks"]):
            status, loc = None, None
            for _ in range(40 if i == 0 else 1):        # first check also waits for the app to come up
                try:
                    body = urllib.parse.urlencode(chk["form"]) if chk.get("form") else None
                    status, loc, _ = _http(chk["method"], chk["path"], body, prof.get("port", 80))
                    if status in chk["expect_status"]:
                        break
                except OSError:
                    pass
                time.sleep(3)
            passed = status in chk["expect_status"] and (loc or "").endswith(chk.get("expect_location_endswith", ""))
            steps.append({"name": f"smoke_{chk['method'].lower()}_{chk['path'].strip('/') or 'root'}",
                          "rc": 0 if passed else 1, "detail": f"{chk['method']} {chk['path']} -> {status}"
                          + (f" Location={loc}" if loc else "")})
            if not passed:
                ok = False
                logs = _run(["docker", "compose", "-p", project, "logs", "--tail", "30"], cwd=work)
                steps.append({"name": "app_logs", "rc": 0, "log_tail": logs["log_tail"]})
                break
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

    for pj in [p for p in cand["files"] if p.endswith("package.json")] if cand.get("needs_lockfile_regen") else []:
        app_dir = (work / pj).parent.resolve()
        r = _run(["docker", "run", "--rm", "--memory", "2g", "--user", "1000:1000", "-e", "HOME=/tmp",
                  "-v", f"{app_dir}:/app", "-w", "/app", "node:22-alpine",
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
        s_steps, smoke_ok = runtime_check(work, project, smoke_profile(state))
        steps += s_steps
    if summary is not None:
        summary["smoke"] = {"baseline_ok": baseline_ok, "after_ok": smoke_ok}
    if summary is not None:
        summary["runtime_check"] = (smoke_profile(state) or {}).get("name", "static only")
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
    """Run the same runtime check on the unmodified app, so a failure later means something."""
    prof = smoke_profile(state)
    work = _copy(state.repo, state.out / "validation" / "baseline_app")
    steps, ok = runtime_check(work, "gvbaseline", prof)
    state.log("validation_agent", "baseline_smoke", {"ok": ok, "profile": (prof or {}).get("name", "static only")})
    return {"ok": True if ok is None else ok, "profile": (prof or {}).get("name", "static only"), "steps": steps}
