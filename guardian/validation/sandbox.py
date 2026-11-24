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
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from ..discovery import build_inventory
from ..intel.detectors import run_detectors
from ..intel.osv import scan_components
from ..intel.registry import registry_metadata
from ..policies import load as load_policy

SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class ValidationPolicyError(RuntimeError):
    """Raised when a target asks the validator for unsafe host/container access."""


def _compose_files(work):
    root = Path(work)
    ignored = {".git", "node_modules", ".venv", "venv", "target"}
    return sorted(p for p in root.rglob("*compose*.y*ml")
                  if not ignored.intersection(p.relative_to(root).parts))


def _outside_repo(work, source, base=None):
    """Return true for a bind source that can escape the validation copy."""
    if not isinstance(source, str) or not source:
        return False
    source = source.strip()
    # Interpolation is intentionally rejected: the validator cannot prove where
    # ${PWD}, ${HOME}, or another host-provided value resolves.
    if "$" in source or source.startswith("~") or "docker.sock" in source:
        return True
    candidate = Path(source)
    if candidate.is_absolute():
        return True
    try:
        return not ((Path(base) if base else Path(work)) / candidate).resolve().is_relative_to(Path(work).resolve())
    except (OSError, ValueError):
        return True


def _minimal_yaml_load(text):
    """Minimal indentation-based YAML subset parser used when PyYAML is not installed."""
    if yaml is not None:
        return yaml.safe_load(text) or {}
    root = {}
    # stack entries: (indent, container_dict, last_key)
    stack = [(-1, root, None)]
    for raw in text.splitlines():
        s = raw.split("#", 1)[0].rstrip()
        if not s.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = s.strip()
        while len(stack) > 1 and (indent < stack[-1][0] or (indent == stack[-1][0] and not (stripped.startswith("- ") and isinstance(stack[-1][1], list)))):
            stack.pop()
        _, parent, last_key = stack[-1]
        stripped = s.strip()
        if stripped.startswith("- "):
            val = stripped[2:].strip().strip("'\"")
            if len(stack) > 1 and isinstance(stack[-2][1], dict) and stack[-2][2] is not None and parent == {}:
                p_dict, p_key = stack[-2][1], stack[-2][2]
                p_dict[p_key] = [val]
                stack[-1] = (indent, p_dict[p_key], None)
            elif isinstance(parent, list):
                parent.append(val)
        elif ":" in stripped:
            k, _, v = stripped.partition(":")
            k, v = k.strip(), v.strip()
            if isinstance(parent, dict):
                if not v:
                    parent[k] = {}
                    stack[-1] = (stack[-1][0], parent, k)
                    stack.append((indent, parent[k], None))
                else:
                    vl = v.strip("'\"")
                    parent[k] = True if vl.lower() == "true" else False if vl.lower() == "false" else vl
                    stack[-1] = (stack[-1][0], parent, k)
    return root


def compose_policy_violations(work):
    """Return unsafe Compose constructs before any target container is started.

    Runtime execution is only enabled for an explicitly trusted profile, but this
    policy is still enforced as a second fail-closed boundary.
    """
    violations = []
    for path in _compose_files(work):
        try:
            data = _minimal_yaml_load(path.read_text()) or {}
        except Exception as exc:
            violations.append(f"{path.name}: invalid YAML ({type(exc).__name__})")
            continue
        for service, cfg in (data.get("services") or {}).items():
            if not isinstance(cfg, dict):
                continue
            for field in ("privileged", "network_mode", "pid", "ipc", "userns_mode"):
                value = cfg.get(field)
                if value is True or value == "host":
                    violations.append(f"{path.name}:{service} uses unsafe {field}={value!r}")
            if cfg.get("cap_add") or cfg.get("devices") or cfg.get("security_opt"):
                violations.append(f"{path.name}:{service} requests capabilities/devices/security options")
            for item in cfg.get("volumes") or []:
                if isinstance(item, str):
                    source = item.split(":", 1)[0]
                else:
                    item = item or {}
                    source = item.get("source", "")
                    if item.get("type") not in (None, "bind"):
                        source = ""  # named/managed volumes do not expose the host
                if _outside_repo(work, source, path.parent):
                    violations.append(f"{path.name}:{service} mounts host path {source!r}")
            build = cfg.get("build")
            context = build.get("context") if isinstance(build, dict) else build
            if _outside_repo(work, context, path.parent):
                violations.append(f"{path.name}:{service} builds from context outside the repository")
            for field in ("env_file", "secrets", "configs"):
                entries = cfg.get(field) or []
                if isinstance(entries, (str, dict)):
                    entries = [entries]
                for entry in entries:
                    source = entry if isinstance(entry, str) else (entry or {}).get("file", "")
                    if _outside_repo(work, source, path.parent):
                        violations.append(f"{path.name}:{service} references host file {source!r} via {field}")
    return violations


def _run(cmd, cwd=None, timeout=900):
    t = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        rc, output = r.returncode, r.stdout + r.stderr
    except FileNotFoundError as exc:
        rc, output = 127, str(exc)
    except subprocess.TimeoutExpired as exc:
        rc = 124
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        output = stdout + stderr + " command timed out"
    return {"cmd": " ".join(cmd), "rc": rc, "seconds": round(time.time() - t, 1),
            "log_tail": output[-2500:]}


def _compose_cmd():
    """Select the v2 Compose executable without requiring a user config edit."""
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return ["docker", "compose"]


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
    """Return a trusted runtime profile, or None for static-only validation.

    A repository name alone is not trusted: the configured remote identity must
    match the profile. Generic Dockerfiles/Compose files are never executed by
    default because they are untrusted code.
    """
    names = {p.get("name") for p in (state.inventory or {}).get("projects", [])}
    for prof in load_policy("smoke_profiles.json")["profiles"]:
        allowed = set(prof.get("trusted_remote_ids", []))
        remote_id = (getattr(state, "identity", {}) or {}).get("remote_id")
        if names & set(prof["match"].get("project_names", [])) and (not allowed or remote_id in allowed):
            return prof
    return None


def runtime_check(work, project, prof):
    """Returns (steps, ok). ok is None when no runtime check applies."""
    if prof is None:
        return [{"name": "runtime_check", "rc": 0, "detail": "no trusted runtime profile: static only; runtime checks skipped"}], None
    violations = compose_policy_violations(work) if prof.get("compose") else []
    if violations:
        return [{"name": "sandbox_policy", "rc": 1, "detail": "; ".join(violations[:8])}], False
    if prof.get("build_only"):
        r = _run(["docker", "build", "--pull=false", "-t", f"{project}:check", "."], cwd=work, timeout=1200)
        r["name"] = "docker_build"
        _run(["docker", "image", "rm", "-f", f"{project}:check"], timeout=120)
        return [r], r["rc"] == 0
    steps = []
    compose = _compose_cmd()
    up = _run([*compose, "-p", project, "up", "-d", "--build"], cwd=work, timeout=900)
    up["name"] = "build_and_boot"; steps.append(up)
    try:
        if up["rc"] != 0:
            return steps, False
        for test in prof.get("test_commands", []):
            service = test["service"]
            cmd = [*compose, "-p", project, "exec", "-T"]
            if test.get("user"):
                cmd += ["--user", str(test["user"])]
            cmd += [service, *test["command"]]
            result = _run(cmd, cwd=work, timeout=test.get("timeout", 900))
            result["name"] = test.get("name", "test")
            steps.append(result)
            if result["rc"] != 0:
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
                logs = _run([*compose, "-p", project, "logs", "--tail", "30"], cwd=work)
                steps.append({"name": "app_logs", "rc": 0, "log_tail": logs["log_tail"]})
                break
        return steps, ok
    finally:
        _run([*compose, "-p", project, "down", "-v", "--remove-orphans"], cwd=work, timeout=300)


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
                  "--mount", f"type=bind,src={app_dir},dst=/app", "-w", "/app", "node:22-alpine",
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
        summary["runtime_validated"] = smoke_ok is not None
    if summary is not None:
        summary["runtime_check"] = (smoke_profile(state) or {}).get("name", "static only")
    if not smoke or smoke_ok is None:
        verdict = "partial"
    elif smoke_ok is False and baseline_ok:
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
    return {"ok": ok, "profile": (prof or {}).get("name", "static only"),
            "runtime_validated": ok is not None, "steps": steps}
