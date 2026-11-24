"""Read-only tools the agents may call. Every call is stored as evidence (EV-xxxx) the agent can cite.

None of these execute target code, write to the repo, or reach anything but the npm registry
and OSV cache. Secrets are redacted from file excerpts before the LLM sees them.
"""
import json
import re
import subprocess
from pathlib import Path

from ..discovery.lockfile import pkg_name
from ..intel.registry import registry_metadata
from ..intel.risk import import_usage

TOOLS = {}
MAX_CHARS = 8000
# Redaction is intentionally conservative about field names but broad about common
# credential encodings. Repository excerpts are untrusted input and may be sent to
# an external model, so quoted and unquoted values must both be removed.
SECRET_ASSIGNMENT = re.compile(
    r"(?ix)(?P<name>\b(?:zap)?api[_-]?key\b|\b(?:access[_-]?key|secret(?:[_-]?key)?|token|password|passwd|pwd|private[_-]?key|client[_-]?secret)\b)"
    r"(?P<sep>\s*[:=]\s*)(?P<quote>[\"']?)(?P<value>[^\s,;\"']{6,})(?P=quote)"
)
BEARER = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")
TOKEN_PREFIX = re.compile(r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b")
PRIVATE_KEY = re.compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.+?-----END [A-Z ]*PRIVATE KEY-----")


def tool(name, description, properties, required=()):
    def wrap(fn):
        TOOLS[name] = {"fn": fn, "spec": {
            "name": name, "description": description, "strict": True,
            "input_schema": {"type": "object", "properties": properties,
                             "required": list(properties), "additionalProperties": False}}}
        return fn
    return wrap


def specs(names):
    return [TOOLS[n]["spec"] for n in names]


def call(state, name, args):
    if name not in TOOLS:
        return {"error": f"unknown tool {name}"}, None
    try:
        result = TOOLS[name]["fn"](state, **args)
    except Exception as e:  # tool failures go back to the model as errors, not crashes
        return {"error": f"{type(e).__name__}: {e}"}, None
    eid = state.add_evidence(name, args, result)
    return result, eid


def redact(text):
    if not isinstance(text, str):
        return text
    text = SECRET_ASSIGNMENT.sub(lambda m: f"{m.group('name')}{m.group('sep')}{m.group('quote')}[REDACTED]{m.group('quote')}", text)
    text = BEARER.sub(r"\1[REDACTED]", text)
    text = TOKEN_PREFIX.sub("[REDACTED]", text)
    return PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)


from ..discovery.purl import short as _short


def _find_comp(state, component):
    c = state.comps.get(component)
    if c:
        return [c]
    q = component.replace("pkg:npm/", "")
    name, _, ver = q.rpartition("@") if q.count("@") > (1 if q.startswith("@") else 0) else (q, "", "")
    return [c for c in state.comps.values() if c.name == name and (not ver or c.version == ver)]


# ---------- tools ----------

@tool("list_findings", "List findings with their deterministic risk score, most severe first. Use empty string for "
      "filters you do not need.",
      {"category": {"type": "string", "description": "vulnerability|suspicious|maintenance|container|ci or ''"},
       "rule_id": {"type": "string", "description": "e.g. OSV, SC1, CI1, or ''"},
       "component": {"type": "string", "description": "package name or name@version, or ''"},
       "scope": {"type": "string", "description": "prod|dev or ''"},
       "limit": {"type": "integer", "description": "max rows (<= 40)"}})
def list_findings(state, category, rule_id, component, scope, limit):
    rows = []
    for f in state.findings:
        c = state.comps.get(f.get("component_id"))
        if category and f["category"] != category or rule_id and f["rule_id"] != rule_id:
            continue
        if component and not (c and (c.name == component or _short(c.component_id) == component)):
            continue
        if scope and not (c and c.scope == scope):
            continue
        r = state.risk.get(f["finding_id"], {})
        rows.append({"finding_id": f["finding_id"], "rule_id": f["rule_id"], "category": f["category"],
                     "title": f["title"][:120], "component": _short(f.get("component_id")),
                     "scope": c.scope if c else None, "risk_score": r.get("score"), "risk_severity": r.get("severity")})
    rows.sort(key=lambda r: -(r["risk_score"] or 0))
    return {"total": len(rows), "rows": rows[:max(1, min(limit, 40))]}


@tool("get_finding", "Full detail of one finding: evidence, dependency path, risk factor breakdown.",
      {"finding_id": {"type": "string"}})
def get_finding(state, finding_id):
    f = state.by_id.get(finding_id)
    if not f:
        return {"error": "no such finding_id"}
    out = {k: v for k, v in f.items() if k not in ("dependency_path",)}
    out["dependency_path"] = [_short(x) for x in f.get("dependency_path", [])]
    if isinstance(out.get("evidence", {}).get("excerpt"), str):
        out["evidence"] = {**out["evidence"], "excerpt": redact(out["evidence"]["excerpt"])[:1500]}
    out["risk"] = state.risk.get(finding_id)
    return out


@tool("get_component", "Inventory record for a package: scope, direct/transitive, shortest path, parents, findings.",
      {"component": {"type": "string", "description": "purl, name@version or name"}})
def get_component(state, component):
    res = []
    for c in _find_comp(state, component)[:8]:
        res.append({"component_id": c.component_id, "name": c.name, "version": c.version, "scope": c.scope,
                    "relationship": c.relationship, "path": [_short(x) for x in c.path],
                    "parents": [_short(p) for p in c.parents][:10], "source": c.source_url,
                    "has_install_script": c.has_install_script, "risk_status": c.risk_status,
                    "fixed_version": c.fixed_version, "finding_ids": [f["finding_id"] for f in state.findings
                                                                      if f.get("component_id") == c.component_id][:20]})
    return {"matches": res} if res else {"error": "component not found"}


@tool("check_import_usage", "Where application code (outside node_modules) requires/imports a package. "
      "Package-level reachability evidence.", {"package": {"type": "string"}})
def check_import_usage(state, package):
    eco = next((c.ecosystem for c in state.comps.values() if c.name == package), "npm")
    hits = import_usage(state.repo, [package], eco)[package]
    if hits is None:
        return {"package": package, "error": f"import analysis is not supported for {eco}"}
    lines = []
    for h in hits[:15]:
        path, ln = h.rsplit(":", 1)
        try:
            lines.append({"at": h, "code": redact((state.repo / path).read_text(errors="replace").splitlines()[int(ln) - 1].strip())[:200]})
        except (OSError, IndexError):
            lines.append({"at": h})
    return {"package": package, "import_sites": len(hits), "sites": lines}


@tool("read_file", "Read a slice of a repository file (secrets redacted, max 120 lines).",
      {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}})
def read_file(state, path, start_line, end_line):
    p = (state.repo / path).resolve()
    if state.repo.resolve() not in p.parents or not p.is_file():
        return {"error": "path outside repository or not a file"}
    lines = p.read_text(errors="replace").splitlines()
    s, e = max(1, start_line), min(len(lines), max(start_line, end_line), start_line + 119)
    return {"path": path, "lines": f"{s}-{e}", "total_lines": len(lines),
            "text": redact("\n".join(f"{i}: {lines[i - 1]}" for i in range(s, e + 1)))}


@tool("git_commit_info", "Metadata and lockfile entries changed by one commit (read-only git).",
      {"commit": {"type": "string"}})
def git_commit_info(state, commit):
    if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
        return {"error": "commit must be a hex SHA"}
    g = lambda *a: subprocess.run(["git", "-C", str(state.repo), "-c", "core.hooksPath=/dev/null", *a],
                                  capture_output=True, text=True).stdout
    meta = g("show", "-s", "--format=%H%n%an <%ae>%n%ad%n%s", commit).splitlines()
    if not meta:
        return {"error": "commit not found"}
    stat = g("show", "--stat", "--format=", commit).strip().splitlines()
    out = {"commit": meta[0], "author": meta[1], "date": meta[2], "subject": meta[3], "files": stat[:20], "lockfile_changes": []}
    new_t, old_t = g("show", f"{commit}:package-lock.json"), g("show", f"{commit}^:package-lock.json")
    if new_t and old_t:
        new, old = json.loads(new_t).get("packages", {}), json.loads(old_t).get("packages", {})
        for k in sorted(set(new) | set(old)):
            n, o = new.get(k, {}), old.get(k, {})
            diff = {f: [o.get(f), n.get(f)] for f in ("version", "resolved", "integrity") if o.get(f) != n.get(f)}
            if k and diff:
                out["lockfile_changes"].append({"key": k, "package": pkg_name(k), **diff})
        out["lockfile_changes"] = out["lockfile_changes"][:30]
    return out


@tool("npm_registry_metadata", "Official npm registry record for name@version: dist.integrity, tarball URL, "
      "deprecation, publisher, install scripts. Compare with the lockfile to confirm or rule out tampering.",
      {"package": {"type": "string"}, "version": {"type": "string"}})
def npm_registry_metadata(state, package, version):
    meta = registry_metadata(package, version, state.out / "cache" / "registry")
    if not meta or meta.get("error"):
        return {"error": (meta or {}).get("error", "unavailable")}
    lock = [c for c in state.comps.values() if c.name == package and c.version == version]
    if lock:
        meta = {**meta, "lockfile": {"integrity": lock[0].integrity, "resolved": lock[0].source_url},
                "integrity_matches_lockfile": lock[0].integrity == meta["dist"]["integrity"],
                "resolved_matches_registry": lock[0].source_url == meta["dist"]["tarball"]}
    return meta


@tool("get_fix_options", "Deterministic remediation candidates that would close a finding or touch a component.",
      {"finding_id": {"type": "string", "description": "finding id, or '' to use component"},
       "component": {"type": "string", "description": "name or name@version, or ''"}})
def get_fix_options(state, finding_id, component):
    names = {c.component_id for c in _find_comp(state, component)} if component else set()
    rows = []
    for c in state.candidates:
        if (finding_id and finding_id in c["closes"]) or (names and c.get("component_id") in names) or \
                (component and component in c["summary"]):
            rows.append({k: c[k] for k in ("candidate_id", "action", "summary", "change_risk", "compat_notes",
                                           "rollback", "requires", "needs_lockfile_regen")} | {"closes_count": len(c["closes"])})
    return {"candidates": rows[:10]}


@tool("verify_merkle_baseline", "Verify the developer-signed 4096-byte Merkle-tree chunk baseline (.guardian/baseline.json) "
      "and report exact tampered chunks, byte offsets, and modified lines.",
      {"rounds": {"type": "integer", "description": "number of verification rounds (1-5)"}})
def verify_merkle_baseline(state, rounds):
    from ..integrity import run_watch
    try:
        anomalies = run_watch(state.repo, interval=0, rounds=max(1, min(rounds, 5)), full_check_every=1)
        return {"ok": len(anomalies) == 0, "anomalies_count": len(anomalies), "anomalies": anomalies[:20]}
    except FileNotFoundError as e:
        return {"ok": None, "note": str(e)}


@tool("verify_audit_ledger", "Verify every cryptographic hash link (prev_hash -> record_hash) and HMAC signature "
      "in the tamper-evident audit ledger (.guardian/ledger.jsonl).",
      {})
def verify_audit_ledger(state):
    from ..integrity import verify_ledger
    ok, msg, info = verify_ledger(state.repo)
    return {"ok": ok, "message": msg, "detail": info}
