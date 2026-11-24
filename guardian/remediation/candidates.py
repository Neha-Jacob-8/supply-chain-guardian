"""Deterministic remediation candidates.

The Blue Team agent chooses among these; it cannot invent a fix. Each candidate carries the
exact file changes (as a unified diff), what it should close, compatibility notes and rollback.
Read-only lookups: npm registry metadata, `git ls-remote` for action SHAs.
"""
import difflib
import hashlib
import json
import re
from pathlib import Path

from ..ingestion import repository_identity
from ..intel.osv import _semver_key
from ..intel.registry import registry_metadata, resolve_ref_sha


# ---------- helpers ----------

def _diff(path, old, new):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{path}", f"b/{path}"))


def _cid(rule, key, diff_sha256):
    """Candidate identity is bound to both its logical subject and exact patch."""
    material = f"{key}|{diff_sha256}"
    return f"FIX-{rule}-{hashlib.sha256(material.encode()).hexdigest()[:12]}"


def _major(v):
    return _semver_key(v)[0][0]


def _clean_fix(fixed):
    return (fixed or "").split(" ")[0] if fixed and fixed[0].isdigit() else None


def _candidate(rule, key, action, summary, files, closes, change_risk, compat, rollback, component_id=None,
               requires=None, needs_lockfile_regen=False):
    diff = "".join(_diff(p, o, n) for p, (o, n) in files.items())
    diff_sha256 = hashlib.sha256(diff.encode()).hexdigest()
    base_files_sha256 = {p: hashlib.sha256(old.encode()).hexdigest() for p, (old, _new) in files.items()}
    return {"candidate_id": _cid(rule, key, diff_sha256), "action": action, "summary": summary,
            "component_id": component_id, "closes": sorted(set(closes)), "change_risk": change_risk,
            "compat_notes": compat, "rollback": rollback, "requires": requires or [],
            "needs_lockfile_regen": needs_lockfile_regen,
            "files": files, "diff": diff, "diff_sha256": diff_sha256,
            "base_files_sha256": base_files_sha256}


def _insert_top_level_permissions(text):
    """Insert a workflow-level permissions block without moving nested `on:` events."""
    lines = text.splitlines(keepends=True)
    if any(re.match(r"^permissions\s*:", line) for line in lines):
        return text
    on_index = next((i for i, line in enumerate(lines) if re.match(r"^on\s*:", line)), None)
    if on_index is None:
        insert_at = next((i + 1 for i, line in enumerate(lines) if re.match(r"^name\s*:", line)), 0)
    else:
        insert_at = on_index + 1
        # A block-style `on:` mapping ends at the next non-comment top-level key.
        if not lines[on_index].split(":", 1)[1].strip():
            while insert_at < len(lines):
                stripped = lines[insert_at].strip()
                if stripped and not stripped.startswith("#") and not lines[insert_at][0].isspace():
                    break
                insert_at += 1
    block = ["\n" if insert_at and lines[insert_at - 1].strip() else "", "permissions:\n", "  contents: read\n"]
    lines[insert_at:insert_at] = block
    return "".join(lines)


def _is_nodegoat_demo(repo):
    """Return true only for the explicitly documented demo target.

    Runtime/container migration policies are not generic dependency fixes. Keep
    them behind an identity gate so a similarly named arbitrary repository never
    receives a NodeGoat-specific MongoDB/Node recommendation.
    """
    return (repository_identity(repo).get("remote_id") or "") == "owasp/nodegoat"


# ---------- generators ----------

def build_candidates(repo, comps, findings, cache_dir, offline=False):
    repo = Path(repo)
    cache_dir = Path(cache_dir)
    out = []
    by_comp = {}
    for f in findings:
        if f.get("component_id"):
            by_comp.setdefault(f["component_id"], []).append(f)

    def project_pj(c):
        """package.json of the npm project the component belongs to: (relative path, text, parsed)."""
        man = next((m for m in c.projects if m.endswith((".json", ".lock"))), None)
        rel = str(Path(man).parent / "package.json") if man else "package.json"
        rel = rel[2:] if rel.startswith("./") else rel
        f = repo / rel
        if not f.exists():
            return None, None, None
        t = f.read_text()
        return rel, t, json.loads(t)

    # 1) vulnerable direct dependency -> bump the version where it is declared
    for cid, fs in by_comp.items():
        c = comps.get(cid)
        vf = [f for f in fs if f["category"] == "vulnerability"]
        if not c or not vf or c.relationship != "direct":
            continue
        target = _clean_fix(c.fixed_version)
        if not target:
            out.append(_candidate("VULN", cid, "escalate", f"No published fix for all advisories of {c.name}@{c.version}",
                                  {}, [], "high", "Needs replacement or mitigation decision by a human", "n/a", cid))
            continue
        closes = [f["finding_id"] for f in vf if f.get("fixed_version") and
                  not _semver_key(target) < _semver_key(f["fixed_version"])]
        major = _major(target) != _major(c.version)
        compat = (f"Major version jump {_major(c.version)} -> {_major(target)}: API changes likely; code using "
                  f"{c.name} must be re-tested." if major else "Same major version: low API risk.")
        if c.ecosystem == "npm":
            rel, text, pj = project_pj(c)
            section = next((s for s in ("dependencies", "devDependencies", "optionalDependencies")
                            if pj and c.name in pj.get(s, {})), None)
            if not section:
                continue
            meta = registry_metadata(c.name, target, cache_dir / "registry", offline)
            if meta is not None and meta.get("error"):
                out.append(_candidate("VULN", cid, "escalate", f"Fixed version {c.name}@{target} is not on the npm registry",
                                      {}, [], "high", meta["error"], "n/a", cid))
                continue
            old_spec = pj[section][c.name]
            new_text = re.sub(r'("' + re.escape(c.name) + r'"\s*:\s*)"' + re.escape(old_spec) + '"',
                              lambda m: f'{m.group(1)}"{target}"', text, count=1)
            pnpm = any(f.endswith("pnpm-lock.yaml") for f in c.found_in)
            out.append(_candidate(
                "VULN", cid, "upgrade", f"Upgrade {c.name} {c.version} -> {target} ({rel}, {section})",
                {rel: (text, new_text)}, closes, "high" if major else "medium",
                compat + (" Regenerate pnpm-lock.yaml with `pnpm install` (not done automatically)." if pnpm else ""),
                f'Revert {rel} "{c.name}": "{old_spec}" and restore the previous lockfile.', cid, needs_lockfile_regen=not pnpm))
        elif c.ecosystem == "pypi" and any(m.endswith(".txt") for m in c.found_in):
            rel = next(m for m in c.found_in if m.endswith(".txt"))
            text = (repo / rel).read_text()
            names = "|".join({re.escape(c.name), re.escape(c.name.replace("-", "_")), re.escape(c.name.replace("-", "."))})
            new_text = re.sub(r"(?im)^((?:" + names + r")(\[[^\]]*\])?\s*===?\s*)" + re.escape(c.version) + r"\b",
                              lambda m: m.group(1) + target, text, count=1)
            if new_text != text:
                out.append(_candidate(
                    "VULN", cid, "upgrade", f"Upgrade {c.name} {c.version} -> {target} ({rel})", {rel: (text, new_text)},
                    closes, "high" if major else "medium", compat + " Dependencies of the new version are not re-resolved; "
                    "regenerate the pinned file with pip-compile/uv if it is generated.",
                    f"Revert {rel} to {c.name}=={c.version}", cid))
        else:
            manifest = (c.projects or c.found_in or ["its manifest"])[0]
            out.append(_candidate(
                "VULN", cid, "escalate", f"Upgrade {c.name} {c.version} -> {target} in {manifest} (manual)",
                {}, [], "high" if major else "medium",
                f"Automatic patching is not implemented for {c.ecosystem}; update {manifest} and regenerate its lockfile. " + compat,
                "Revert the manifest/lockfile change", cid))

    # 2) vulnerable transitive npm deps -> one "overrides" entry per package name and project
    trans = {}
    for cid, fs in by_comp.items():
        c = comps.get(cid)
        vf = [f for f in fs if f["category"] == "vulnerability"]
        if c and vf and c.ecosystem == "npm" and c.relationship == "transitive" and c.scope == "prod":
            rel = project_pj(c)[0]
            if rel:
                trans.setdefault((rel, c.name), []).append((c, vf))
    for (rel, name), items in sorted(trans.items()):
        fixes = [_clean_fix(c.fixed_version) for c, _ in items]
        if not all(fixes):
            continue
        target = max(fixes, key=_semver_key)
        meta = registry_metadata(name, target, cache_dir / "registry", offline)
        if meta is not None and meta.get("error"):
            continue
        _, text, pj = project_pj(items[0][0])
        overrides = dict(pj.get("overrides", {})); overrides[name] = target
        new_text = json.dumps(dict(pj, overrides=overrides), indent=2) + "\n"
        majors = sorted({_major(c.version) for c, _ in items} - {_major(target)})
        out.append(_candidate(
            "OVR", f"{rel}:{name}", "override",
            f"Force transitive {name} ({', '.join(sorted(c.version for c, _ in items))}) -> {target} via npm overrides",
            {rel: (text, new_text)}, [f["finding_id"] for _, vf in items for f in vf],
            "medium" if majors else "low",
            "Requires npm >= 8.3 to honour `overrides` (older npm ignores it)."
            + (f" Parents expecting major {majors} get {_major(target)}.x." if majors else ""),
            f'Remove the "{name}" entry from "overrides" in {rel} and restore the lockfile.',
            requires=["npm >= 8.3"], needs_lockfile_regen=True))

    # 3) lockfile tampering -> restore registry values (verified against registry metadata), one candidate
    lock_path = repo / "package-lock.json"
    lock_text = lock_path.read_text() if lock_path.exists() else ""
    new_lock, closes, names, commits = lock_text, [], [], set()
    for f in findings:
        if f["rule_id"] not in ("SC1", "SC2") or not f.get("component_id"):
            continue
        c = comps.get(f["component_id"])
        if not c or "github.com" in (c.source_url or ""):
            continue
        meta = registry_metadata(c.name, c.version, cache_dir / "registry", offline)
        if not meta or meta.get("error"):
            continue
        before = new_lock
        for key in c.found_in:
            blk = re.search(r'\n {4}"' + re.escape(key) + r'": \{(.*?)\n {4}\}', new_lock, re.S)
            if not blk:
                continue
            b = blk.group(0)
            nb = re.sub(r'("integrity": )"[^"]*"', lambda m: f'{m.group(1)}"{meta["dist"]["integrity"]}"', b, count=1) \
                if meta["dist"].get("integrity") else b
            nb = re.sub(r'("resolved": )"[^"]*"', lambda m: f'{m.group(1)}"{meta["dist"]["tarball"]}"', nb, count=1)
            new_lock = new_lock.replace(b, nb)
        if new_lock != before or c.name in names:   # a 2nd finding on an already-restored entry
            closes.append(f["finding_id"])
            if c.name not in names:
                names.append(c.name)
            if f["evidence"].get("commit"):
                commits.add(str(f["evidence"]["commit"])[:10])
    if new_lock != lock_text:
        out.append(_candidate(
            "LOCK", ",".join(sorted(closes)), "pin",
            f"Restore tampered lockfile entries ({', '.join(names)}) to the npm registry values",
            {"package-lock.json": (lock_text, new_lock)}, closes, "low",
            "Same versions; integrity/resolved copied from the official npm registry records. Review who made "
            f"commit(s) {', '.join(sorted(commits)) or 'n/a'} and rotate any credentials they could reach.",
            "git checkout the previous package-lock.json"))

    # 4) GitHub Actions -> pin to commit SHA; add least-privilege permissions
    wf_dir = repo / ".github" / "workflows"
    for wf in sorted(wf_dir.glob("*.y*ml")) if wf_dir.is_dir() else []:
        rel, text = str(wf.relative_to(repo)), wf.read_text()
        new, closes = text, []
        for f in findings:
            if f["rule_id"] == "CI1" and f["evidence"].get("path") == rel:
                m = re.search(r"uses:\s*['\"]?([\w.-]+/[\w.-]+)(/[^@\s]*)?@([^\s'\"#]+)", f["evidence"]["excerpt"])
                if not m:
                    continue
                action, sub, ref = m.group(1), m.group(2) or "", m.group(3)
                sha = resolve_ref_sha(f"https://github.com/{action}", ref, cache_dir, offline)
                if sha:
                    new = new.replace(f"{action}{sub}@{ref}", f"{action}{sub}@{sha} # {ref}", 1)
                    closes.append(f["finding_id"])
            if f["rule_id"] == "CI2" and f["evidence"].get("path") == rel and "permissions:" not in new:
                new = _insert_top_level_permissions(new)
                closes.append(f["finding_id"])
        if new != text:
            out.append(_candidate(
                "CI", rel, "pin", f"Pin actions to commit SHAs and set read-only token permissions in {rel}",
                {rel: (text, new)}, closes, "low",
                "Same action versions, now immutable. If a job needs write access, grant it per job.",
                f"git checkout {rel}"))

    # 5) containers -> supported runtime (Dockerfile) and database (compose).
    # These two migrations are intentionally restricted to the trusted demo
    # profile; generic repositories receive findings and human escalation.
    demo_target = _is_nodegoat_demo(repo)
    for name in ("Dockerfile",):
        p = repo / name
        if not p.exists() or not demo_target:
            continue
        text = p.read_text()
        new = re.sub(r"^FROM node:\d+(-alpine)?", "FROM node:22-alpine", text, flags=re.M)
        new = new.replace("npm install --production --no-cache", "npm ci --omit=dev --no-audit --no-fund")
        closes = [f["finding_id"] for f in findings if f["evidence"].get("path") == name and f["rule_id"] in ("CT2", "CT5")]
        if new != text:
            out.append(_candidate(
                "IMG", name, "base_image", "Move the app image from EOL node:12 to node:22 and build with `npm ci`",
                {name: (text, new)}, closes, "high",
                "Node 12 -> 22 is a large runtime jump; old native/legacy packages may break. Enables npm >= 8.3 "
                "(needed for overrides). Tag is still not digest-pinned (CT1 remains until a digest is recorded).",
                "Revert the Dockerfile FROM/RUN lines"))
    for name in ("docker-compose.yml", "docker-compose.yaml"):
        p = repo / name
        if not p.exists() or not demo_target:
            continue
        text = p.read_text()
        new = re.sub(r"(image:\s*)mongo:[\d.]+", r"\1mongo:7.0", text)
        closes = [f["finding_id"] for f in findings if f["evidence"].get("path") == name and f["rule_id"] == "CT2"]
        if new != text:
            out.append(_candidate(
                "DB", name, "base_image", "Move MongoDB from EOL 4.x to supported 7.0",
                {name: (text, new)}, closes, "high",
                "The app uses the mongodb 2.x driver, which predates MongoDB 7 wire protocol changes: likely to break.",
                "Revert the image tag in docker-compose"))

    # 6) shadow / phantom dependencies (SC8) -> add explicit pin to requirements.txt or package.json
    for f in findings:
        if f.get("rule_id") != "SC8" or f.get("category") == "malicious":
            continue
        ev = f.get("evidence") or {}
        if ev.get("vulnerable"):
            continue
        eco, pkg, ver = ev.get("ecosystem"), ev.get("package"), ev.get("resolved_version") or ""
        cid = f.get("component_id")
        if eco == "pypi":
            req_path = repo / "requirements.txt"
            if req_path.exists():
                old_req = req_path.read_text()
                pin_line = f"{pkg}=={ver}" if ver else pkg
                if not re.search(rf"(?im)^{re.escape(pkg)}\s*([=<>!~]|$)", old_req):
                    new_req = old_req.rstrip("\n") + ("\n" if old_req.strip() else "") + pin_line + "\n"
                    out.append(_candidate(
                        "SHDW", f"requirements.txt:{pkg}", "pin",
                        f"Declare shadow dependency {pin_line} in requirements.txt",
                        {"requirements.txt": (old_req, new_req)}, [f["finding_id"]], "low",
                        f"Explicitly pins '{pkg}' (imported in {ev.get('path')}:{ev.get('line')}) in requirements.txt.",
                        "Remove the added line from requirements.txt", cid))
        elif eco == "npm":
            pj_path = repo / "package.json"
            if pj_path.exists():
                try:
                    old_pj = pj_path.read_text()
                    pj_data = json.loads(old_pj)
                except (OSError, json.JSONDecodeError):
                    pj_data = None
                if isinstance(pj_data, dict):
                    deps = dict(pj_data.get("dependencies") or {})
                    if pkg not in deps:
                        deps[pkg] = ver or "*"
                        new_pj = json.dumps({**pj_data, "dependencies": deps}, indent=2) + "\n"
                        out.append(_candidate(
                            "SHDW", f"package.json:{pkg}", "pin",
                            f'Declare shadow dependency "{pkg}": "{deps[pkg]}" in package.json',
                            {"package.json": (old_pj, new_pj)}, [f["finding_id"]], "low",
                            f"Explicitly declares '{pkg}' (imported in {ev.get('path')}:{ev.get('line')}) in package.json.",
                            f'Remove "{pkg}" from dependencies in package.json', cid, needs_lockfile_regen=bool(ver)))
        elif eco == "cargo":
            ct_path = repo / "Cargo.toml"
            if ct_path.exists():
                old_ct = ct_path.read_text()
                pin_line = f'{pkg} = "{ver or "*"}"'
                if "[dependencies]" in old_ct and not re.search(rf"(?m)^\s*{re.escape(pkg)}\s*=", old_ct):
                    new_ct = old_ct.replace("[dependencies]", f"[dependencies]\n{pin_line}", 1)
                    out.append(_candidate(
                        "SHDW", f"Cargo.toml:{pkg}", "pin",
                        f"Declare shadow crate {pin_line} in Cargo.toml",
                        {"Cargo.toml": (old_ct, new_ct)}, [f["finding_id"]], "low",
                        f"Explicitly declares crate '{pkg}' (used in {ev.get('path')}:{ev.get('line')}) in Cargo.toml.",
                        f"Remove {pkg} from Cargo.toml", cid))
        elif eco == "maven":
            pom_path = repo / "pom.xml"
            if pom_path.exists() and "</dependencies>" in pom_path.read_text():
                old_pom = pom_path.read_text()
                g, _, a = pkg.partition(":")
                a = a or g.split(".")[-1]
                v_tag = f"<version>{ver}</version>" if ver else ""
                dep_xml = f"    <dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>{v_tag}</dependency>\n  </dependencies>"
                if a not in old_pom:
                    new_pom = old_pom.replace("</dependencies>", dep_xml, 1)
                    out.append(_candidate(
                        "SHDW", f"pom.xml:{pkg}", "pin",
                        f"Declare shadow Maven artifact {g}:{a} in pom.xml",
                        {"pom.xml": (old_pom, new_pom)}, [f["finding_id"]], "low",
                        f"Explicitly declares '{g}:{a}' (imported in {ev.get('path')}:{ev.get('line')}) in pom.xml.",
                        f"Remove {g}:{a} from pom.xml", cid))
        elif eco == "golang":
            gm_path = repo / "go.mod"
            if gm_path.exists():
                old_gm = gm_path.read_text()
                req_line = f"\nrequire {pkg} {ver or 'v0.0.0'}\n"
                if pkg not in old_gm:
                    new_gm = old_gm.rstrip("\n") + req_line
                    out.append(_candidate(
                        "SHDW", f"go.mod:{pkg}", "pin",
                        f"Declare shadow Go module {pkg} in go.mod",
                        {"go.mod": (old_gm, new_gm)}, [f["finding_id"]], "low",
                        f"Explicitly declares '{pkg}' (imported in {ev.get('path')}:{ev.get('line')}) in go.mod.",
                        f"Remove {pkg} from go.mod", cid))
    return out
