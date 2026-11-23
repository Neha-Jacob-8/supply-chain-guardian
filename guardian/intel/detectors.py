"""Non-CVE supply-chain detectors (deterministic, rule-based).

Each finding is an *indicator*: a verified fact (file, line, commit) plus a rule that
says why it is risky. Nothing here executes target code; git is only read.

Rules
  SC1  lockfile integrity changed without a version change (git history)
  SC2  dependency resolved from a non-registry source (current lockfile / history)
  SC3  package runs install scripts (current lockfile / newly added in history)
  SC4  dependency spec is floating (latest, *, tarball/git branch without commit)
  SC5  lockfile v2 sections disagree (legacy `dependencies` vs `packages`): npm 6 and npm 7+ would install different code
  SC6  new direct dependency appeared in lockfile history
  SC7  direct dependency made an unexplained major-version jump in lockfile history
  MT1  package deprecated by its maintainer
  CT1  container image not pinned to a digest
  CT2  container image runtime is end-of-life
  CT3  final image runs as root
  CT4  remote script piped to a shell / remote ADD
  CT5  `npm install` instead of `npm ci` (lockfile not enforced)
  CI1  GitHub Action not pinned to a commit SHA
  CI2  workflow has no `permissions:` block (default token permissions)
  CI3  `pull_request_target` trigger
  CI4  untrusted `${{ github.event.* }}` used inside `run:`
"""
import hashlib
import json
import re
import subprocess
from datetime import date
from pathlib import Path

from ..policies import load as load_policy
from ..discovery.lockfile import make_purl, pkg_name
from .osv import _semver_key

REGISTRY = "https://registry.npmjs.org/"
SKIP_DIRS = {"node_modules", ".git"}

EOL = load_policy("eol.json")   # policies/eol.json (snapshot; refresh before relying on it)


# ---------- helpers ----------

def _sha(text):
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()


def _finding(rule, category, severity, title, detail, evidence, component_id=None, fix=None):
    anchor = f"{rule}|{component_id}|{evidence.get('path')}|{evidence.get('line')}|{evidence.get('commit')}"
    return {
        "finding_id": f"{rule}-{_sha(anchor)[:10]}", "rule_id": rule, "category": category,
        "severity": severity, "title": title, "detail": detail,
        "component_id": component_id, "evidence_class": "indicator",
        "evidence": evidence, "recommendation": fix,
    }


def _files(repo, pred):
    for p in sorted(repo.rglob("*")):
        rel = p.relative_to(repo)
        if p.is_file() and not SKIP_DIRS & set(rel.parts) and pred(p):
            yield p, str(rel)


def _git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", *args],
                       capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def _lock_lines(text):
    """lockfile key -> line number (keys under "packages" sit at 4-space indent)."""
    out = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^ {4}"([^"]*)": \{', line)
        if m and m.group(1) not in out:
            out[m.group(1)] = i
    return out


def _hashes(integrity):
    """'sha512-AAA sha1-BBB' -> {'sha512': 'AAA', 'sha1': 'BBB'}"""
    return dict(part.split("-", 1) for part in (integrity or "").split() if "-" in part)


# ---------- lockfile: current state ----------

def lockfile_current(repo, lock_rel, comps):
    text = (repo / lock_rel).read_text()
    pk, lines, fsha = json.loads(text)["packages"], _lock_lines(text), _sha(text)
    out, seen = [], set()
    for key, p in pk.items():
        if not key or not p.get("version"):
            continue
        cid = make_purl(pkg_name(key), p["version"])
        c = comps.get(cid)
        prod = bool(c and c.scope == "prod")
        ev = {"source": "file", "path": lock_rel, "line": lines.get(key), "sha256": fsha,
              "excerpt": json.dumps({key: {k: p[k] for k in ("version", "resolved", "deprecated",
                                                              "hasInstallScript") if k in p}})}
        res = p.get("resolved")
        if res and not res.startswith(REGISTRY) and ("SC2", cid) not in seen:
            seen.add(("SC2", cid))
            floating = bool(re.search(r"/(tarball|archive)/(master|main|HEAD)\b|#(master|main)$", res))
            out.append(_finding(
                "SC2", "suspicious", "HIGH" if floating else "MEDIUM",
                f"{pkg_name(key)} is fetched from outside the npm registry",
                f"resolved = {res}" + (" (a moving branch: contents can change without a version change)" if floating else ""),
                ev, cid, "Depend on a published registry version, or pin to an immutable commit SHA."))
        if p.get("hasInstallScript") and ("SC3", cid) not in seen:
            seen.add(("SC3", cid))
            out.append(_finding(
                "SC3", "suspicious", "MEDIUM" if prod else "LOW",
                f"{pkg_name(key)} runs install scripts",
                "Code from this package executes during `npm install`" + (" (prod dependency)" if prod else " (dev only)"),
                ev, cid, "Install with --ignore-scripts where possible; review the script; allow-list it."))
        if p.get("deprecated") and ("MT1", cid) not in seen:
            seen.add(("MT1", cid))
            direct = bool(c and c.relationship == "direct")
            out.append(_finding(
                "MT1", "maintenance", "MEDIUM" if (prod and direct) else "LOW",
                f"{pkg_name(key)}@{p['version']} is deprecated",
                p["deprecated"], ev, cid, "Upgrade or replace with the maintained alternative."))
    return out


def lockfile_consistency(repo, lock_rel, comps):
    """v2 lockfiles carry two copies of the tree. npm <= 6 reads `dependencies`, npm >= 7 reads `packages`."""
    text = (repo / lock_rel).read_text()
    data = json.loads(text)
    pk, legacy = data.get("packages", {}), data.get("dependencies")
    if not legacy:
        return []
    lines, out = _lock_lines(text), []

    def walk(tree, prefix):
        for name, d in tree.items():
            key = f"{prefix}node_modules/{name}"
            p = pk.get(key)
            if p is not None:
                diff = {f: [d.get(f), p.get(f)] for f in ("version", "integrity", "resolved")
                        if d.get(f) and p.get(f) and d.get(f) != p.get(f)}
                if "version" in diff and ("://" in d["version"] or ":" in d["version"].split("/")[0]):
                    del diff["version"]   # npm stores the URL as `version` for URL/git deps in the legacy section
                if diff:
                    cid = make_purl(name, p.get("version", "?"))
                    ex = json.dumps({"key": key, **{f"{k}_legacy_vs_packages": v for k, v in diff.items()}})
                    out.append(_finding(
                        "SC5", "suspicious", "HIGH", f"{name}: lockfile sections disagree ({', '.join(diff)})",
                        "The legacy `dependencies` section (used by npm <= 6) and the `packages` section (npm >= 7) "
                        "record different values, so different npm versions would install different code.",
                        {"source": "file", "path": lock_rel, "line": lines.get(key), "sha256": _sha(text), "excerpt": ex},
                        cid, "Regenerate the lockfile from a trusted state and compare against registry values."))
            walk(d.get("dependencies", {}), key + "/")

    walk(legacy, "")
    return out


def package_json_specs(repo, comps, pj_rel="package.json"):
    out = []
    pj = repo / pj_rel
    if not pj.exists():
        return out
    text, data = pj.read_text(), json.loads(pj.read_text())
    lines = text.splitlines()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in data.get(section, {}).items():
            why = None
            if spec in ("latest", "*", "") or spec.startswith((">", "x")):
                why = f'version spec "{spec}" accepts any future release'
            elif re.match(r"^(https?:|git(\+\w+)?:|github:|[\w-]+/[\w.-]+(#.*)?$)", spec) and \
                    not re.search(r"[#/][0-9a-f]{40}$", spec):
                why = f'"{spec}" points at a URL/git ref, not an immutable version or commit'
            if not why:
                continue
            ln = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), None)
            cid = next((c.component_id for c in comps.values()
                        if c.name == name and c.relationship == "direct"), None)
            out.append(_finding(
                "SC4", "suspicious", "MEDIUM", f"{name} has a floating dependency spec", why,
                {"source": "file", "path": pj_rel, "line": ln, "sha256": _sha(text),
                 "excerpt": lines[ln - 1].strip() if ln else f'"{name}": "{spec}"'},
                cid, "Pin an exact published version (and commit the lockfile)."))
    return out


# ---------- lockfile: history ("what changed") ----------

def lockfile_history(repo, lock_rel, max_commits=20):
    """Compare each commit that touched the lockfile with its parent."""
    findings, changes = [], []
    log = _git(repo, "log", f"-n{max_commits}", "--format=%H%x09%an%x09%ad%x09%s", "--date=short", "--", lock_rel)
    for row in (log or "").splitlines():
        sha, author, day, subject = row.split("\t", 3)
        parent = _git(repo, "rev-parse", "--verify", "-q", f"{sha}^")
        new_t = _git(repo, "show", f"{sha}:{lock_rel}")
        old_t = _git(repo, "show", f"{parent.strip()}:{lock_rel}") if parent else None
        if not (new_t and old_t):
            changes.append({"commit": sha[:10], "date": day, "subject": subject, "note": "parent not in shallow clone"})
            continue
        try:
            new, old = json.loads(new_t).get("packages"), json.loads(old_t).get("packages")
        except json.JSONDecodeError:
            continue
        if new is None or old is None:
            changes.append({"commit": sha[:10], "date": day, "subject": subject, "note": "lockfile v1, not compared"})
            continue
        lines = _lock_lines(new_t)
        added = sorted(set(new) - set(old) - {""})
        removed = sorted(set(old) - set(new) - {""})
        changed = [k for k in set(new) & set(old) if k and new[k].get("version") != old[k].get("version")]
        changes.append({"commit": sha[:10], "date": day, "author": author, "subject": subject,
                        "added": len(added), "removed": len(removed), "version_changed": len(changed)})
        old_root = old.get("", {})
        new_root = new.get("", {})
        old_direct = {**(old_root.get("dependencies") or {}), **(old_root.get("optionalDependencies") or {}),
                      **(old_root.get("devDependencies") or {})}
        new_direct = {**(new_root.get("dependencies") or {}), **(new_root.get("optionalDependencies") or {}),
                      **(new_root.get("devDependencies") or {})}
        for name in sorted(set(new_direct) - set(old_direct)):
            key = f"node_modules/{name}"
            pkg = new.get(key, {})
            if not pkg.get("version"):
                continue
            cid = make_purl(name, pkg["version"])
            ev = {"source": "git", "path": lock_rel, "commit": sha, "commit_date": day,
                  "commit_subject": subject, "line": lines.get(key),
                  "excerpt": json.dumps({"dependency": name, "version": pkg["version"],
                                         "declared_spec": new_direct[name]})}
            ev["sha256"] = _sha(ev["excerpt"])
            findings.append(_finding(
                "SC6", "suspicious", "MEDIUM", f"New direct dependency added: {name}@{pkg['version']}",
                f"Commit {sha[:10]} added {name} to the root dependency declarations. Review the reason, provenance, and owner before trusting it.",
                ev, cid, "Confirm the dependency is intentional, pin it, and review its provenance before release."))
        for name in sorted(set(new_direct) & set(old_direct)):
            key = f"node_modules/{name}"
            old_pkg, new_pkg = old.get(key, {}), new.get(key, {})
            old_ver, new_ver = old_pkg.get("version"), new_pkg.get("version")
            if not old_ver or not new_ver or _semver_key(old_ver)[0][0] == _semver_key(new_ver)[0][0]:
                continue
            cid = make_purl(name, new_ver)
            ev = {"source": "git", "path": lock_rel, "commit": sha, "commit_date": day,
                  "commit_subject": subject, "line": lines.get(key),
                  "excerpt": json.dumps({"dependency": name, "before": old_ver, "after": new_ver})}
            ev["sha256"] = _sha(ev["excerpt"])
            findings.append(_finding(
                "SC7", "suspicious", "MEDIUM", f"Direct dependency major version changed: {name} {old_ver} -> {new_ver}",
                f"Commit {sha[:10]} changed a direct dependency across a major-version boundary. Confirm compatibility and review the change rationale.",
                ev, cid, "Review release notes and run the application test suite before accepting the major upgrade."))
        algo_upgrades = 0
        base_ev = {"source": "git", "path": lock_rel, "commit": sha, "commit_date": day,
                   "commit_subject": subject}
        for k in sorted(set(new) & set(old)):
            if not k:
                continue
            n, o = new[k], old[k]
            same_ver = n.get("version") == o.get("version")
            cid = make_purl(pkg_name(k), n.get("version", "?"))
            diff = {"key": k, "version": n.get("version")}
            hn, ho = _hashes(n.get("integrity")), _hashes(o.get("integrity"))
            common = set(hn) & set(ho)
            if same_ver and hn and ho and not common:
                algo_upgrades += 1   # e.g. sha1 -> sha512 re-record by npm: benign, not a finding
            if same_ver and any(hn[a] != ho[a] for a in common):
                ev = {**base_ev, "line": lines.get(k), "excerpt": json.dumps(
                    {**diff, "integrity_before": o["integrity"], "integrity_after": n["integrity"]})}
                ev["sha256"] = _sha(ev["excerpt"])
                findings.append(_finding(
                    "SC1", "suspicious", "HIGH",
                    f"{pkg_name(k)}@{n.get('version')} tarball hash changed without a version change",
                    f"Commit {sha[:10]} ({day}, {author}: \"{subject}\") replaced the integrity hash of the same "
                    "version. A registry version is immutable, so this means a different tarball is being trusted.",
                    ev, cid, "Restore the registry integrity value (npm view <pkg>@<ver> dist.integrity) and review the commit."))
            if same_ver and n.get("resolved") != o.get("resolved") and n.get("resolved") \
                    and not n["resolved"].startswith(REGISTRY):
                ev = {**base_ev, "line": lines.get(k), "excerpt": json.dumps(
                    {**diff, "resolved_before": o.get("resolved"), "resolved_after": n["resolved"]})}
                ev["sha256"] = _sha(ev["excerpt"])
                findings.append(_finding(
                    "SC2", "suspicious", "HIGH",
                    f"{pkg_name(k)} download source moved off the npm registry",
                    f"Commit {sha[:10]} changed resolved URL from {o.get('resolved')} to {n['resolved']} "
                    "with no version change.", ev, cid, "Revert the resolved URL to the npm registry."))
        changes[-1]["hash_algorithm_upgrades"] = algo_upgrades
        for k in added:
            if new[k].get("hasInstallScript"):
                cid = make_purl(pkg_name(k), new[k].get("version", "?"))
                ev = {**base_ev, "line": lines.get(k), "excerpt": json.dumps({k: new[k].get("version")})}
                ev["sha256"] = _sha(ev["excerpt"])
                findings.append(_finding(
                    "SC3", "suspicious", "MEDIUM", f"New dependency with install script: {pkg_name(k)}",
                    f"Added in commit {sha[:10]} ({day})", ev, cid, "Review before installing."))
    return findings, changes


# ---------- containers ----------

def _parse_image(ref):
    digest = "@sha256:" in ref
    base = ref.split("@")[0]
    name, _, tag = base.rpartition(":") if ":" in base.split("/")[-1] else (base, "", "")
    return name.split("/")[-1], tag or "latest", digest


def _image_checks(ref, ev, today):
    out = []
    if ref.startswith("$") or "${" in ref:
        return out
    name, tag, digest = _parse_image(ref)
    if not digest:
        out.append(_finding(
            "CT1", "container", "MEDIUM", f"Image {ref} is not pinned to a digest",
            f'tag "{tag}" is mutable: the image behind it can change on every pull', ev,
            fix=f"Pin as {ref}@sha256:<digest>"))
    m = re.match(r"(\d+)(?:\.(\d+))?", tag)
    if name in EOL and m:
        for key in (f"{m.group(1)}.{m.group(2)}" if m.group(2) else None, m.group(1)):
            if key and key in EOL[name]:
                eol = EOL[name][key]
                if date.fromisoformat(eol) < today:
                    out.append(_finding(
                        "CT2", "container", "HIGH", f"{name} {key} is end-of-life (since {eol})",
                        f"{ref} no longer receives security fixes", ev,
                        fix=f"Move to a supported {name} release"))
                break
    return out


def dockerfiles(repo, today=None):
    today = today or date.today()
    out = []
    for p, rel in _files(repo, lambda p: p.name.startswith("Dockerfile")):
        text = p.read_text(errors="replace")
        fsha = _sha(text)
        # join line continuations, keep the first line number
        logical, buf, start = [], "", None
        for i, line in enumerate(text.splitlines(), 1):
            if start is None:
                start = i
            buf += line.rstrip("\\").rstrip() + " "
            if not line.rstrip().endswith("\\"):
                logical.append((start, buf.strip())); buf, start = "", None
        final_user = None
        for ln, ins in logical:
            ev = {"source": "file", "path": rel, "line": ln, "sha256": fsha, "excerpt": ins[:200]}
            up = ins.upper()
            if up.startswith("FROM "):
                final_user = None
                img = ins.split()[1]
                if not re.fullmatch(r"\d+", img):   # skip "FROM 0"-style stage refs
                    out += _image_checks(img, ev, today)
            elif up.startswith("USER "):
                final_user = ins.split()[1]
            if re.search(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b", ins) or \
                    re.match(r"ADD\s+https?://", ins, re.I):
                out.append(_finding("CT4", "container", "HIGH", "Remote content executed or added at build time",
                                    "Build depends on an unpinned remote script/file", ev,
                                    fix="Download a pinned version and verify its checksum"))
            if re.search(r"\bnpm (install|i)\b", ins) and "npm ci" not in ins:
                out.append(_finding("CT5", "container", "MEDIUM", "Image build uses `npm install`, not `npm ci`",
                                    "`npm install` may resolve versions differently from the committed lockfile",
                                    ev, fix="Use `npm ci --omit=dev` so the build installs exactly the lockfile"))
        if final_user in (None, "root", "0"):
            out.append(_finding("CT3", "container", "MEDIUM", "Final image runs as root",
                                "No non-root USER in the final stage",
                                {"source": "file", "path": rel, "line": None, "sha256": fsha, "excerpt": ""},
                                fix="Add a non-root USER"))
    for p, rel in _files(repo, lambda p: re.match(r"(docker-)?compose.*\.ya?ml$", p.name)):
        text = p.read_text(errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            m = re.match(r"\s*image:\s*['\"]?([^\s'\"#]+)", line)
            if m:
                out += _image_checks(m.group(1), {"source": "file", "path": rel, "line": i,
                                                  "sha256": _sha(text), "excerpt": line.strip()}, today)
    return out


# ---------- CI/CD (GitHub Actions) ----------

def workflows(repo, today=None):
    today = today or date.today()
    out = []
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        return out
    for p in sorted(wf_dir.glob("*.y*ml")):
        rel, text = str(p.relative_to(repo)), p.read_text(errors="replace")
        fsha, lines = _sha(text), text.splitlines()
        ev = lambda i, s: {"source": "file", "path": rel, "line": i, "sha256": fsha, "excerpt": s.strip()[:200]}
        if not any(re.match(r"\s*permissions\s*:", l) for l in lines):
            out.append(_finding("CI2", "ci", "MEDIUM", f"{p.name}: no `permissions:` block",
                                "The GITHUB_TOKEN gets the repository's default permissions, which may include write access",
                                ev(None, ""), fix="Add `permissions: contents: read` at workflow level"))
        run_indent = None
        for i, line in enumerate(lines, 1):
            indent = len(line) - len(line.lstrip())
            if run_indent is not None and line.strip() and indent <= run_indent:
                run_indent = None
            m = re.match(r"\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", line)
            if m and not m.group(1).startswith(("./", "docker://")):
                action, _, ref = m.group(1).partition("@")
                if not re.fullmatch(r"[0-9a-f]{40}", ref):
                    out.append(_finding(
                        "CI1", "ci", "MEDIUM", f"Action {action}@{ref or '(none)'} is not pinned to a commit SHA",
                        "Tags are mutable; whoever controls the action repo can change what runs in your CI", ev(i, line),
                        fix=f"Pin {action} to a full commit SHA (keep the tag as a comment)"))
            if re.search(r"^\s*(on:.*pull_request_target|pull_request_target\s*:)", line):
                out.append(_finding("CI3", "ci", "HIGH", f"{p.name}: pull_request_target trigger",
                                    "Runs with repository secrets on code from forks", ev(i, line),
                                    fix="Use pull_request, or never check out the PR head in this workflow"))
            if re.match(r"\s*-?\s*run\s*:", line):
                run_indent = indent
            in_run = run_indent is not None or re.match(r"\s*-?\s*run\s*:", line)
            if in_run and re.search(r"\$\{\{\s*github\.event\.", line):
                out.append(_finding("CI4", "ci", "HIGH", f"{p.name}: untrusted event data in a shell step",
                                    "github.event.* values can be attacker-controlled (script injection)", ev(i, line),
                                    fix="Pass it through an env variable and quote it"))
            if in_run:
                d = re.search(r"docker run\b.*\s([a-z0-9][a-z0-9./_-]*:[\w.-]+)\s*$", line)
                if d and not re.fullmatch(r"\d+:\d+", d.group(1)):
                    out += _image_checks(d.group(1), ev(i, line), today)
                if re.search(r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b", line):
                    out.append(_finding("CT4", "ci", "HIGH", "Remote script piped to a shell in CI",
                                        "Unpinned remote code runs with CI credentials", ev(i, line),
                                        fix="Pin and checksum-verify the script"))
    return out


# ---------- entry point ----------

STATUS_RANK = {"clean": 0, "maintenance": 1, "suspicious": 2, "vulnerable": 3}


def other_ecosystem_specs(repo, comps):
    """Floating or unpinned sources outside npm: requirements ranges / VCS URLs, git deps on branches."""
    out = []
    for c in comps.values():
        if c.relationship != "direct":
            continue
        src = c.source_url or ""
        if c.ecosystem == "pypi" and c.resolution == "declared-only":
            vcs = src.startswith(("git+", "http")) and not re.search(r"@[0-9a-f]{40}", src)
            why = (f"installed from {src[:120]}, not an immutable release or commit" if vcs else
                   "not pinned to an exact version: every install can resolve a different release")
            out.append(_finding("SC4", "suspicious", "MEDIUM" if (vcs or c.scope == "prod") else "LOW",
                                f"{c.name}: floating Python requirement", why,
                                {"source": "file", "path": (c.found_in or [""])[0], "line": None, "sha256": "",
                                 "excerpt": f"{c.name} {src if vcs else ''}".strip()},
                                c.component_id, "Pin with == (pip-compile / uv lock) and use hashes."))
        if c.ecosystem == "git" and not re.fullmatch(r"[0-9a-f]{40}", c.version or ""):
            out.append(_finding("SC2", "suspicious", "HIGH" if c.version in ("main", "master", "") else "MEDIUM",
                                f"{c.name} is a git dependency on a moving ref",
                                f"version '{c.version or 'unspecified'}' is a branch/tag, so its contents can change "
                                "without any change in this repository (a moving branch)",
                                {"source": "file", "path": (c.found_in or [""])[0], "line": None, "sha256": "",
                                 "excerpt": f"{c.source_url} @ {c.version or '?'}"},
                                c.component_id, "Pin to a full commit SHA."))
    return out


def run_detectors(repo_path, inv, comps, history=20):
    """inv: the inventory dict (or, for backwards compatibility, an npm lockfile path)."""
    repo = Path(repo_path)
    if isinstance(inv, dict):
        locks, projects = inv.get("npm_lockfiles", []), inv.get("projects", [])
    else:
        locks, projects = ([inv] if inv else []), []
    findings, changes = [], []
    for lock_rel in locks:
        findings += lockfile_current(repo, lock_rel, comps) + lockfile_consistency(repo, lock_rel, comps)
        if history:
            h, ch = lockfile_history(repo, lock_rel, history)
            findings += h
            changes += [dict(x, lockfile=lock_rel) for x in ch]
    pj_dirs = {str(Path(p["manifest"]).parent) for p in projects if p["ecosystem"] == "npm"} or ({"."} if locks else set())
    for d in sorted(pj_dirs):
        findings += package_json_specs(repo, comps, str(Path(d) / "package.json"))
    findings += other_ecosystem_specs(repo, comps) + dockerfiles(repo) + workflows(repo)
    # component status: never downgrade a "vulnerable" component
    for f in findings:
        c = comps.get(f["component_id"]) if f["component_id"] else None
        if c:
            new = "maintenance" if f["category"] == "maintenance" else "suspicious"
            cur = c.risk_status if c.risk_status in STATUS_RANK else "clean"
            if STATUS_RANK[new] > STATUS_RANK[cur]:
                c.risk_status = new
    return findings, changes
