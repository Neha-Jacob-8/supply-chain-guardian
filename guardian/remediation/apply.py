"""Apply verified fixes to the target repository (after human approval and independent validation).

Only fixes whose validation verdict is `verified` are applied, and exactly the files the validator
checked (the candidate's changes plus any lockfile it regenerated in the sandbox). In a git repository
the changes go onto a new local branch `guardian/remediation-<time>`, one commit per fix, with git hooks
disabled. Nothing is pushed. Several fixes to the same file are combined with a three-way merge; a fix
that conflicts is reported and left out instead of overwriting another fix.
"""
import subprocess
import tempfile
import time
from pathlib import Path

GIT_ENV = {"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin"}
AUTHOR = ["-c", "user.name=Supply Chain Guardian", "-c", "user.email=guardian@localhost", "-c", "core.hooksPath=/dev/null"]


def _git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *AUTHOR, *args], capture_output=True, text=True, timeout=60, env=GIT_ENV)
    return r.returncode, (r.stdout + r.stderr).strip()


def _is_git(repo):
    return _git(repo, "rev-parse", "--is-inside-work-tree")[0] == 0 and (Path(repo) / ".git").exists()


def validated_files(cand, work, baseline):
    """{path: (old, new, strict)} as validated: the candidate's files plus lockfiles regenerated next to them.

    A regenerated lockfile is `strict`: it is applied only if the repository still has the lockfile the
    validator started from, because two independently regenerated lockfiles cannot be merged line by line.
    """
    files = {p: (old, new, False) for p, (old, new) in cand["files"].items()}
    if cand.get("needs_lockfile_regen"):
        for p in [p for p in cand["files"] if p.endswith("package.json")]:
            lock = str(Path(p).parent / "package-lock.json")
            lock = lock[2:] if lock.startswith("./") else lock
            src, orig = Path(work) / lock, Path(baseline) / lock
            if src.exists():
                files[lock] = (orig.read_text() if orig.exists() else "", src.read_text(), True)
    return files


def _merge(current, base, new):
    """Three-way merge of `new` (validated against `base`) into `current`. Returns text or None on conflict."""
    if current == base:
        return new
    if current == new:
        return current
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for name, text in (("current", current), ("base", base), ("new", new)):
            p = Path(d) / name
            p.write_text(text)
            paths.append(str(p))
        r = subprocess.run(["git", "merge-file", "-p", *paths], capture_output=True, text=True, timeout=60, env=GIT_ENV)
    return r.stdout if r.returncode == 0 else None


def apply_verified(state, cands_by_id):
    """Apply every verified, not yet applied fix. Returns the new apply records."""
    repo = Path(state.repo)
    done = {a["candidate_id"] for a in state.applied if a["status"] == "applied"}
    todo = [v for v in state.validations if v["verdict"] == "verified" and v["candidate_id"] not in done
            and v["candidate_id"] in cands_by_id]
    if not todo:
        return []
    git = _is_git(repo)
    branch = None
    baseline = state.out / "validation" / "baseline"
    if git:
        touched = sorted({p for v in todo for p in validated_files(cands_by_id[v["candidate_id"]],
                                                                    state.out / "validation" / v["candidate_id"], baseline)})
        rc, dirty = _git(repo, "status", "--porcelain", "--", *touched)
        if rc != 0 or dirty:
            rec = [{"candidate_id": v["candidate_id"], "status": "skipped", "files": [],
                    "detail": f"uncommitted local changes in {', '.join(touched)}; commit or stash them, then resume"}
                   for v in todo]
            state.applied += rec
            return rec
        rc, cur = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
        if cur.startswith("guardian/remediation"):
            branch = cur
        else:
            branch = "guardian/remediation-" + time.strftime("%Y%m%d-%H%M%S")
            rc, out = _git(repo, "switch", "-c", branch)
            if rc != 0:
                rec = [{"candidate_id": v["candidate_id"], "status": "skipped", "files": [],
                        "detail": f"could not create branch {branch}: {out[-300:]}"} for v in todo]
                state.applied += rec
                return rec

    records = []
    for v in todo:
        cid = v["candidate_id"]
        cand = cands_by_id[cid]
        files = validated_files(cand, state.out / "validation" / cid, baseline)
        merged, conflict = {}, None
        for path, (old, new, strict) in files.items():
            target = repo / path
            current = target.read_text() if target.exists() else ""
            text = (new if current in (old, new) else None) if strict else _merge(current, old, new)
            if text is None:
                conflict = path
                break
            merged[path] = text
        if conflict:
            rec = {"candidate_id": cid, "summary": cand["summary"], "status": "conflict", "files": [],
                   "detail": f"{conflict} conflicts with a fix applied earlier; re-run the analysis to rebuild this fix"}
        else:
            for path, text in merged.items():
                (repo / path).write_text(text)
            rec = {"candidate_id": cid, "summary": cand["summary"], "status": "applied", "files": sorted(merged),
                   "branch": branch, "commit": None,
                   "detail": "applied to the working tree" + (f" on local branch {branch}" if branch else " (not a git repository)")}
            if git:
                _git(repo, "add", "--", *merged)
                msg = (f"Guardian fix: {cand['summary']}\n\nCandidate: {cid}\nCloses: {', '.join(cand['closes'][:20])}\n"
                       f"Approved by: {state.approvals.get(cid, {}).get('by', 'human reviewer')}\n"
                       f"Validation: {v['verdict']} (independent validation agent)\nRollback: {cand['rollback']}")
                rc, out = _git(repo, "commit", "--no-verify", "-m", msg, "--", *merged)
                if rc == 0:
                    rec["commit"] = _git(repo, "rev-parse", "--short", "HEAD")[1]
                elif "nothing to commit" in out or "no changes added" in out:
                    rec["detail"] = "already present in the repository; nothing to commit"
                else:
                    rec["detail"] += f"; commit failed: {out[-300:]}"
        state.log("orchestrator", "apply", {k: rec.get(k) for k in ("candidate_id", "status", "branch", "commit", "detail")})
        records.append(rec)
    state.applied += records
    if git and any(r["status"] == "applied" for r in records):
        rc, patch = _git(repo, "format-patch", "--stdout", f"{_base_ref(repo, branch)}..{branch}")
        if rc == 0 and patch:
            (state.out / "remediation.patch").write_text(patch + "\n")
    return records


def _base_ref(repo, branch):
    """The commit the remediation branch started from (first parent of its first Guardian commit)."""
    rc, log = _git(repo, "log", "--format=%H %s", branch)
    shas = [line.split(" ", 1)[0] for line in log.splitlines() if " " in line and line.split(" ", 1)[1].startswith("Guardian fix:")]
    return f"{shas[-1]}~1" if shas else branch
