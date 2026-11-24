"""Repository ingestion: validate a GitHub URL and clone it safely.

Safety: only https://github.com/<owner>/<repo>; git hooks disabled; no submodule recursion;
no credential prompts; limited history depth (enough for lockfile "what changed" analysis);
nothing from the repository is executed.
"""
import os
import re
import subprocess
from pathlib import Path

GITHUB = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
GITHUB_DOMAIN = re.compile(r"^github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
GITHUB_SHORTHAND = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$")


def _git(repo, *args):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )


def _canonical_remote(url):
    """Return owner/repository for accepted HTTPS and common GitHub git URL forms."""
    value = (url or "").strip().removesuffix(".git").rstrip("/")
    value = re.sub(r"^git@github\.com:", "https://github.com/", value)
    value = re.sub(r"^ssh://git@github\.com/", "https://github.com/", value)
    match = re.search(r"github\.com/([^/]+)/([^/]+)$", value, re.I)
    return f"{match.group(1).lower()}/{match.group(2).lower()}" if match else None


def repository_identity(repo):
    """Return the immutable target identity recorded with approvals and reports."""
    repo = Path(repo)
    remote = _git(repo, "config", "--get", "remote.origin.url")
    head = _git(repo, "rev-parse", "HEAD")
    status = _git(repo, "status", "--porcelain", "--untracked-files=no")
    remote_url = remote.stdout.strip() if remote.returncode == 0 else None
    return {
        "path": str(repo.resolve()),
        "remote": remote_url,
        "remote_id": _canonical_remote(remote_url),
        "commit": head.stdout.strip() if head.returncode == 0 else None,
        "dirty": bool(status.stdout.strip()) if status.returncode == 0 else None,
    }


def _matches_remote(dest, owner, repo):
    if not (dest / ".git").is_dir():
        return False
    current = _git(dest, "config", "--get", "remote.origin.url")
    return current.returncode == 0 and _canonical_remote(current.stdout) == f"{owner.lower()}/{repo.lower()}"


def parse_github_url(url):
    val = url.strip()
    m = GITHUB.match(val) or GITHUB_DOMAIN.match(val)
    if not m and not val.startswith(("http://", "https://", "git@", "ssh://", "file://", "/", "./", "../")):
        if not Path(val).exists():
            m = GITHUB_SHORTHAND.match(val)
    if not m or m.group(1) in (".", "..") or m.group(2) in (".", ".."):
        raise ValueError("only public https://github.com/<owner>/<repo> URLs or owner/repo shorthand are accepted")
    return m.group(1), m.group(2)


def clone(url, dest_root="targets", depth=50, ref=None):
    owner, repo = parse_github_url(url)
    dest = Path(dest_root) / repo
    if dest.exists():
        if _matches_remote(dest, owner, repo):
            return dest                   # preserve local demo branches; never overwrite local work
        # Different owners can use the same repository name. Never scan the wrong checkout silently.
        dest = Path(dest_root) / f"{owner}--{repo}"
        if dest.exists():
            if _matches_remote(dest, owner, repo):
                return dest
            raise RuntimeError(f"clone destination {dest} exists but does not match {owner}/{repo}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
           "clone", "--depth", str(depth), "--no-recurse-submodules", "--single-branch"]
    if ref:
        cmd += ["--branch", ref]
    r = subprocess.run(cmd + [f"https://github.com/{owner}/{repo}.git", str(dest)],
                       capture_output=True, text=True, env=env, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"clone failed: {r.stderr.strip()[-300:]}")
    return dest


def resolve_target(target, dest_root="targets"):
    """A local path is used as-is; a GitHub URL or owner/repo shorthand is cloned (or reused) under dest_root."""
    t = target.strip()
    if t.startswith(("http://", "https://", "git@", "ssh://", "file://")):
        return clone(t, dest_root)
    p = Path(t)
    if p.is_dir():
        return p
    if GITHUB_DOMAIN.match(t) or GITHUB_SHORTHAND.match(t):
        return clone(t, dest_root)
    raise ValueError(f"{target} is neither a directory nor a GitHub URL")
