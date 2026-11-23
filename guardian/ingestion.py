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


def parse_github_url(url):
    m = GITHUB.match(url.strip())
    if not m or m.group(2) in (".", ".."):
        raise ValueError("only public https://github.com/<owner>/<repo> URLs are accepted")
    return m.group(1), m.group(2)


def clone(url, dest_root="targets", depth=50, ref=None):
    owner, repo = parse_github_url(url)
    dest = Path(dest_root) / repo
    if dest.exists():
        return dest                       # reuse an existing clone; never overwrite local work
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
    """A local path is used as-is; a GitHub URL is cloned (or reused) under dest_root."""
    if target.startswith(("http://", "https://", "git@", "ssh://", "file://")):
        return clone(target, dest_root)
    p = Path(target)
    if not p.is_dir():
        raise ValueError(f"{target} is neither a directory nor a GitHub URL")
    return p
