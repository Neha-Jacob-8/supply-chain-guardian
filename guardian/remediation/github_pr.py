"""GitHub App integration: authenticate with a .pem private key, fork (if external),
push a Dependabot-style remediation branch, and open a Pull Request.

Configuration (from .env or environment):
  GITHUB_APP_ID               Numeric GitHub App ID
  GITHUB_APP_PRIVATE_KEY_PATH Path to the GitHub App .pem private key file
                              (auto-discovers *.pem in workspace root if unset)
  GITHUB_APP_INSTALLATION_ID  Optional installation ID (auto-discovered via /app/installations if unset)
"""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

GH_API = "https://api.github.com"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def resolve_pem_path(explicit_path: str | None = None) -> Path:
    cand = explicit_path or os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "").strip()
    if cand and Path(cand).is_file():
        return Path(cand)
    raw_pem = os.environ.get("GITHUB_APP_PRIVATE_KEY", "").strip()
    if raw_pem:
        tf = Path(tempfile.gettempdir()) / "guardian-app-key.pem"
        tf.write_text(raw_pem.replace("\\n", "\n"), encoding="utf-8")
        try:
            os.chmod(tf, 0o600)
        except OSError:
            pass
        return tf
    # Auto-discover a .pem file in the current working directory if present
    pems = sorted(Path(".").glob("*.pem"))
    if pems:
        return pems[0]
    raise RuntimeError("GitHub App private key (.pem) not found. Set GITHUB_APP_PRIVATE_KEY_PATH in .env.")


def create_app_jwt(app_id: str, pem_path: Path) -> str:
    """Sign an RS256 GitHub App JWT using `/usr/bin/openssl` (zero external Python deps)."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(pem_path)],
        input=signing_input,
        capture_output=True,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"OpenSSL RS256 signing failed: {proc.stderr.decode(errors='replace').strip()}")
    return f"{header}.{payload}.{_b64url(proc.stdout)}"


def _gh_request(method: str, path_or_url: str, token: str, body: dict | None = None) -> tuple[int, dict | list]:
    url = path_or_url if path_or_url.startswith("http") else f"{GH_API}{path_or_url}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "supply-chain-guardian-app",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", errors="replace")
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            err_json = json.loads(raw)
        except Exception:
            err_json = {"message": raw}
        return e.code, err_json


def get_installation_token(app_id: str, pem_path: Path, installation_id: str | None = None, owner_repo: str | None = None) -> tuple[str, str]:
    """Exchange a GitHub App JWT for an installation access token. Returns (token, installation_id)."""
    app_jwt = create_app_jwt(app_id, pem_path)
    inst_id = installation_id or os.environ.get("GITHUB_APP_INSTALLATION_ID", "").strip()
    if not inst_id and owner_repo:
        st, data = _gh_request("GET", f"/repos/{owner_repo}/installation", app_jwt)
        if st == 200 and isinstance(data, dict) and data.get("id"):
            inst_id = str(data["id"])
    if not inst_id:
        st, installs = _gh_request("GET", "/app/installations", app_jwt)
        if st != 200 or not isinstance(installs, list) or not installs:
            raise RuntimeError(f"Could not find GitHub App installations (HTTP {st}): {installs}")
        inst_id = str(installs[0]["id"])
    st, tok_data = _gh_request("POST", f"/app/installations/{inst_id}/access_tokens", app_jwt, {})
    if st not in (200, 201) or not isinstance(tok_data, dict) or not tok_data.get("token"):
        raise RuntimeError(f"Failed to create GitHub App installation token (HTTP {st}): {tok_data}")
    return tok_data["token"], inst_id


def _parse_owner_repo(remote_url: str) -> tuple[str, str]:
    m = re.search(r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$", (remote_url or "").strip(), re.I)
    if not m:
        raise RuntimeError(f"Repository remote '{remote_url}' is not a GitHub repository.")
    return m.group(1), m.group(2)


def _git(repo: Path, *args: str, env_extra: dict | None = None) -> tuple[int, str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env_extra or {})}
    r = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out.strip()


def _sanitize(text: str, token: str) -> str:
    return text.replace(token, "***") if token else text


def _dependabot_branch_name(summary_items: list[dict]) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    if len(summary_items) == 1:
        slug = re.sub(r"[^a-z0-9._-]+", "-", (summary_items[0].get("action") or "fix").lower()).strip("-")[:36]
        return f"guardian/deps/{slug}-{ts}"
    return f"guardian/security-updates-{len(summary_items)}-fixes-{ts}"


def _build_pr_body(report_data: dict, branch: str) -> str:
    exec_md = ((report_data.get("executive_narrative") or {}).get("markdown") or "").strip()
    actions = (report_data.get("executive_narrative") or {}).get("actions") or []
    lines = [
        "## Supply Chain Guardian — Automated Security & Dependency Remediation",
        "",
        f"Branch: `{branch}`",
        "",
    ]
    if exec_md:
        lines += [exec_md, ""]
    if actions:
        lines += [
            "### Verified Changes Included",
            "| Candidate | Change | Verdict | Outcome |",
            "|---|---|---|---|",
        ]
        for a in actions:
            lines.append(f"| `{a.get('candidate_id')}` | {a.get('action')} | **{a.get('verdict')}** | {a.get('outcome')} |")
        lines.append("")
    lines += [
        "---",
        "*Generated and verified independently by **Supply Chain Guardian** (`supply-chain-guardian[bot]`).*",
    ]
    return "\n".join(lines)


def create_remediation_pr(
    repo_path: str | Path,
    out_dir: str | Path,
    app_id: str | None = None,
    pem_path: str | None = None,
    installation_id: str | None = None,
) -> dict:
    """Fork (if needed), commit validated changes to a Dependabot-style branch, push, and raise a GitHub PR."""
    repo = Path(repo_path)
    out = Path(out_dir)
    aid = (
        app_id
        or os.environ.get("GITHUB_APP_CLIENT_ID", "")
        or os.environ.get("GITHUB_APP_ID", "")
    ).strip()
    if not aid:
        raise RuntimeError("GITHUB_APP_CLIENT_ID or GITHUB_APP_ID is not set in .env or environment.")
    pem = resolve_pem_path(pem_path)

    rc, remote_url = _git(repo, "config", "--get", "remote.origin.url")
    if rc != 0 or not remote_url:
        raise RuntimeError("Target repository has no GitHub remote.origin.url configured.")
    owner, repo_name = _parse_owner_repo(remote_url)
    owner_repo = f"{owner}/{repo_name}"

    token, used_inst = get_installation_token(aid, pem, installation_id, owner_repo=owner_repo)

    # Fetch upstream metadata (default branch)
    st, repo_meta = _gh_request("GET", f"/repos/{owner_repo}", token)
    if st != 200 or not isinstance(repo_meta, dict):
        raise RuntimeError(f"Could not read GitHub repo {owner_repo} (HTTP {st}): {repo_meta}")
    base_branch = repo_meta.get("default_branch") or "main"

    # Attempt fork; if fork is same owner or disallowed, push directly to upstream branch
    fork_owner = owner
    push_owner_repo = owner_repo
    st_fork, fork_data = _gh_request("POST", f"/repos/{owner_repo}/forks", token, {})
    if st_fork in (200, 201, 202) and isinstance(fork_data, dict) and fork_data.get("full_name"):
        push_owner_repo = fork_data["full_name"]
        fork_owner = (fork_data.get("owner") or {}).get("login") or fork_owner
        if st_fork == 202:
            time.sleep(2)  # allow newly created GitHub fork to initialize

    report_path = out / "report.json"
    report_data = json.loads(report_path.read_text()) if report_path.exists() else {}
    actions = ((report_data.get("executive_narrative") or {}).get("actions")) or []
    branch = _dependabot_branch_name(actions)

    # Stage & commit any working-tree changes on the new branch
    _git(repo, "checkout", "-B", branch)
    rc_stat, dirty = _git(repo, "status", "--porcelain")
    if dirty:
        _git(repo, "add", "-A")
        n_fixes = len(actions)
        commit_title = (
            f"chore(deps): {actions[0]['action']}"
            if n_fixes == 1
            else f"chore(deps): remediate {n_fixes or 'security'} supply-chain finding(s)"
        )
        _git(
            repo,
            "-c", "user.name=supply-chain-guardian[bot]",
            "-c", "user.email=supply-chain-guardian[bot]@users.noreply.github.com",
            "commit", "--no-verify", "-m", commit_title,
        )

    push_url = f"https://x-access-token:{token}@github.com/{push_owner_repo}.git"
    rc_push, push_out = _git(repo, "push", "-u", push_url, f"{branch}:{branch}")
    if rc_push != 0:
        raise RuntimeError(f"Git push failed: {_sanitize(push_out[-300:], token)}")

    head_ref = f"{fork_owner}:{branch}" if push_owner_repo != owner_repo else branch
    pr_title = (
        f"chore(deps): {actions[0]['action']}"
        if len(actions) == 1
        else f"chore(deps): Supply Chain Guardian remediated {len(actions) or 1} security finding(s)"
    )
    pr_body = _build_pr_body(report_data, branch)
    st_pr, pr_data = _gh_request(
        "POST",
        f"/repos/{owner_repo}/pulls",
        token,
        {"title": pr_title, "head": head_ref, "base": base_branch, "body": pr_body},
    )
    if st_pr not in (200, 201) or not isinstance(pr_data, dict):
        raise RuntimeError(f"Failed to create Pull Request (HTTP {st_pr}): {pr_data}")

    return {
        "ok": True,
        "pr_url": pr_data.get("html_url"),
        "pr_number": pr_data.get("number"),
        "branch": branch,
        "head": head_ref,
        "base": base_branch,
        "fork": push_owner_repo,
        "upstream": owner_repo,
        "installation_id": used_inst,
    }
