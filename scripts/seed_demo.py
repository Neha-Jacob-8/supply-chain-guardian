"""Seed a *local* demo branch in a target clone with a simulated lockfile tamper.

Creates branch `guardian-demo` with one commit that:
  - replaces express's integrity hash (same version)  -> SC1
  - points body-parser at a non-registry mirror        -> SC2
The mirror uses the reserved `.example` domain, so nothing can ever be fetched from it.
Nothing is pushed. Return to normal with: git -C <repo> checkout master

usage: python3 scripts/seed_demo.py targets/NodeGoat
"""
import base64, hashlib, re, subprocess, sys
from pathlib import Path

BRANCH = "guardian-demo"


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, "-c", "core.hooksPath=/dev/null", *args],
                          check=True, capture_output=True, text=True).stdout


def replace_in_block(text, key, field, new_value):
    m = re.search(r'\n {4}"' + re.escape(key) + r'": \{(.*?)\n {4}\}', text, re.S)
    if not m:
        sys.exit(f"{key} not found in lockfile")
    block = m.group(0)
    new_block, n = re.subn(r'("' + field + r'": )"[^"]*"', lambda mm: f'{mm.group(1)}"{new_value}"', block, count=1)
    if n != 1:
        sys.exit(f"{field} not found for {key}")
    return text.replace(block, new_block)


def main(repo):
    lock = Path(repo) / "package-lock.json"
    if BRANCH in git(repo, "branch", "--list", BRANCH):
        sys.exit(f"branch {BRANCH} already exists; delete it with: git -C {repo} branch -D {BRANCH}")
    git(repo, "checkout", "-q", "-b", BRANCH)
    text = lock.read_text()
    fake = "sha512-" + base64.b64encode(hashlib.sha512(b"guardian-demo-tamper").digest()).decode()
    text = replace_in_block(text, "node_modules/express", "integrity", fake)
    bp_ver = re.search(r'"node_modules/body-parser": \{\s*"version": "([^"]+)"', text).group(1)
    text = replace_in_block(text, "node_modules/body-parser", "resolved",
                            f"https://npm-mirror.example/body-parser/-/body-parser-{bp_ver}.tgz")
    lock.write_text(text)
    git(repo, "-c", "user.name=Demo Seeder", "-c", "user.email=demo@example.invalid",
        "commit", "-q", "-am", "chore: refresh lockfile")
    print(f"Seeded {BRANCH} in {repo}:\n" + git(repo, "log", "-1", "--stat", "--format=%h %s"))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "targets/NodeGoat")
