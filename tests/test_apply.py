import subprocess
import tempfile
import unittest
from pathlib import Path

from guardian.agents.state import RunState
from guardian.remediation import apply_verified

REQS = "anyio==4.7.0\nflask==3.1.0\nrequests==2.32.3\nsix==1.17.0\ntorch==2.5.1\n"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def cand(cid, old, new, summary):
    return {"candidate_id": cid, "summary": summary, "closes": [f"F-{cid}"], "rollback": "revert",
            "files": {"requirements.txt": (old, new)}, "needs_lockfile_regen": False}


def setup(verdicts, dirty=False):
    d = Path(tempfile.mkdtemp())
    repo = d / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(REQS)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "init")
    if dirty:
        (repo / "requirements.txt").write_text(REQS + "extra==1.0\n")
    s = RunState(repo, d / "out")
    cands = {
        "FIX-A": cand("FIX-A", REQS, REQS.replace("torch==2.5.1", "torch==2.6.0"), "Upgrade torch"),
        "FIX-B": cand("FIX-B", REQS, REQS.replace("anyio==4.7.0", "anyio==4.14.2"), "Upgrade anyio"),
        "FIX-C": cand("FIX-C", REQS, REQS.replace("torch==2.5.1", "torch==2.7.0"), "Other torch"),
    }
    s.validations = [{"candidate_id": c, "verdict": v} for c, v in verdicts.items()]
    s.approvals = {c: {"status": "approved", "by": "tester"} for c in verdicts}
    return s, repo, cands


class ApplyTests(unittest.TestCase):
    def test_verified_fixes_merge_into_one_file_on_a_local_branch(self):
        s, repo, cands = setup({"FIX-A": "verified", "FIX-B": "verified"})
        recs = apply_verified(s, cands)
        self.assertEqual([r["status"] for r in recs], ["applied", "applied"])
        text = (repo / "requirements.txt").read_text()
        self.assertIn("torch==2.6.0", text)
        self.assertIn("anyio==4.14.2", text)
        branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
        self.assertTrue(branch.startswith("guardian/remediation-"))
        self.assertEqual(git(repo, "rev-list", "--count", "main..HEAD"), "2")
        self.assertEqual(git(repo, "status", "--porcelain"), "")
        self.assertIn("Guardian fix: Upgrade anyio", git(repo, "log", "-1", "--format=%B"))
        self.assertIn("torch==2.6.0", (s.out / "remediation.patch").read_text())
        self.assertEqual(apply_verified(s, cands), [])          # idempotent

    def test_only_verified_fixes_are_applied(self):
        s, repo, cands = setup({"FIX-A": "partial", "FIX-B": "failed"})
        self.assertEqual(apply_verified(s, cands), [])
        self.assertEqual((repo / "requirements.txt").read_text(), REQS)
        self.assertEqual(git(repo, "rev-parse", "--abbrev-ref", "HEAD"), "main")

    def test_conflicting_fix_is_reported_not_overwritten(self):
        s, repo, cands = setup({"FIX-A": "verified", "FIX-C": "verified"})
        recs = apply_verified(s, cands)
        self.assertEqual([r["status"] for r in recs], ["applied", "conflict"])
        self.assertIn("torch==2.6.0", (repo / "requirements.txt").read_text())

    def test_uncommitted_local_changes_are_never_touched(self):
        s, repo, cands = setup({"FIX-A": "verified"}, dirty=True)
        recs = apply_verified(s, cands)
        self.assertEqual(recs[0]["status"], "skipped")
        self.assertIn("extra==1.0", (repo / "requirements.txt").read_text())
        self.assertIn("torch==2.5.1", (repo / "requirements.txt").read_text())
        self.assertEqual(git(repo, "rev-parse", "--abbrev-ref", "HEAD"), "main")

    def test_npm_fix_applies_the_lockfile_regenerated_during_validation(self):
        s, repo, _ = setup({"FIX-N": "verified", "FIX-M": "verified"})
        pj, lock = '{"dependencies": {"bson": "1.0.4"}}\n', '{"lockfileVersion": 2, "bson": "1.0.4"}\n'
        (repo / "package.json").write_text(pj); (repo / "package-lock.json").write_text(lock)
        git(repo, "add", "."); git(repo, "commit", "-qm", "npm")
        base = s.out / "validation" / "baseline"; base.mkdir(parents=True); (base / "package-lock.json").write_text(lock)
        cands = {}
        for cid, ver in (("FIX-N", "1.1.4"), ("FIX-M", "1.1.5")):
            work = s.out / "validation" / cid; work.mkdir(parents=True)
            (work / "package-lock.json").write_text(lock.replace("1.0.4", ver))
            cands[cid] = {"candidate_id": cid, "summary": f"bson {ver}", "closes": [], "rollback": "revert",
                          "needs_lockfile_regen": True, "files": {"package.json": (pj, pj.replace("1.0.4", ver))}}
        recs = apply_verified(s, cands)
        self.assertEqual([r["status"] for r in recs], ["applied", "conflict"])   # 2nd lockfile was built from the old one
        self.assertEqual(recs[0]["files"], ["package-lock.json", "package.json"])
        self.assertIn("1.1.4", (repo / "package-lock.json").read_text())
        self.assertIn("1.1.4", (repo / "package.json").read_text())


if __name__ == "__main__":
    unittest.main()
