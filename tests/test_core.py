import json
import subprocess
import tempfile
import unittest
from datetime import date
from pathlib import Path

from guardian.discovery.lockfile import pkg_name, make_purl, resolve
from guardian.intel.osv import cvss3_score, _matching_range, _semver_key
from guardian.intel.detectors import _hashes, _image_checks, lockfile_history, workflows, lockfile_consistency


class Lockfile(unittest.TestCase):
    def test_pkg_name_and_purl(self):
        self.assertEqual(pkg_name("node_modules/a/node_modules/@s/b"), "@s/b")
        self.assertEqual(make_purl("@s/b", "1.0.0"), "pkg:npm/%40s/b@1.0.0")

    def test_resolve_prefers_nested_then_walks_up(self):
        pk = {"": {}, "node_modules/a": {}, "node_modules/a/node_modules/c": {}, "node_modules/c": {}}
        self.assertEqual(resolve("node_modules/a", "c", pk), "node_modules/a/node_modules/c")
        self.assertEqual(resolve("node_modules/b", "c", pk), "node_modules/c")
        self.assertIsNone(resolve("node_modules/a", "zzz", pk))


class Vulns(unittest.TestCase):
    def test_cvss_known_scores(self):
        for vec, want in [("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
                          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
                          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]:
            self.assertEqual(cvss3_score(vec), want)
        self.assertIsNone(cvss3_score("garbage"))

    def test_semver_prerelease_sorts_before_release(self):
        self.assertLess(_semver_key("1.0.0-alpha.4"), _semver_key("1.0.0"))
        self.assertLess(_semver_key("0.3.9"), _semver_key("0.3.17"))

    def test_matching_range_picks_containing_interval(self):
        rec = {"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.3.1"}]}]}]}
        self.assertEqual(_matching_range(rec, "x", "2.1.0")[:2], ("2.0.0", "2.3.1"))
        self.assertEqual(_matching_range(rec, "x", "1.0.0")[:2], ("0", "1.2.0"))


class Detectors(unittest.TestCase):
    def test_hashes(self):
        self.assertEqual(_hashes("sha512-AA== sha1-BB"), {"sha512": "AA==", "sha1": "BB"})

    def test_eol_and_unpinned_image(self):
        rules = {f["rule_id"] for f in _image_checks("node:12-alpine", {}, date(2026, 1, 1))}
        self.assertEqual(rules, {"CT1", "CT2"})
        pinned = "node:22-alpine@sha256:" + "a" * 64
        self.assertEqual(_image_checks(pinned, {}, date(2026, 1, 1)), [])

    def test_action_pinning(self):
        with tempfile.TemporaryDirectory() as d:
            wf = Path(d, ".github/workflows"); wf.mkdir(parents=True)
            (wf / "ci.yml").write_text("on: push\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
                                       "      - uses: actions/checkout@v4\n"
                                       "      - uses: actions/setup-node@" + "b" * 40 + "\n"
                                       "      - run: echo ${{ github.event.issue.title }}\n")
            rules = [f["rule_id"] for f in workflows(Path(d))]
        self.assertEqual(sorted(rules), ["CI1", "CI4"])   # only the tag-pinned action; permissions present

    def _repo_with_history(self, before, after):
        d = tempfile.mkdtemp()
        g = lambda *a: subprocess.run(["git", "-C", d, "-c", "core.hooksPath=/dev/null",
                                       "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True, capture_output=True)
        g("init", "-q")
        lock = Path(d, "package-lock.json")
        for i, entry in enumerate((before, after)):
            lock.write_text(json.dumps({"packages": {"": {}, "node_modules/x": entry}}, indent=2))
            g("add", "."); g("commit", "-qm", f"c{i}")
        return Path(d)

    def test_sc1_flags_same_algorithm_change(self):
        repo = self._repo_with_history({"version": "1.0.0", "integrity": "sha512-AAA"},
                                       {"version": "1.0.0", "integrity": "sha512-BBB"})
        self.assertEqual([f["rule_id"] for f in lockfile_history(repo, "package-lock.json")[0]], ["SC1"])

    def test_sc1_ignores_hash_algorithm_upgrade(self):
        repo = self._repo_with_history({"version": "1.0.0", "integrity": "sha1-AAA"},
                                       {"version": "1.0.0", "integrity": "sha512-BBB"})
        findings, changes = lockfile_history(repo, "package-lock.json")
        self.assertEqual(findings, [])
        self.assertEqual(changes[0]["hash_algorithm_upgrades"], 1)

    def test_sc5_section_disagreement_but_not_url_versions(self):
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 2, "packages": {
            "": {}, "node_modules/a": {"version": "1.0.0", "integrity": "sha512-NEW"},
            "node_modules/u": {"version": "0.2.0", "resolved": "https://github.com/x/u/tarball/master"}},
            "dependencies": {"a": {"version": "1.0.0", "integrity": "sha512-OLD"},
                             "u": {"version": "https://github.com/x/u/tarball/master"}}}))
        found = lockfile_consistency(d, "package-lock.json", {})
        self.assertEqual([f["title"].split(":")[0] for f in found], ["a"])


if __name__ == "__main__":
    unittest.main()
