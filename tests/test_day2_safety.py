import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from guardian.agents.tools import redact
from guardian.remediation.candidates import _candidate, _insert_top_level_permissions, build_candidates
from guardian.validation.sandbox import _run, compose_policy_violations, runtime_check, validate


class Day2Safety(unittest.TestCase):
    def test_redacts_common_secret_forms(self):
        text = (
            'zapApiKey="abcd1234secret" API_KEY=unquoted-secret-value '
            'Authorization: Bearer abcdefghijklmnop github_pat_FAKEONLY123456789012345 '
            '-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----'
        )
        out = redact(text)
        self.assertNotIn("abcd1234secret", out)
        self.assertNotIn("unquoted-secret-value", out)
        self.assertNotIn("abcdefghijklmnop", out)
        self.assertNotIn("github_pat_FAKEONLY", out)
        self.assertNotIn("BEGIN PRIVATE KEY", out)

    def test_permissions_insert_after_complete_on_mapping(self):
        source = "name: CI\non:\n  push:\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        patched = _insert_top_level_permissions(source)
        self.assertIn("  push:\n  pull_request:\n\npermissions:\n", patched)
        self.assertLess(patched.index("pull_request"), patched.index("permissions:"))
        self.assertLess(patched.index("permissions:"), patched.index("jobs:"))

    def test_compose_policy_rejects_host_escape_requests(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            (work / "docker-compose.yml").write_text(
                "services:\n  app:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
            )
            violations = compose_policy_violations(work)
            self.assertTrue(any("privileged" in item for item in violations))
            self.assertTrue(any("docker.sock" in item for item in violations))

    def test_compose_policy_rejects_interpolated_and_nested_escape_paths(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            nested = work / "nested"
            nested.mkdir()
            (nested / "docker-compose.yml").write_text(
                "services:\n app:\n  build:\n   context: ../../outside\n  volumes:\n   - ${PWD}/secrets:/run/secrets\n"
            )
            violations = compose_policy_violations(work)
        self.assertTrue(any("outside the repository" in item for item in violations))
        self.assertTrue(any("host path" in item for item in violations))

    def test_missing_runtime_binary_is_a_failed_step_not_a_crash(self):
        result = _run(["guardian-test-command-that-does-not-exist"])
        self.assertEqual(result["rc"], 127)

    def test_untrusted_runtime_profile_is_static_only(self):
        state = SimpleNamespace(repo=Path("."), inventory={"projects": []}, identity={"remote_id": None})
        self.assertIsNone(__import__("guardian.validation.sandbox", fromlist=["smoke_profile"]).smoke_profile(state))
        steps, ok = runtime_check(Path("."), "test-project", None)
        self.assertIsNone(ok)
        self.assertIn("static only", steps[0]["detail"])

    def test_runtime_profile_requires_trusted_remote_identity(self):
        module = __import__("guardian.validation.sandbox", fromlist=["smoke_profile"])
        matching = SimpleNamespace(inventory={"projects": [{"name": "owasp-nodejs-goat"}]},
                                   identity={"remote_id": "owasp/nodegoat"})
        wrong_remote = SimpleNamespace(inventory={"projects": [{"name": "owasp-nodejs-goat"}]},
                                       identity={"remote_id": "someone/else"})
        self.assertIsNotNone(module.smoke_profile(matching))
        self.assertIsNone(module.smoke_profile(wrong_remote))

    def test_static_only_validation_is_partial_not_verified(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo, out = root / "repo", root / "out"
            repo.mkdir(); out.mkdir()
            (repo / "note.txt").write_text("old")
            state = SimpleNamespace(
                repo=repo, out=out, inventory={"projects": []}, comps={},
                by_id={"F1": {"finding_id": "F1", "rule_id": "SC6", "category": "suspicious",
                              "evidence": {"path": "note.txt"}, "component_id": None}},
                log=lambda *_args, **_kwargs: None,
            )
            candidate = _candidate("TEST", "note", "patch", "text change", {"note.txt": ("old", "new")},
                                   ["F1"], "low", "none", "restore")
            with patch("guardian.validation.sandbox.baseline", return_value=({}, [], {})), \
                    patch("guardian.validation.sandbox.scan_tree", return_value=({}, [])):
                result = validate(state, candidate, smoke=True, baseline_ok=True)
            self.assertEqual(result["verdict"], "partial")
            self.assertFalse(result["comparison"]["runtime_validated"])

    def test_candidate_hash_changes_with_exact_patch(self):
        a = _candidate("TEST", "x", "patch", "x", {"x": ("a", "b")}, [], "low", "", "")
        b = _candidate("TEST", "x", "patch", "x", {"x": ("a", "c")}, [], "low", "", "")
        self.assertNotEqual(a["candidate_id"], b["candidate_id"])
        self.assertNotEqual(a["diff_sha256"], b["diff_sha256"])

    def test_nodegoat_container_patch_is_not_generic(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            (repo / "Dockerfile").write_text("FROM node:12-alpine\nRUN npm install --production --no-cache\n")
            (repo / "docker-compose.yml").write_text("services:\n app:\n  image: mongo:4.4\n")
            findings = [{"finding_id": "CT2-X", "rule_id": "CT2", "evidence": {"path": "Dockerfile"}},
                        {"finding_id": "CT2-Y", "rule_id": "CT2", "evidence": {"path": "docker-compose.yml"}}]
            candidates = build_candidates(repo, {}, findings, repo / "cache", offline=True)
        self.assertFalse(any(c["action"] == "base_image" for c in candidates))


if __name__ == "__main__":
    unittest.main()
