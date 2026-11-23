import tempfile
import unittest
from pathlib import Path

from guardian.agents.base import Agent, check_citations
from guardian.agents.llm import ScriptedLLM
from guardian.agents.state import RunState
from guardian.agents import tools as T
from guardian.models import Component


def make_state():
    d = Path(tempfile.mkdtemp())
    (d / "repo").mkdir()
    (d / "repo" / "app.js").write_text('const x = require("lodash");\nconst zapApiKey = "abcd1234secret";\n')
    s = RunState(d / "repo", d / "out")
    c = Component(component_id="pkg:npm/lodash@4.17.11", name="lodash", version="4.17.11",
                  relationship="direct", path=["pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.11"])
    s.comps = {c.component_id: c}
    s.set_findings([{"finding_id": "GHSA-35jh-r3h4-6jhm:pkg:npm/lodash@4.17.11", "rule_id": "OSV",
                     "category": "vulnerability", "title": "Command injection", "component_id": c.component_id,
                     "advisory_id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "cves": ["CVE-2021-23337"],
                     "severity": "HIGH", "evidence": {"source": "OSV"}}])
    s.risk = {"GHSA-35jh-r3h4-6jhm:pkg:npm/lodash@4.17.11": {"score": 70, "severity": "HIGH", "factors": {}}}
    return s


class EchoAgent(Agent):
    name = "echo"
    tool_names = ["get_component", "check_import_usage"]
    result_schema = {"type": "object", "properties": {"claim": {"type": "string"},
                                                       "evidence_ids": {"type": "array", "items": {"type": "string"}}},
                     "required": ["claim", "evidence_ids"], "additionalProperties": False}

    def task(self, state):
        return "Is lodash used?"

    def fallback(self, state):
        return {"claim": "fallback", "evidence_ids": []}


class Guardrails(unittest.TestCase):
    def test_rejects_invented_ids_and_advisories(self):
        s = make_state()
        errs = check_citations(s, {"claim": "CVE-2099-0001 affects lodash", "evidence_ids": ["EV-made-up"]})
        self.assertEqual(len(errs), 2)

    def test_accepts_real_citations(self):
        s = make_state()
        fid = s.findings[0]["finding_id"]
        self.assertEqual(check_citations(s, {"claim": "CVE-2021-23337 affects lodash", "evidence_ids": [fid]}), [])

    def test_agent_self_corrects_after_rejected_submit(self):
        s = make_state()
        fid = s.findings[0]["finding_id"]
        llm = ScriptedLLM([
            {"tool_uses": [("check_import_usage", {"package": "lodash"})]},
            {"tool_uses": [("submit_result", {"claim": "CVE-2099-1 is exploitable", "evidence_ids": ["nope"]})]},
            {"tool_uses": [("submit_result", {"claim": "lodash is imported by app.js", "evidence_ids": [fid]})]},
        ])
        res = EchoAgent().run(s, llm)
        self.assertEqual(res["mode"], "llm:scripted")
        self.assertEqual(res["evidence_ids"], [fid])
        kinds = [e["kind"] for e in s.events]
        self.assertIn("tool_call", kinds)
        self.assertEqual([e["detail"]["accepted"] for e in s.events if e["kind"] == "submit"], [False, True])

    def test_schema_violations_are_rejected_and_corrected(self):
        s = make_state()
        fid = s.findings[0]["finding_id"]
        llm = ScriptedLLM([
            {"tool_uses": [("submit_result", {"evidence_ids": [fid]})]},                      # missing "claim"
            {"tool_uses": [("submit_result", {"claim": "lodash is used", "evidence_ids": [fid]})]},
        ])
        res = EchoAgent().run(s, llm)
        self.assertEqual(res["claim"], "lodash is used")
        rejected = [e for e in s.events if e["kind"] == "submit" and not e["detail"]["accepted"]]
        self.assertIn("result.claim is missing", rejected[0]["detail"]["errors"][0])

    def test_tool_calls_become_citable_evidence(self):
        s = make_state()
        out, eid = T.call(s, "check_import_usage", {"package": "lodash"})
        self.assertEqual(out["import_sites"], 1)
        self.assertIn(eid, s.known_ids())

    def test_secrets_redacted_from_file_reads(self):
        s = make_state()
        out, _ = T.call(s, "read_file", {"path": "app.js", "start_line": 1, "end_line": 5})
        self.assertNotIn("abcd1234secret", out["text"])
        self.assertIn("[REDACTED]", out["text"])

    def test_read_file_cannot_escape_repo(self):
        s = make_state()
        out, _ = T.call(s, "read_file", {"path": "../../etc/passwd", "start_line": 1, "end_line": 2})
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
