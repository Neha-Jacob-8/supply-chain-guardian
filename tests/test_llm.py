import os
import unittest
from types import SimpleNamespace as NS
from unittest import mock

from guardian.agents import llm as L


class FakeMessages:
    def __init__(self):
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return NS(stop_reason="tool_use", usage=NS(input_tokens=11, output_tokens=7),
                  content=[NS(type="thinking", thinking=""), NS(type="text", text="checking"),
                           NS(type="tool_use", id="toolu_1", name="get_finding", input={"finding_id": "X"})])


class ClaudeClient(unittest.TestCase):
    def test_request_shape_and_parsing(self):
        c = L.ClaudeLLM.__new__(L.ClaudeLLM)
        import anthropic
        c.anthropic, c.model, c.effort = anthropic, "claude-opus-5-5", "medium"
        fake = FakeMessages()
        c.client = NS(beta=NS(messages=fake))
        step = c.step("sys", [{"role": "user", "content": "hi"}], [{"name": "t"}])
        k = fake.kwargs
        self.assertEqual(k["model"], "claude-opus-5-5")
        self.assertEqual(k["thinking"], {"type": "adaptive"})
        self.assertEqual(k["output_config"], {"effort": "medium"})
        self.assertEqual(k["fallbacks"], "default")
        self.assertIn("server-side-fallback-2026-07-01", k["betas"])
        self.assertNotIn("tool_choice", k)                      # forced tool choice is rejected on this model
        self.assertEqual(step.stop_reason, "tool_use")
        self.assertEqual([(u.name, u.input) for u in step.tool_uses], [("get_finding", {"finding_id": "X"})])
        self.assertEqual(step.text, "checking")
        self.assertEqual(len(step.content), 3)                  # thinking blocks are passed back unchanged

    def test_auto_mode_without_credentials_uses_fallback(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("os.path.isdir", return_value=False):
            self.assertIsNone(L.get_llm("auto"))
        self.assertIsNone(L.get_llm("none"))


if __name__ == "__main__":
    unittest.main()
