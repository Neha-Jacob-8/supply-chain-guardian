import io
import json
import unittest
import urllib.error
from unittest import mock

from guardian.agents.gemini import GeminiLLM
from guardian.agents.llm import LLMUnavailable

OK = {"candidates": [{"content": {"parts": [{"functionCall": {"name": "get_finding", "args": {"finding_id": "X"}, "id": "c1"},
                                             "thoughtSignature": "sig"}]}, "finishReason": "STOP"}],
      "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 3}, "modelVersion": "m-test"}


def http_error(code, msg):
    return urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(json.dumps({"error": {"message": msg}}).encode()))


class GeminiFallback(unittest.TestCase):
    def make(self, outcomes):
        llm = GeminiLLM(keys=["KEY_ONE", "KEY_TWO"], models=["m1", "m2"], backoff=0)
        calls = []

        def fake(key, model, body):
            calls.append((key, model))
            out = outcomes.pop(0)
            if isinstance(out, Exception):
                raise out
            return out
        llm._post = fake
        return llm, calls

    def step(self, llm):
        return llm.step("sys", [{"role": "user", "content": "go"}], [{"name": "get_finding", "description": "d",
                        "input_schema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}}])

    def test_invalid_key_falls_back_to_next_key(self):
        llm, calls = self.make([http_error(400, "API key not valid. Please pass a valid API key."), OK])
        st = self.step(llm)
        self.assertEqual(calls, [("KEY_ONE", "m1"), ("KEY_TWO", "m1")])
        self.assertEqual(st.usage["key"], "#2")
        self.assertIn("KEY_ONE", llm.dead_keys)

    def test_overload_retries_then_next_model(self):
        llm, calls = self.make([http_error(503, "high demand"), http_error(503, "high demand"), OK])
        self.step(llm)
        self.assertEqual(calls, [("KEY_ONE", "m1"), ("KEY_ONE", "m1"), ("KEY_ONE", "m2")])

    def test_retired_model_is_skipped_for_all_keys(self):
        llm, calls = self.make([http_error(404, "no longer available"), OK, OK])
        self.step(llm); self.step(llm)
        self.assertEqual(calls, [("KEY_ONE", "m1"), ("KEY_ONE", "m2"), ("KEY_ONE", "m2")])

    def test_quota_moves_to_next_key_and_errors_hide_keys(self):
        llm, calls = self.make([http_error(429, "quota KEY_ONE"), http_error(429, "quota"),
                                http_error(429, "quota"), http_error(429, "quota")])
        with self.assertRaises(LLMUnavailable) as cm:
            self.step(llm)
        self.assertEqual(len(calls), 4)
        self.assertNotIn("KEY_ONE", str(cm.exception))

    def test_tool_call_parsing_and_history_round_trip(self):
        llm, _ = self.make([OK])
        st = self.step(llm)
        self.assertEqual([(u.id, u.name, u.input) for u in st.tool_uses], [("c1", "get_finding", {"finding_id": "X"})])
        hist = [{"role": "user", "content": "go"}, {"role": "assistant", "content": st.content},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": '{"a": 1}'}]}]
        contents = llm._contents(hist)
        self.assertEqual(contents[1]["parts"][0]["thoughtSignature"], "sig")      # signatures passed back unchanged
        self.assertEqual(contents[2]["parts"][0]["functionResponse"], {"name": "get_finding", "response": {"result": {"a": 1}}, "id": "c1"})

    def test_official_google_genai_sdk_transport(self):
        import guardian.agents.gemini as G
        llm = GeminiLLM(keys=["SDK_KEY_1"], models=["gemini-2.5-flash"], backoff=0)
        captured = {}

        class FakeModels:
            def generate_content(self, model, contents, config=None):
                captured["model"] = model
                captured["config"] = config
                return mock.MagicMock(model_dump=lambda **kw: OK)

        class FakeClient:
            def __init__(self, api_key):
                captured["api_key"] = api_key
                self.models = FakeModels()

        with mock.patch.object(G, "HAS_GOOGLE_GENAI_SDK", True), \
                mock.patch.object(G, "genai", mock.MagicMock(Client=FakeClient)):
            st = self.step(llm)
        self.assertEqual(captured["api_key"], "SDK_KEY_1")
        self.assertEqual(captured["model"], "gemini-2.5-flash")
        self.assertEqual(st.tool_uses[0].name, "get_finding")


if __name__ == "__main__":
    unittest.main()
