import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from guardian.agents.groq import GroqLLM, groq_keys


class GroqBackend(unittest.TestCase):
    def test_reads_four_numbered_keys_in_order_without_duplicates(self):
        env = {
            "GROQ_API_KEYS": "first,second",
            "GROQ_API_KEY_1": "second",
            "GROQ_API_KEY_2": "third",
            "GROQ_API_KEY_3": "fourth",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(groq_keys(), ["first", "second", "third", "fourth"])

    def test_rate_limit_rotates_to_next_key(self):
        backend = GroqLLM(keys=["k1", "k2"], models=["model"], backoff=0)
        calls = []

        def fake_post(key, model, body):
            calls.append(key)
            if key == "k1":
                raise urllib.error.HTTPError(
                    "https://example.invalid", 429, "rate limit", {}, io.BytesIO(b'{"error":{"message":"quota"}}')
                )
            return {
                "choices": [{
                    "message": {"role": "assistant", "content": "done", "tool_calls": []},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2},
            }

        backend._post = fake_post
        step = backend.step("system", [{"role": "user", "content": "hello"}], [])
        self.assertEqual(calls, ["k1", "k2"])
        self.assertEqual(step.text, "done")
        self.assertEqual(step.usage["key"], "#2")

    def test_tool_calls_and_results_round_trip_in_openai_shape(self):
        backend = GroqLLM(keys=["k1"], models=["model"], backoff=0)
        captured = {}

        def fake_post(key, model, body):
            captured.update(body)
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "checking",
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "get_finding", "arguments": '{"finding_id":"F1"}'},
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
            }

        backend._post = fake_post
        first = backend.step("system", [{"role": "user", "content": "inspect"}], [{
            "name": "get_finding", "description": "read a finding",
            "input_schema": {"type": "object", "properties": {"finding_id": {"type": "string"}}},
        }])
        self.assertEqual(first.tool_uses[0].name, "get_finding")
        self.assertEqual(first.tool_uses[0].input, {"finding_id": "F1"})
        def second_post(key, model, body):
            captured.update(body)
            return {"choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}

        backend._post = second_post
        backend.step("system", [
            {"role": "user", "content": "inspect"},
            {"role": "assistant", "content": first.content},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": json.dumps({"ok": True})}]},
        ], [])
        tool_messages = [m for m in captured["messages"] if m.get("role") == "tool"]
        self.assertEqual(tool_messages[0]["tool_call_id"], "call_1")


if __name__ == "__main__":
    unittest.main()
