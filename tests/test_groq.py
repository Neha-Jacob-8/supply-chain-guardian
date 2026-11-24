import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from guardian.agents.groq import GroqLLM, groq_keys
from guardian.agents.llm import LLMUnavailable


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


def _http_error(code, error, headers=None):
    return urllib.error.HTTPError(
        "https://example.invalid", code, "error", headers or {}, io.BytesIO(json.dumps({"error": error}).encode())
    )


_OK = {"choices": [{"message": {"role": "assistant", "content": "done"}, "finish_reason": "stop"}]}


class GroqFallback(unittest.TestCase):
    def test_tokens_per_minute_413_moves_to_next_model(self):
        backend = GroqLLM(keys=["k1"], models=["small", "big"], backoff=0, rate_wait=0)
        calls = []

        def fake_post(key, model, body):
            calls.append(model)
            if model == "small":
                raise _http_error(413, {"message": "Request too large on tokens per minute (TPM): Limit 6000"})
            return _OK

        backend._post = fake_post
        step = backend.step("system", [{"role": "user", "content": "hi"}], [])
        self.assertEqual(calls, ["small", "big"])
        self.assertEqual(step.usage["model"], "big")

    def test_malformed_tool_call_retries_then_tries_next_model(self):
        backend = GroqLLM(keys=["k1"], models=["flaky", "steady"], backoff=0, rate_wait=0)
        calls = []

        def fake_post(key, model, body):
            calls.append(model)
            if model == "flaky":
                raise _http_error(400, {"message": "Tool call validation failed", "code": "tool_use_failed"})
            return _OK

        backend._post = fake_post
        step = backend.step("system", [{"role": "user", "content": "hi"}], [])
        self.assertEqual(calls, ["flaky", "flaky", "steady"])
        self.assertEqual(step.text, "done")

    def test_other_bad_requests_still_fail_fast(self):
        backend = GroqLLM(keys=["k1", "k2"], models=["m"], backoff=0, rate_wait=0)
        calls = []

        def fake_post(key, model, body):
            calls.append(key)
            raise _http_error(400, {"message": "messages: field required", "code": "invalid_request"})

        backend._post = fake_post
        with self.assertRaises(LLMUnavailable):
            backend.step("system", [{"role": "user", "content": "hi"}], [])
        self.assertEqual(calls, ["k1"])

    def test_waits_once_when_every_key_is_rate_limited(self):
        backend = GroqLLM(keys=["k1", "k2"], models=["m"], backoff=0, rate_wait=5)
        calls, slept = [], []

        def fake_post(key, model, body):
            calls.append(key)
            if len(calls) <= 2:
                raise _http_error(429, {"message": "rate limit"}, {"retry-after": "3"})
            return _OK

        backend._post = fake_post
        with mock.patch("guardian.agents.groq.time.sleep", slept.append):
            step = backend.step("system", [{"role": "user", "content": "hi"}], [])
        self.assertEqual(calls, ["k1", "k2", "k1"])
        self.assertEqual(slept, [4.0])
        self.assertEqual(step.text, "done")

    def test_rate_wait_gives_up_after_configured_rounds(self):
        backend = GroqLLM(keys=["k1"], models=["m"], backoff=0, rate_wait=60, rate_rounds=2)
        slept = []

        def fake_post(key, model, body):
            raise _http_error(429, {"message": "rate limit"}, {"retry-after": "100"})

        backend._post = fake_post
        with mock.patch("guardian.agents.groq.time.sleep", slept.append):
            with self.assertRaises(LLMUnavailable):
                backend.step("system", [{"role": "user", "content": "hi"}], [])
        self.assertEqual(slept, [60, 60])

    def test_request_larger_than_model_cap_does_not_wait(self):
        backend = GroqLLM(keys=["k1"], models=["m"], backoff=0, rate_wait=60)
        slept = []

        def fake_post(key, model, body):
            raise _http_error(413, {"message": "Request too large on tokens per minute (TPM): Limit 8000, Requested 9512"})

        backend._post = fake_post
        with mock.patch("guardian.agents.groq.time.sleep", slept.append):
            with self.assertRaises(LLMUnavailable):
                backend.step("system", [{"role": "user", "content": "hi"}], [])
        self.assertEqual(slept, [])


class GroqTokenBudget(unittest.TestCase):
    def _history(self, rounds):
        messages = [{"role": "user", "content": "task"}]
        for i in range(rounds):
            messages.append({"role": "assistant", "content": {"_groq": {
                "role": "assistant", "content": "",
                "tool_calls": [{"id": f"c{i}", "type": "function",
                                "function": {"name": "get_finding", "arguments": json.dumps({"draft": "x" * 900})}}],
            }}})
            body = json.dumps({"evidence_id": f"EV-{i}", "result": "y" * 3000})
            messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": f"c{i}", "content": body}]})
        return messages

    def _send(self, backend, messages):
        sent = {}

        def fake_post(key, model, body):
            sent.update(body)
            return _OK

        backend._post = fake_post
        step = backend.step("system", messages, [])
        return sent["messages"], step

    def test_small_requests_are_sent_unchanged(self):
        backend = GroqLLM(keys=["k1"], models=["m"], backoff=0)
        history = self._history(1)
        sent, step = self._send(backend, history)
        self.assertEqual(sent, GroqLLM._messages("system", history))
        self.assertNotIn("trimmed", step.usage)

    def test_large_history_is_trimmed_oldest_first_keeping_evidence_ids(self):
        backend = GroqLLM(keys=["k1"], models=["m"], backoff=0)
        backend.max_input_tokens = 2500
        history = self._history(5)
        sent, step = self._send(backend, history)
        tool_msgs = [m for m in sent if m["role"] == "tool"]
        self.assertEqual(json.loads(tool_msgs[0]["content"])["evidence_id"], "EV-0")
        self.assertIn("trimmed", json.loads(tool_msgs[0]["content"])["result"])
        self.assertIn("y" * 3000, tool_msgs[-1]["content"])          # latest result always intact
        self.assertEqual(sent[1], {"role": "user", "content": "task"})  # task always intact
        self.assertLessEqual(len(json.dumps(sent)) / 3, 2500)
        self.assertGreater(step.usage["trimmed"], 0)
        # the stored agent history itself is never modified
        self.assertIn("x" * 900, history[1]["content"]["_groq"]["tool_calls"][0]["function"]["arguments"])


if __name__ == "__main__":
    unittest.main()
