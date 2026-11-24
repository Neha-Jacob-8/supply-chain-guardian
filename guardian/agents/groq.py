"""Groq backend using the OpenAI-compatible Chat Completions API.

The backend accepts multiple keys and rotates through them when a key is
invalid or rate-limited. A model can also be retired independently of the
keys. Keys are read from ``GROQ_API_KEYS`` (comma-separated) and the numbered
``GROQ_API_KEY_1`` ... ``GROQ_API_KEY_9`` variables. They are never included in
errors, audit events, or reports.
"""

import json
import os
import time
import urllib.error
import urllib.request

from .llm import LLMUnavailable, Step, ToolUse


ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODELS = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]


def groq_keys():
    """Return configured Groq keys in stable order, without duplicates."""
    raw = [os.environ.get("GROQ_API_KEYS", ""), os.environ.get("GROQ_API_KEY", "")]
    raw += [os.environ.get(f"GROQ_API_KEY_{i}", "") for i in range(1, 10)]
    keys = []
    for chunk in raw:
        for key in chunk.split(","):
            key = key.strip()
            if key and key not in keys:
                keys.append(key)
    return keys


class GroqLLM:
    name = "groq"

    def __init__(self, keys=None, models=None, timeout=120, backoff=2.0):
        self.keys = list(keys if keys is not None else groq_keys())
        if not self.keys:
            raise LLMUnavailable("no Groq API keys configured (GROQ_API_KEYS)")
        env_models = [m.strip() for m in os.environ.get("GUARDIAN_GROQ_MODELS", "").split(",") if m.strip()]
        self.models = list(models or env_models or DEFAULT_MODELS)
        self.dead_keys, self.dead_models = set(), set()
        self.timeout, self.backoff = timeout, backoff
        self.calls = 0
        self.last = {}

    @staticmethod
    def _messages(system, messages):
        """Convert the agent loop's Anthropic-shaped history to OpenAI format."""
        out = [{"role": "system", "content": system}]
        for message in messages:
            role, content = message.get("role", "user"), message.get("content", "")
            if role == "assistant" and isinstance(content, dict) and "_groq" in content:
                out.append(content["_groq"])
                continue
            if role == "assistant":
                if isinstance(content, str):
                    out.append({"role": "assistant", "content": content})
                else:
                    out.append({"role": "assistant", "content": ""})
                continue
            if isinstance(content, str):
                out.append({"role": "user", "content": content})
                continue

            # Agent tool results are represented as Anthropic-style blocks.
            text_parts = []
            for block in content or []:
                if block.get("type") == "tool_result":
                    value = block.get("content", "")
                    if not isinstance(value, str):
                        value = json.dumps(value, default=str)
                    if block.get("is_error"):
                        value = "Tool error: " + value
                    out.append({
                        "role": "tool",
                        "tool_call_id": block.get("tool_use_id", "unknown"),
                        "content": value,
                    })
                elif block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
            if text_parts:
                out.append({"role": "user", "content": "\n".join(text_parts)})
        return out

    @staticmethod
    def _tools(tools):
        return [{
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool["input_schema"],
            },
        } for tool in tools]

    def _post(self, key, model, body):
        payload = dict(body)
        payload["model"] = model
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.load(response)

    def _request(self, body):
        errors = []
        for key_index, key in enumerate(self.keys):
            if key in self.dead_keys:
                continue
            for model in self.models:
                if model in self.dead_models or key in self.dead_keys:
                    continue
                for attempt in (1, 2):
                    try:
                        data = self._post(key, model, body)
                        self.last = {"key": f"#{key_index + 1}", "model": model}
                        return data, key_index, model
                    except urllib.error.HTTPError as exc:
                        try:
                            message = json.loads(exc.read().decode(errors="replace")).get("error", {}).get("message", "")
                        except Exception:
                            message = ""
                        message = str(message).replace(key, "<key>")[:180]
                        errors.append(f"key#{key_index + 1}/{model}: HTTP {exc.code} {message}")
                        if exc.code in (401, 403):
                            self.dead_keys.add(key)
                            break
                        if exc.code == 404:
                            self.dead_models.add(model)
                            break
                        if exc.code == 429:
                            break
                        if exc.code in (500, 502, 503, 504) and attempt == 1:
                            time.sleep(self.backoff)
                            continue
                        if exc.code in (400, 413, 422):
                            raise LLMUnavailable(f"Groq rejected request: {message}") from exc
                        break
                    except (urllib.error.URLError, TimeoutError, OSError) as exc:
                        errors.append(f"key#{key_index + 1}/{model}: {type(exc).__name__}")
                        if attempt == 1:
                            time.sleep(self.backoff)
                            continue
                        break
        raise LLMUnavailable("all Groq keys/models failed: " + " | ".join(errors[-6:]))

    def step(self, system, messages, tools):
        body = {
            "model": self.models[0],
            "messages": self._messages(system, messages),
            "tools": self._tools(tools),
            "tool_choice": "auto",
            "max_tokens": 16000,
        }
        data, key_index, model = self._request(body)
        self.calls += 1
        usage = data.get("usage") or {}
        choices = data.get("choices") or []
        if not choices:
            return Step("refusal", {"_groq": {"role": "assistant", "content": ""}}, [], "", {
                "provider": "groq", "model": model, "key": f"#{key_index + 1}",
            })

        choice = choices[0]
        message = choice.get("message") or {"role": "assistant", "content": ""}
        content = message.get("content") or ""
        raw = {"role": "assistant", "content": content}
        uses = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            arguments = function.get("arguments", {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except ValueError:
                    arguments = {}
            tool_id = call.get("id") or f"groq_{self.calls}_{len(uses)}"
            raw.setdefault("tool_calls", []).append({
                "id": tool_id,
                "type": "function",
                "function": {"name": function.get("name", ""), "arguments": json.dumps(arguments)},
            })
            uses.append(ToolUse(tool_id, function.get("name", ""), dict(arguments)))
        stop = "tool_use" if uses else {"stop": "end_turn", "length": "max_tokens"}.get(
            choice.get("finish_reason"), "end_turn"
        )
        meta = {
            "provider": "groq", "model": model, "key": f"#{key_index + 1}",
            "input": usage.get("prompt_tokens"), "output": usage.get("completion_tokens"),
        }
        return Step(stop, {"_groq": raw}, uses, content, meta)
