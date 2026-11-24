"""Groq backend using the OpenAI-compatible Chat Completions API.

The backend accepts multiple keys and rotates through them when a key is
invalid or rate-limited. A model can also be retired independently of the
keys. Keys are read from ``GROQ_API_KEYS`` (comma-separated) and the numbered
``GROQ_API_KEY_1`` ... ``GROQ_API_KEY_9`` variables. They are never included in
errors, audit events, or reports.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

from .llm import LLMUnavailable, Step, ToolUse


ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODELS = ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]
# Groq's Cloudflare front rejects urllib's default "Python-urllib" agent with 403 (error 1010).
USER_AGENT = "supply-chain-guardian/1.0"


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

    def __init__(self, keys=None, models=None, timeout=120, backoff=2.0, rate_wait=60.0, rate_rounds=4):
        self.keys = list(keys if keys is not None else groq_keys())
        if not self.keys:
            raise LLMUnavailable("no Groq API keys configured (GROQ_API_KEYS)")
        env_models = [m.strip() for m in os.environ.get("GUARDIAN_GROQ_MODELS", "").split(",") if m.strip()]
        self.models = list(models or env_models or DEFAULT_MODELS)
        self.dead_keys, self.dead_models = set(), set()
        self.timeout, self.backoff = timeout, backoff
        self.rate_wait, self.rate_rounds = rate_wait, rate_rounds
        try:
            self.max_input_tokens = int(os.environ.get("GUARDIAN_GROQ_MAX_INPUT_TOKENS", "6000"))
        except ValueError:
            self.max_input_tokens = 6000
        self.tokens_per_char = 1 / 3          # refined from Groq's reported usage after each call
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
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                     "User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.load(response)

    def _request(self, body):
        """Walk keys x models; if the only obstacle was rate limiting, wait once and walk again."""
        errors = []
        for round_ in range(self.rate_rounds + 1):
            waits = []
            result = self._walk(body, errors, waits)
            if result:
                return result
            if round_ == self.rate_rounds or not waits or self.rate_wait <= 0:
                break
            # free-tier limits are per minute: wait for the earliest key/model to free up
            time.sleep(min(min(waits) + 1.0, self.rate_wait))
        raise LLMUnavailable("all Groq keys/models failed: " + " | ".join(errors[-6:]))

    def _walk(self, body, errors, waits):
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
                            error = json.loads(exc.read().decode(errors="replace")).get("error", {}) or {}
                        except Exception:
                            error = {}
                        code = str(error.get("code", ""))
                        message = str(error.get("message", "")).replace(key, "<key>")[:180]
                        errors.append(f"key#{key_index + 1}/{model}: HTTP {exc.code} {message}")
                        if exc.code in (401, 403):
                            self.dead_keys.add(key)
                            break
                        if exc.code == 404 or code in ("model_not_found", "model_decommissioned"):
                            self.dead_models.add(model)
                            break
                        if exc.code == 429:
                            # rate / tokens-per-minute limit: limits are per model and per key, so move on
                            waits.append(self._retry_after(exc))
                            break
                        if exc.code == 413 and "per minute" in message:
                            # request alone exceeds this model's per-minute cap: waiting won't help, try others
                            break
                        if exc.code in (500, 502, 503, 504) and attempt == 1:
                            time.sleep(self.backoff)
                            continue
                        if code in ("tool_use_failed", "output_parse_failed") or "failed_generation" in error \
                                or "tool call" in message.lower():
                            # the model produced malformed output: retry once, then try another model
                            if attempt == 1:
                                continue
                            break
                        if exc.code in (400, 413, 422):
                            raise LLMUnavailable(f"Groq rejected request: {message}") from exc
                        break
                    except (urllib.error.URLError, TimeoutError, OSError) as exc:
                        errors.append(f"key#{key_index + 1}/{model}: {type(exc).__name__}")
                        if attempt == 1:
                            time.sleep(self.backoff)
                            continue
                        break
        return None

    @staticmethod
    def _retry_after(exc):
        try:
            return max(0.0, float(str((exc.headers or {}).get("retry-after", "")).rstrip("s")))
        except ValueError:
            return 5.0

    def _size(self, msgs, tools):
        return len(json.dumps(msgs)) + len(json.dumps(tools))

    def _fit(self, msgs, tools):
        """Shrink older history until the request fits the per-request token budget.

        Free-tier Groq models cap tokens per minute (6-8k), and a single request above the cap is refused
        outright. The system prompt, the task and the latest turn are always sent in full; older tool
        results keep only their evidence_id (still citable), and earlier tool-call drafts are dropped.
        """
        if self.max_input_tokens <= 0 or self._size(msgs, tools) * self.tokens_per_char <= self.max_input_tokens:
            return msgs, 0
        last_assistant = max((i for i, m in enumerate(msgs) if m.get("role") == "assistant"), default=len(msgs))
        msgs, trimmed = list(msgs), 0
        for i in range(2, len(msgs)):
            if self._size(msgs, tools) * self.tokens_per_char <= self.max_input_tokens:
                break
            m = msgs[i]
            if m.get("role") == "tool" and i < last_assistant and len(m.get("content", "")) > 160:
                eid = re.search(r'"evidence_id": "([^"]+)"', m["content"])
                note = "[older result trimmed to fit the token budget; call the tool again if you need it]"
                msgs[i] = {**m, "content": json.dumps({"evidence_id": eid.group(1), "result": note}) if eid
                           else m["content"][:120] + " ... " + note}
                trimmed += 1
            elif m.get("role") == "assistant" and m.get("tool_calls"):
                calls = [{**c, "function": {**c["function"], "arguments": '{"_omitted": "earlier draft trimmed"}'}}
                         if len(c.get("function", {}).get("arguments", "")) > 400 else c for c in m["tool_calls"]]
                if calls != m["tool_calls"]:
                    msgs[i] = {**m, "tool_calls": calls}
                    trimmed += 1
        return msgs, trimmed

    def step(self, system, messages, tools):
        tools = self._tools(tools)
        msgs, trimmed = self._fit(self._messages(system, messages), tools)
        body = {
            "model": self.models[0],
            "messages": msgs,
            "tools": tools,
            "tool_choice": "auto",
            "max_tokens": 16000,
        }
        data, key_index, model = self._request(body)
        self.calls += 1
        usage = data.get("usage") or {}
        if usage.get("prompt_tokens"):
            # calibrate the chars->tokens estimate from what Groq actually counted
            self.tokens_per_char = min(0.5, max(0.2, usage["prompt_tokens"] / max(1, self._size(msgs, tools))))
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
            **({"trimmed": trimmed} if trimmed else {}),
        }
        return Step(stop, {"_groq": raw}, uses, content, meta)
