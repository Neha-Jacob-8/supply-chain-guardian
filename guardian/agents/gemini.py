"""Gemini backend (REST, standard library) with ordered key and model fallback.

Keys:   GEMINI_API_KEYS="k1,k2,k3" and/or GEMINI_API_KEY, GEMINI_API_KEY_1..9 (environment or .env).
Models: GUARDIAN_GEMINI_MODELS="m1,m2" (default below).

For every request the backend walks keys in order and, per key, models in order:
  400 invalid key / 401 / 403  -> the key is dropped for the rest of the run, next key
  404 model not available       -> the model is dropped for every key, next model
  429 quota / rate limit        -> next model, then next key
  500 / 503 / 504 / timeout     -> one retry after a short backoff, then next model
If every combination fails it raises LLMUnavailable, and the agent moves to the next provider or its
labelled rule-based fallback. Keys are sent only in the x-goog-api-key header and never logged.
"""
import json
import os
import time
import urllib.error
import urllib.request

from .llm import LLMUnavailable, Step, ToolUse

ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_MODELS = ["gemini-3.5-flash", "gemini-flash-latest", "gemini-3.5-flash-lite", "gemini-flash-lite-latest"]


def gemini_keys(for_testing=False):
    raw = []
    if for_testing:
        raw += [os.environ.get("GEMINI_API_FOR_TESTING", ""), os.environ.get("GEMINI_TEST_API_KEY", "")]
    raw += [os.environ.get("GEMINI_API_KEYS", ""), os.environ.get("GEMINI_API_KEY", "")]
    raw += [os.environ.get(f"GEMINI_API_KEY_{i}", "") for i in range(1, 10)]
    if not for_testing:
        raw += [os.environ.get("GEMINI_API_FOR_TESTING", ""), os.environ.get("GEMINI_TEST_API_KEY", "")]
    keys = []
    for chunk in raw:
        for k in chunk.split(","):
            k = k.strip()
            if k and k not in keys:
                keys.append(k)
    return keys


class GeminiLLM:
    name = "gemini"

    def __init__(self, keys=None, models=None, timeout=120, backoff=2.0):
        self.keys = list(keys if keys is not None else gemini_keys())
        if not self.keys:
            raise LLMUnavailable("no Gemini API keys configured (GEMINI_API_KEYS)")
        env_models = [m.strip() for m in os.environ.get("GUARDIAN_GEMINI_MODELS", "").split(",") if m.strip()]
        self.models = list(models or env_models or DEFAULT_MODELS)
        self.dead_keys, self.dead_models = set(), set()
        self.timeout, self.backoff = timeout, backoff
        self.id_names = {}
        self.calls = 0
        self.last = {}

    # ---------- message conversion (our Anthropic-shaped history -> Gemini contents) ----------
    def _contents(self, messages):
        out = []
        for m in messages:
            c = m["content"]
            if m["role"] == "assistant":
                out.append({"role": "model", "parts": c["_gemini"] if isinstance(c, dict) and "_gemini" in c
                            else [{"text": str(c)}]})
            elif isinstance(c, str):
                out.append({"role": "user", "parts": [{"text": c}]})
            else:
                parts = []
                for b in c:
                    if b.get("type") == "tool_result":
                        try:
                            payload = json.loads(b["content"])
                        except (TypeError, ValueError):
                            payload = b["content"]
                        resp = {"error": payload} if b.get("is_error") else {"result": payload}
                        fr = {"name": self.id_names.get(b["tool_use_id"], "unknown"), "response": resp}
                        if not b["tool_use_id"].startswith("gem_"):
                            fr["id"] = b["tool_use_id"]
                        parts.append({"functionResponse": fr})
                    elif b.get("type") == "text":
                        parts.append({"text": b["text"]})
                out.append({"role": "user", "parts": parts})
        return out

    @staticmethod
    def _tools(tools):
        return [{"functionDeclarations": [{"name": t["name"], "description": t.get("description", ""),
                                           "parametersJsonSchema": t["input_schema"]} for t in tools]}]

    # ---------- transport with fallback ----------
    def _post(self, key, model, body):
        req = urllib.request.Request(ENDPOINT.format(model=model), data=json.dumps(body).encode(),
                                     headers={"x-goog-api-key": key, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.load(r)

    def _request(self, body):
        errors = []
        for ki, key in enumerate(self.keys):
            if key in self.dead_keys:
                continue
            for model in self.models:
                if model in self.dead_models or key in self.dead_keys:
                    continue
                for attempt in (1, 2):
                    try:
                        data = self._post(key, model, body)
                        self.last = {"key": f"#{ki + 1}", "model": model}
                        return data, ki, model
                    except urllib.error.HTTPError as e:
                        try:
                            msg = json.loads(e.read().decode()).get("error", {}).get("message", "")
                        except Exception:
                            msg = ""
                        msg = msg.replace(key, "<key>")[:160]
                        errors.append(f"key#{ki + 1}/{model}: HTTP {e.code} {msg}")
                        if e.code in (401, 403) or (e.code == 400 and ("API key" in msg or "API_KEY" in msg)):
                            self.dead_keys.add(key)
                            break
                        if e.code == 404:
                            self.dead_models.add(model)
                            break
                        if e.code == 429:
                            break
                        if e.code in (500, 502, 503, 504) and attempt == 1:
                            time.sleep(self.backoff)
                            continue
                        if e.code == 400:
                            raise LLMUnavailable(f"Gemini rejected the request: {msg}")
                        break
                    except (urllib.error.URLError, TimeoutError, OSError) as e:
                        errors.append(f"key#{ki + 1}/{model}: {type(e).__name__}")
                        if attempt == 1:
                            time.sleep(self.backoff)
                            continue
                        break
        raise LLMUnavailable("all Gemini keys/models failed: " + " | ".join(errors[-6:]))

    def step(self, system, messages, tools):
        body = {"systemInstruction": {"parts": [{"text": system}]}, "contents": self._contents(messages),
                "tools": self._tools(tools), "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}}}
        data, ki, model = self._request(body)
        self.calls += 1
        usage = data.get("usageMetadata", {})
        meta = {"provider": "gemini", "model": data.get("modelVersion", model), "key": f"#{ki + 1}",
                "input": usage.get("promptTokenCount"), "output": usage.get("candidatesTokenCount")}
        cands = data.get("candidates") or []
        if not cands:
            return Step("refusal", {"_gemini": [{"text": ""}]}, [], "", meta)
        cand = cands[0]
        parts = (cand.get("content") or {}).get("parts") or []
        uses = []
        for i, p in enumerate(parts):
            fc = p.get("functionCall")
            if fc:
                uid = fc.get("id") or f"gem_{self.calls}_{i}"
                self.id_names[uid] = fc["name"]
                uses.append(ToolUse(uid, fc["name"], dict(fc.get("args") or {})))
        text = "\n".join(p["text"] for p in parts if p.get("text") and not p.get("thought"))
        finish = cand.get("finishReason", "STOP")
        stop = "tool_use" if uses else {"STOP": "end_turn", "MAX_TOKENS": "max_tokens"}.get(finish, "refusal")
        return Step(stop, {"_gemini": parts or [{"text": ""}]}, uses, text, meta)
