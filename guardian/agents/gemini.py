"""Gemini backend powered by the Official Google GenAI SDK (`google-genai`: `from google import genai`)
with ordered multi-key and multi-model rotation and automatic REST fallback if the SDK package is not installed.

Keys:   GEMINI_API_KEYS="k1,k2,k3" and/or GEMINI_API_KEY, GEMINI_API_KEY_1..9, GEMINI_API_FOR_TESTING (environment or .env).
Models: GUARDIAN_GEMINI_MODELS="m1,m2" (default below).
"""
import json
import os
import time
import urllib.error
import urllib.request

from .llm import LLMUnavailable, Step, ToolUse

try:
    from google import genai
    from google.genai import types as genai_types
    HAS_GOOGLE_GENAI_SDK = True
except ImportError:
    genai = None
    genai_types = None
    HAS_GOOGLE_GENAI_SDK = False

ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_MODELS = ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash", "gemini-flash-latest"]


def gemini_keys(for_testing=False, for_sandbox=False):
    raw = []
    if for_sandbox:
        raw += [os.environ.get("GEMINI_FOR_SANDBOX", ""), os.environ.get("GEMINI_SANDBOX_API_KEY", "")]
    if for_testing:
        raw += [os.environ.get("GEMINI_API_FOR_TESTING", ""), os.environ.get("GEMINI_TEST_API_KEY", "")]
    raw += [os.environ.get("GEMINI_API_KEYS", ""), os.environ.get("GEMINI_API_KEY", "")]
    raw += [os.environ.get(f"GEMINI_API_KEY_{i}", "") for i in range(1, 10)]
    if not for_testing:
        raw += [os.environ.get("GEMINI_API_FOR_TESTING", ""), os.environ.get("GEMINI_TEST_API_KEY", "")]
    if not for_sandbox:
        raw += [os.environ.get("GEMINI_FOR_SANDBOX", ""), os.environ.get("GEMINI_SANDBOX_API_KEY", "")]
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

    # ---------- transport via Official Google GenAI SDK (`google.genai.Client`) ----------
    def _sdk_call(self, key, model, body):
        """Invoke Gemini using the official `google-genai` Python SDK (`genai.Client(api_key=key)`)."""
        client = genai.Client(api_key=key)
        sys_parts = ((body.get("systemInstruction") or {}).get("parts")) or []
        sys_text = "\n".join(p.get("text", "") for p in sys_parts if p.get("text"))
        config_kwargs = {}
        if sys_text:
            config_kwargs["system_instruction"] = sys_text
        if body.get("tools"):
            config_kwargs["tools"] = body["tools"]
        resp = client.models.generate_content(
            model=model,
            contents=body.get("contents", []),
            config=config_kwargs or None,
        )
        if hasattr(resp, "model_dump"):
            return resp.model_dump(by_alias=True, exclude_none=True)
        if hasattr(resp, "to_json_dict"):
            return resp.to_json_dict()
        # Normalize SDK response object into standard dict format
        parts = []
        cands = getattr(resp, "candidates", None) or []
        finish = "STOP"
        if cands:
            c0 = cands[0]
            finish = str(getattr(c0, "finish_reason", "STOP")).split(".")[-1]
            for p in getattr(getattr(c0, "content", None), "parts", None) or []:
                fc = getattr(p, "function_call", None)
                if fc:
                    parts.append({"functionCall": {"name": fc.name, "args": dict(fc.args or {}), "id": getattr(fc, "id", None)}})
                elif getattr(p, "text", None):
                    parts.append({"text": p.text})
        um = getattr(resp, "usage_metadata", None)
        return {
            "candidates": [{"content": {"parts": parts}, "finishReason": finish}] if cands else [],
            "usageMetadata": {
                "promptTokenCount": getattr(um, "prompt_token_count", None) if um else None,
                "candidatesTokenCount": getattr(um, "candidates_token_count", None) if um else None,
            },
            "modelVersion": getattr(resp, "model_version", model),
        }

    def _post(self, key, model, body):
        if HAS_GOOGLE_GENAI_SDK and genai is not None:
            return self._sdk_call(key, model, body)
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
                    except Exception as e:
                        if isinstance(e, LLMUnavailable):
                            raise
                        code = getattr(e, "code", None)
                        if isinstance(e, urllib.error.HTTPError):
                            try:
                                msg = json.loads(e.read().decode()).get("error", {}).get("message", "")
                            except Exception:
                                msg = str(e)
                        else:
                            msg = getattr(e, "message", None) or str(e)
                            if code is None:
                                for c in (400, 401, 403, 404, 429, 500, 502, 503, 504):
                                    if f" {c} " in f" {msg} " or msg.startswith(str(c)):
                                        code = c
                                        break
                        msg = msg.replace(key, "<key>")[:160]
                        if code is not None:
                            errors.append(f"key#{ki + 1}/{model}: HTTP {code} {msg}")
                            if code in (401, 403) or (code == 400 and ("API key" in msg or "API_KEY" in msg)):
                                self.dead_keys.add(key)
                                break
                            if code == 404:
                                self.dead_models.add(model)
                                break
                            if code == 429:
                                break
                            if code in (500, 502, 503, 504) and attempt == 1:
                                time.sleep(self.backoff)
                                continue
                            if code == 400:
                                raise LLMUnavailable(f"Gemini rejected the request: {msg}")
                            break
                        else:
                            errors.append(f"key#{ki + 1}/{model}: {type(e).__name__}")
                            if attempt == 1:
                                time.sleep(self.backoff)
                                continue
                            break
        raise LLMUnavailable("all Gemini keys/models failed: " + " | ".join(errors[-6:]))

    def step(self, system, messages, tools):
        body = {"systemInstruction": {"parts": [{"text": system}]}, "contents": self._contents(messages)}
        if tools:
            body["tools"] = self._tools(tools)
            body["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
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
