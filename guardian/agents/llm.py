"""LLM backends for the agents.

ClaudeLLM  - Claude via the Anthropic SDK (Messages API + client tools; we own the loop so every
             tool call is logged and every submitted result is citation-checked).
ScriptedLLM - deterministic stand-in used by unit tests.
Credentials come from the environment (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / `ant auth login`).
"""
import os
from dataclasses import dataclass, field

MODEL = os.environ.get("GUARDIAN_MODEL", "claude-opus-5-5")


class LLMUnavailable(Exception):
    pass


@dataclass
class ToolUse:
    id: str
    name: str
    input: dict


@dataclass
class Step:
    stop_reason: str
    content: list                      # appended back verbatim as the assistant turn
    tool_uses: list = field(default_factory=list)
    text: str = ""
    usage: dict = field(default_factory=dict)


def credentials_present():
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return True
    return (os.path.isdir(os.path.expanduser("~/.config/anthropic")))


class ClaudeLLM:
    name = "claude"

    def __init__(self, model=MODEL, effort="medium"):
        try:
            import anthropic
        except ImportError as e:
            raise LLMUnavailable("anthropic SDK not installed (pip install anthropic)") from e
        self.anthropic = anthropic
        self.client = anthropic.Anthropic()
        self.model, self.effort = model, effort

    def step(self, system, messages, tools):
        a = self.anthropic
        try:
            r = self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=messages,
                tools=tools,
                thinking={"type": "adaptive"},
                output_config={"effort": self.effort},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",   # route refusals to a fallback model server-side
            )
        except a.AuthenticationError as e:
            raise LLMUnavailable(f"authentication failed: {e}") from e
        except a.PermissionDeniedError as e:
            raise LLMUnavailable(f"permission denied: {e}") from e
        except a.NotFoundError as e:
            raise LLMUnavailable(f"model or endpoint not found: {e}") from e
        except a.RateLimitError as e:
            raise LLMUnavailable(f"rate limited after retries: {e}") from e
        except a.APIStatusError as e:
            raise LLMUnavailable(f"API error {e.status_code}: {e}") from e
        except a.APIConnectionError as e:
            raise LLMUnavailable(f"cannot reach API: {e}") from e
        tool_uses = [ToolUse(b.id, b.name, dict(b.input)) for b in r.content if b.type == "tool_use"]
        text = "\n".join(b.text for b in r.content if b.type == "text")
        usage = {"input": r.usage.input_tokens, "output": r.usage.output_tokens}
        return Step(r.stop_reason, r.content, tool_uses, text, usage)


class ScriptedLLM:
    """Replays a fixed list of steps: each item is {"tool_uses": [(name, input), ...], "text": "..."}."""
    name = "scripted"

    def __init__(self, script):
        self.script, self.i = list(script), 0

    def step(self, system, messages, tools):
        if self.i >= len(self.script):
            return Step("end_turn", [{"type": "text", "text": "done"}], [], "done")
        s = self.script[self.i]; self.i += 1
        uses = [ToolUse(f"tu_{self.i}_{k}", n, inp) for k, (n, inp) in enumerate(s.get("tool_uses", []))]
        content = ([{"type": "text", "text": s["text"]}] if s.get("text") else []) + \
                  [{"type": "tool_use", "id": u.id, "name": u.name, "input": u.input} for u in uses]
        return Step("tool_use" if uses else "end_turn", content, uses, s.get("text", ""))


class ChainLLM:
    """Ordered providers: an agent run that fails on one provider restarts on the next."""

    def __init__(self, providers):
        self.providers = providers
        self.name = "+".join(p.name for p in providers)


def get_llm(mode="auto"):
    """mode: auto (every provider with credentials, Claude first), claude, gemini, none."""
    if mode == "none":
        return None
    providers, errors = [], []
    if mode in ("auto", "claude") and (mode == "claude" or credentials_present()):
        try:
            providers.append(ClaudeLLM())
        except Exception as e:
            errors.append(f"claude: {e}")
    if mode in ("auto", "gemini"):
        from .gemini import GeminiLLM, gemini_keys
        if mode == "gemini" or gemini_keys():
            try:
                providers.append(GeminiLLM())
            except Exception as e:
                errors.append(f"gemini: {e}")
    if not providers:
        if mode != "auto":
            raise LLMUnavailable("; ".join(errors) or f"{mode} is not configured")
        return None
    return providers[0] if len(providers) == 1 else ChainLLM(providers)
