"""Model access for the agents, with per-call cost accounting.

Model strings carry their provider:
  anthropic:claude-haiku-5-5            -> Anthropic API directly (spends Anthropic credits)
  openrouter:anthropic/claude-haiku-5.5 -> OpenRouter (OpenAI-compatible)
Unprefixed: "claude-*" means anthropic, anything with a "/" means openrouter.

Both paths ask for one structured answer through a single tool (`LLM.call_tool`):

* Anthropic (`_anthropic_tool`): tool_choice auto + strict schema + a cached system block, one
  retry with more room on max_tokens and re-prompts if the model answers in prose. Cost is
  computed from ANTHROPIC_PRICES.
* OpenRouter (`_openrouter_tool`, OpenAI SDK): a forced tool_choice where the model accepts it;
  tool_choice "auto" plus an explicit instruction and one re-prompt for models that reject it
  (OPENROUTER_NO_FORCED_TOOL, or a 400 about tool_choice at run time). For `anthropic/*` ids the
  system message carries a cache_control breakpoint (OpenRouter's way to get Anthropic prompt
  caching); other providers cache automatically and get a plain string. Cost is the `cost`
  OpenRouter reports, falling back to its public price list only when that is missing.
"""
from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache

from .config import Settings

OPENROUTER_URL = "https://openrouter.ai/api/v1"

# OpenRouter model-id prefixes whose upstream rejects a forced tool_choice
# ({"type": "function", "function": {"name": ...}}). These get tool_choice="auto" instead.
OPENROUTER_NO_FORCED_TOOL = (
    "anthropic/claude-sonnet-5.5",
    "anthropic/claude-opus-5.5",
)
# Hard cap on chat.completions.create calls per call_tool (rejected requests included).
OPENROUTER_MAX_CALLS = 4

# Anthropic list prices, USD per million tokens (cache write = 5-minute TTL, 1.25x input).
# Claude Haiku 5.5 doubles input/output price above 100K prompt tokens; triage prompts are ~5K.
ANTHROPIC_PRICES = {
    "claude-haiku-5-5": {"input": 0.10, "output": 0.50, "cache_write": 0.125, "cache_read": 0.01},
    "claude-sonnet-5-5": {"input": 2.00, "output": 10.00, "cache_write": 2.50, "cache_read": 0.20},
    "claude-sonnet-5": {"input": 2.00, "output": 10.00, "cache_write": 2.50, "cache_read": 0.20},   # fallback target
    "claude-opus-5-5": {"input": 4.00, "output": 20.00, "cache_write": 5.00, "cache_read": 0.20},
}


@dataclass
class Usage:
    model: str
    input_tokens: int = 0          # uncached input
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    output_tokens: int = 0         # includes thinking
    cost_usd: float = 0.0
    latency_s: float = 0.0

    @property
    def prompt_tokens(self) -> int:
        return self.input_tokens + self.cache_write_tokens + self.cache_read_tokens

    def add(self, other: "Usage") -> None:
        for f in ("input_tokens", "cache_write_tokens", "cache_read_tokens", "output_tokens", "cost_usd", "latency_s"):
            setattr(self, f, getattr(self, f) + getattr(other, f))


@dataclass
class ToolCall:
    """Result of asking the model to answer through one tool."""
    args: dict | None
    usage: Usage
    stop_reason: str
    text: str = ""
    provider: str = ""
    notes: list[str] = field(default_factory=list)


def split_model(model: str) -> tuple[str, str]:
    if ":" in model and model.split(":", 1)[0] in ("anthropic", "openrouter"):
        p, m = model.split(":", 1)
        return p, m
    return ("anthropic", model) if model.startswith("claude-") else ("openrouter", model)


def openrouter_forces_tool(model: str) -> bool:
    """True if a forced tool_choice may be sent to this OpenRouter model id (no "openrouter:" prefix)."""
    return not model.startswith(OPENROUTER_NO_FORCED_TOOL)


def _openrouter_system(model: str, system: str):
    """System message content: cache_control content parts for anthropic/*, else a plain string."""
    if model.startswith("anthropic/"):
        return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
    return system


class LLM:
    def __init__(self, s: Settings):
        self.s = s
        self._anthropic = None
        self._openrouter = None

    # ---------- clients ----------
    def anthropic(self):
        if self._anthropic is None:
            import anthropic
            if not self.s.anthropic_key:
                raise SystemExit("no Anthropic key: set SOC_ANTHROPIC_API_KEY in ~/.anthropic_env")
            self._anthropic = anthropic.Anthropic(api_key=self.s.anthropic_key, max_retries=3)
        return self._anthropic

    def openrouter(self):
        if self._openrouter is None:
            from openai import OpenAI
            if not self.s.openrouter_key:
                raise SystemExit("OPENROUTER_API_KEY not set (environment or ~/.openrouter_env)")
            self._openrouter = OpenAI(base_url=OPENROUTER_URL, api_key=self.s.openrouter_key,
                                      default_headers={"X-Title": "tiny-agenticsoc"})
        return self._openrouter

    # ---------- one structured answer through a tool ----------
    def call_tool(self, model: str, system: str, user: str, tool: dict, effort: str = "low",
                  max_tokens: int = 4000) -> ToolCall:
        """tool = {"name", "description", "input_schema"}; returns the tool's arguments."""
        provider, m = split_model(model)
        if provider == "anthropic":
            return self._anthropic_tool(m, system, user, tool, effort, max_tokens)
        return self._openrouter_tool(m, system, user, tool, effort, max_tokens)

    def _anthropic_tool(self, model, system, user, tool, effort, max_tokens) -> ToolCall:
        import anthropic
        client = self.anthropic()
        # Forced tool_choice is rejected by Claude Sonnet 5.5 / Opus 5.5, so: auto + strict schema
        # + an explicit instruction in the prompt, and one re-prompt if no tool call comes back.
        tools = [{**tool, "strict": True}]
        system_blocks = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        messages: list = [{"role": "user", "content": user}]
        total = Usage(model=f"anthropic:{model}")
        notes: list[str] = []
        for attempt in range(3):
            t0 = time.monotonic()
            try:
                resp = client.messages.create(
                    model=model, max_tokens=max_tokens, system=system_blocks, tools=tools,
                    tool_choice={"type": "auto"}, output_config={"effort": effort}, messages=messages)
            except anthropic.BadRequestError as e:
                raise RuntimeError(f"Anthropic rejected the request: {e.message}") from None
            total.add(self._anthropic_usage(model, resp.usage, time.monotonic() - t0))
            if resp.stop_reason == "refusal":
                cat = getattr(getattr(resp, "stop_details", None), "category", None)
                return ToolCall(None, total, "refusal", provider="anthropic", notes=notes + [f"refusal category={cat}"])
            for block in resp.content:
                if block.type == "tool_use" and block.name == tool["name"]:
                    return ToolCall(dict(block.input), total, resp.stop_reason, provider="anthropic", notes=notes)
            if resp.stop_reason == "max_tokens":
                notes.append(f"max_tokens={max_tokens} hit; retrying with more room")
                max_tokens = min(max_tokens * 3, 16000)
                continue
            # answered in prose: keep the turn (append-only history) and ask for the tool call
            notes.append("no tool call; re-prompted")
            messages = messages + [{"role": "assistant", "content": resp.content},
                                   {"role": "user", "content": f"Submit your answer by calling {tool['name']} now."}]
        text = "".join(b.text for b in resp.content if b.type == "text")
        return ToolCall(None, total, resp.stop_reason, text=text, provider="anthropic", notes=notes)

    @staticmethod
    def _anthropic_usage(model: str, u, latency: float) -> Usage:
        p = ANTHROPIC_PRICES.get(model, {})
        usage = Usage(model=f"anthropic:{model}", input_tokens=u.input_tokens or 0,
                      cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
                      cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
                      output_tokens=u.output_tokens or 0, latency_s=latency)
        usage.cost_usd = (usage.input_tokens * p.get("input", 0) + usage.cache_write_tokens * p.get("cache_write", 0)
                          + usage.cache_read_tokens * p.get("cache_read", 0) + usage.output_tokens * p.get("output", 0)) / 1e6
        return usage

    def _openrouter_tool(self, model, system, user, tool, effort, max_tokens) -> ToolCall:
        import openai
        client = self.openrouter()
        name = tool["name"]
        # No "strict" here: not every OpenRouter upstream accepts it.
        fn = {"type": "function", "function": {"name": name, "description": tool["description"],
                                               "parameters": tool["input_schema"]}}
        force = {"type": "function", "function": {"name": name}}
        system_msg = {"role": "system", "content": _openrouter_system(model, system)}
        instructed = f"{user}\n\nAnswer by calling the {name} tool."

        def start(forced: bool) -> list:
            # In auto mode the prompt itself must ask for the tool call.
            return [system_msg, {"role": "user", "content": user if forced else instructed}]

        forced = openrouter_forces_tool(model)
        messages = start(forced)
        total = Usage(model=f"openrouter:{model}")
        notes: list[str] = []
        budget = max_tokens
        length_retried = reprompted = False
        choice = None
        for _ in range(OPENROUTER_MAX_CALLS):
            t0 = time.monotonic()
            try:
                resp = client.chat.completions.create(
                    model=model, messages=messages, max_tokens=budget, tools=[fn],
                    tool_choice=force if forced else "auto",
                    extra_body={"usage": {"include": True}, "reasoning": {"effort": effort}})
            except openai.BadRequestError as e:
                msg = getattr(e, "message", None) or str(e)
                if forced and "tool_choice" in f"{msg} {e.body}":
                    # Upstream rejects forcing even though it is not listed: retry once in auto mode.
                    notes.append("forced tool_choice rejected; retrying with tool_choice=auto")
                    forced = False
                    messages = start(forced)
                    continue
                raise RuntimeError(f"OpenRouter rejected the request: {msg}") from None
            total.add(self._openrouter_usage(model, resp.usage, time.monotonic() - t0))
            choice = resp.choices[0]
            if choice.finish_reason == "length":
                # Arguments may be truncated JSON: one retry with twice the room.
                notes.append(f"length at max_tokens={budget}")
                if length_retried:
                    break
                length_retried = True
                budget *= 2
                continue
            calls = choice.message.tool_calls or []
            if calls:
                return ToolCall(json.loads(calls[0].function.arguments), total, choice.finish_reason,
                                provider="openrouter", notes=notes)
            if forced or reprompted:
                break
            # answered in prose: keep the turn and ask for the tool call, once
            reprompted = True
            notes.append("no tool call; re-prompted")
            messages = messages + [
                # Anthropic upstreams reject an empty assistant turn, hence the placeholder.
                {"role": "assistant", "content": choice.message.content or "(no answer)"},
                {"role": "user", "content": f"Submit your answer by calling {name} now."}]
        if choice is None:   # unreachable in practice: only rejected calls, which raise or continue
            return ToolCall(None, total, "error", provider="openrouter", notes=notes)
        return ToolCall(None, total, choice.finish_reason or "", text=choice.message.content or "",
                        provider="openrouter", notes=notes)

    @staticmethod
    def _openrouter_usage(model: str, u, latency: float) -> Usage:
        usage = Usage(model=f"openrouter:{model}", latency_s=latency)
        if not u:
            return usage
        details = getattr(u, "prompt_tokens_details", None)
        cached = (getattr(details, "cached_tokens", 0) or 0) if details else 0
        written = (getattr(details, "cache_write_tokens", 0) or 0) if details else 0
        usage.cache_read_tokens = cached
        usage.cache_write_tokens = written
        # prompt_tokens is the total; split it so Usage.prompt_tokens still equals it.
        usage.input_tokens = (u.prompt_tokens or 0) - cached - written
        usage.output_tokens = u.completion_tokens or 0
        cost = getattr(u, "cost", None)
        if cost is None:
            cost = (u.model_extra or {}).get("cost")
        if cost is None:
            # Only reached when OpenRouter did not report cost: fetch the public price list.
            p = _openrouter_prices().get(model, {})
            prompt = p.get("prompt", 0)
            cost = (usage.input_tokens * prompt + cached * p.get("input_cache_read", prompt)
                    + written * p.get("input_cache_write", prompt) + usage.output_tokens * p.get("completion", 0))
        usage.cost_usd = float(cost)
        return usage


@lru_cache(maxsize=1)
def _openrouter_prices() -> dict[str, dict[str, float]]:
    with urllib.request.urlopen(f"{OPENROUTER_URL}/models", timeout=20) as r:
        data = json.load(r)["data"]
    return {m["id"]: {k: float(v or 0) for k, v in m.get("pricing", {}).items()
                      if k in ("prompt", "completion", "input_cache_read", "input_cache_write")} for m in data}
