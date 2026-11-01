"""OpenRouter client (OpenAI-compatible) with per-call cost accounting."""
from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass
from functools import lru_cache

from openai import OpenAI

from .config import Settings

BASE_URL = "https://openrouter.ai/api/v1"


@lru_cache(maxsize=1)
def _prices() -> dict[str, dict[str, float]]:
    """$/token from OpenRouter's public model list; used when a response carries no cost."""
    with urllib.request.urlopen(f"{BASE_URL}/models", timeout=20) as r:
        data = json.load(r)["data"]
    return {m["id"]: {k: float(v or 0) for k, v in m.get("pricing", {}).items() if k in ("prompt", "completion", "input_cache_read")}
            for m in data}


@dataclass
class Usage:
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0
    cost_usd: float = 0.0
    latency_s: float = 0.0

    def add(self, other: "Usage") -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.cached_tokens += other.cached_tokens
        self.cost_usd += other.cost_usd
        self.latency_s += other.latency_s


class LLM:
    def __init__(self, s: Settings):
        if not s.openrouter_key:
            raise SystemExit("OPENROUTER_API_KEY not set (environment or ~/.openrouter_env)")
        self.client = OpenAI(base_url=BASE_URL, api_key=s.openrouter_key,
                             default_headers={"X-Title": "tiny-agenticsoc"})

    def chat(self, model: str, messages: list[dict], tools: list[dict] | None = None,
             tool_choice=None, max_tokens: int = 1200, temperature: float = 0.0,
             reasoning_effort: str | None = None):
        """reasoning_effort: low|medium|high for models that think before answering. Thinking
        tokens count against max_tokens, so a small budget with high effort truncates the answer."""
        t0 = time.monotonic()
        extra = {"usage": {"include": True}}
        if reasoning_effort:
            extra["reasoning"] = {"effort": reasoning_effort}
        kw = dict(model=model, messages=messages, max_tokens=max_tokens, temperature=temperature,
                  extra_body=extra)
        if tools:
            kw.update(tools=tools, tool_choice=tool_choice or "auto")
        resp = self.client.chat.completions.create(**kw)
        u = resp.usage
        usage = Usage(model=model, latency_s=time.monotonic() - t0)
        if u:
            usage.prompt_tokens = u.prompt_tokens or 0
            usage.completion_tokens = u.completion_tokens or 0
            details = getattr(u, "prompt_tokens_details", None)
            usage.cached_tokens = (getattr(details, "cached_tokens", 0) or 0) if details else 0
            cost = getattr(u, "cost", None) or (u.model_extra or {}).get("cost")
            if cost is None:
                p = _prices().get(model, {})
                cost = ((usage.prompt_tokens - usage.cached_tokens) * p.get("prompt", 0)
                        + usage.cached_tokens * p.get("input_cache_read", p.get("prompt", 0))
                        + usage.completion_tokens * p.get("completion", 0))
            usage.cost_usd = float(cost)
        return resp, usage
