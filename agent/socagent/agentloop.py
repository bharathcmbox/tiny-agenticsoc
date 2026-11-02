"""The one tool-use loop every agent shares (investigation, console search).

Anthropic API, manual loop:
- adaptive thinking, depth via output_config.effort; tool_choice auto (forced choice is a 400 on 5.5 models)
- append-only history: response content echoed back unchanged (thinking blocks stay valid)
- server-side refusal fallback ("default"); fallback turns echoed as documented
- automatic prompt caching across turns
- cost per attempt from usage.iterations
- the answer arrives through a terminal tool; the harness enforces the step cap
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

import anthropic

from .llm import ANTHROPIC_PRICES

FALLBACK_BETA = "server-side-fallback-2026-07-01"
Executor = Callable[[str, dict], tuple[str, bool]]
Emit = Callable[[dict], None]


@dataclass
class LoopResult:
    status: str = "running"                 # complete | no_submission | refused | error
    answer: dict | None = None               # terminal tool input
    steps: int = 0
    tool_calls: list[dict] = field(default_factory=list)
    served_by: list[str] = field(default_factory=list)
    input_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    seconds: float = 0.0
    notes: list[str] = field(default_factory=list)


def _cost(model: str, u) -> float:
    p = ANTHROPIC_PRICES.get(model, ANTHROPIC_PRICES["claude-sonnet-5-5"])
    return ((u.input_tokens or 0) * p["input"] + (u.cache_creation_input_tokens or 0) * p["cache_write"]
            + (u.cache_read_input_tokens or 0) * p["cache_read"] + (u.output_tokens or 0) * p["output"]) / 1e6


def _account(r: LoopResult, resp) -> float:
    u = resp.usage
    before = r.cost_usd
    for it in list(getattr(u, "iterations", None) or []) or [u]:
        model = getattr(it, "model", None) or resp.model
        r.input_tokens += it.input_tokens or 0
        r.cache_write_tokens += it.cache_creation_input_tokens or 0
        r.cache_read_tokens += it.cache_read_input_tokens or 0
        r.output_tokens += it.output_tokens or 0
        r.cost_usd += _cost(model, it)
    if resp.model not in r.served_by:
        r.served_by.append(resp.model)
    return r.cost_usd - before


def _echo(content: list) -> list:
    """After a mid-output fallback, drop model-internal blocks before the last fallback block."""
    idx = [i for i, b in enumerate(content) if b.type == "fallback"]
    if not idx:
        return content
    cut = idx[-1]
    return [b for i, b in enumerate(content) if i > cut or (i < cut and b.type == "text")]


def short(d: dict) -> str:
    s = ", ".join(f"{k}={v!r}" for k, v in d.items() if k not in ("start", "end"))
    return s if len(s) < 110 else s[:107] + "..."


def run_loop(client: anthropic.Anthropic, model: str, system: str, user_content: str, tools: list[dict],
             terminal: str, execute: Executor, effort: str = "medium", max_steps: int = 16,
             max_tokens: int = 16000, emit: Emit | None = None,
             budget_usd: float | None = None) -> LoopResult:
    emit = emit or (lambda e: None)
    r = LoopResult()
    t_start = time.monotonic()
    messages: list = [{"role": "user", "content": user_content}]
    nudged = False
    while r.steps < max_steps:
        r.steps += 1
        emit({"type": "step", "step": r.steps})
        try:
            resp = client.beta.messages.create(
                model=model, max_tokens=max_tokens, system=system, tools=tools, tool_choice={"type": "auto"},
                output_config={"effort": effort}, cache_control={"type": "ephemeral"},
                betas=[FALLBACK_BETA], fallbacks="default", messages=messages)
        except anthropic.AuthenticationError:
            r.status = "error"; r.notes.append("Anthropic rejected the API key")
            break
        except anthropic.RateLimitError as e:
            r.status = "error"; r.notes.append(f"rate limited at step {r.steps}: {e.message}")
            break
        except anthropic.APIStatusError as e:
            r.status = "error"; r.notes.append(f"API error {e.status_code} at step {r.steps}: {e.message}")
            break
        except anthropic.APIConnectionError as e:
            r.status = "error"; r.notes.append(f"connection error at step {r.steps}: {e}")
            break
        spent = _account(r, resp)
        emit({"type": "usage", "step": r.steps, "cost_usd": round(r.cost_usd, 5), "step_cost_usd": round(spent, 5)})
        for b in resp.content:
            if b.type == "fallback":
                note = f"fallback at step {r.steps}: {b.from_.model} -> {b.to.model}"
                r.notes.append(note); emit({"type": "note", "text": note})
        if resp.stop_reason == "refusal":
            cat = getattr(getattr(resp, "stop_details", None), "category", None)
            r.status = "refused"; r.notes.append(f"refused at step {r.steps} (category={cat}) even after fallback")
            break

        content = _echo(resp.content)
        messages.append({"role": "assistant", "content": content})
        uses = [b for b in content if b.type == "tool_use"]
        final = next((b for b in uses if b.name == terminal), None)
        if final:
            r.answer = dict(final.input); r.status = "complete"
            break
        if not uses:
            if resp.stop_reason == "max_tokens":
                r.notes.append(f"max_tokens at step {r.steps}")
            if nudged:
                r.status = "no_submission"
                break
            nudged = True
            messages.append({"role": "user", "content": f"Submit your result now by calling {terminal}."})
            continue

        results = []
        for u in uses:
            emit({"type": "tool_call", "step": r.steps, "name": u.name, "args": dict(u.input)})
            t0 = time.monotonic()
            out, err = execute(u.name, dict(u.input))
            secs = round(time.monotonic() - t0, 2)
            r.tool_calls.append({"step": r.steps, "name": u.name, "args": dict(u.input), "chars": len(out),
                                 "error": err, "seconds": secs})
            emit({"type": "tool_result", "step": r.steps, "name": u.name, "chars": len(out), "error": err,
                  "seconds": secs, "preview": out[:240]})
            results.append({"type": "tool_result", "tool_use_id": u.id, "content": out,
                            **({"is_error": True} if err else {})})
        user_turn: list = results
        over_budget = budget_usd is not None and r.cost_usd >= budget_usd
        if r.steps == max_steps - 1 or over_budget:
            # one-time harness notice, as a text block after the tool results
            why = "Spend limit reached" if over_budget else "Step limit reached"
            user_turn = results + [{"type": "text", "text": f"{why}: call {terminal} on your next turn with what you have."}]
            max_steps = min(max_steps, r.steps + 1)
        messages.append({"role": "user", "content": user_turn})
    else:
        r.status = "no_submission"
    r.seconds = round(time.monotonic() - t_start, 1)
    r.cost_usd = round(r.cost_usd, 5)
    return r
