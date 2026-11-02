"""Natural-language search: answer an analyst's question with evidence, using the read-only SOC tools."""
from __future__ import annotations

from datetime import datetime, timezone

import anthropic

from .agentloop import LoopResult, run_loop
from .tools import DATA_NOTES, TOOL_SPECS, SocTools
from .triage import ENVIRONMENT

ANSWER = {
    "name": "answer",
    "description": "Return the answer to the analyst. Call this exactly once, when you can answer (or know you can't).",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "answer_markdown": {"type": "string", "description": "Direct answer first, then detail. Markdown; short tables welcome."},
            "evidence": {"type": "array", "description": "The events that support the answer",
                         "items": {"type": "object", "properties": {
                             "time": {"type": "string"}, "host": {"type": "string"},
                             "source": {"type": "string", "description": "e.g. Sysmon EID 1, auditd, Zeek conn, Suricata alert, Wazuh rule 100400"},
                             "detail": {"type": "string", "description": "the field values that matter"}},
                             "required": ["time", "host", "source", "detail"], "additionalProperties": False}},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "follow_ups": {"type": "array", "items": {"type": "string"}, "description": "2-3 useful next questions"},
        },
        "required": ["answer_markdown", "evidence", "confidence", "follow_ups"],
        "additionalProperties": False,
    },
}


SYSTEM = f"""You answer questions from SOC analysts about a small lab network monitored by Wazuh (Sysmon,
Windows event logs, auditd, file integrity), Zeek and Suricata. You have read-only search tools over all
alerts and raw events. The question states the current time; interpret relative times ("today",
"last hour") from it.

- Search before answering; never answer from general knowledge alone. If the data cannot answer the
  question, say what you searched and what is missing.
- Lead with the direct answer, then the supporting detail. Cite evidence: timestamps, hosts and field values
  you actually saw. Keep it concise: an analyst is reading this in a search box.
- Prefer a few precise queries over many broad ones. Use top_values for "which/how many" questions,
  host_timeline for "what happened on X", process_tree for "what started this", network_flows for
  connections and DNS.
- Finish by calling the answer tool.

{DATA_NOTES}

{ENVIRONMENT}"""


def ask(client: anthropic.Anthropic, model: str, tools: SocTools, question: str, effort: str = "low",
        max_steps: int = 10, budget_usd: float | None = None, emit=None) -> LoopResult:
    # the clock goes in the user turn, so tools + system stay byte-identical and cache across questions
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return run_loop(client, model, SYSTEM, f"Current time: {now}\nQuestion: {question}", TOOL_SPECS + [ANSWER], "answer", tools.run,
                    effort=effort, max_steps=max_steps, max_tokens=12000, emit=emit, budget_usd=budget_usd)
