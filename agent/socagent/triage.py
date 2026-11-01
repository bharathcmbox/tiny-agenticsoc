"""Triage agent: one cheap-model call per alert bundle, structured verdict via a forced tool call."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

from .llm import LLM, Usage
from .poller import Bundle

ENVIRONMENT = """\
Environment (asset inventory the SOC maintains):
- win-victim 10.10.10.20: Windows Server 2022, standalone (no domain). Local admin: Administrator.
- lin-victim 10.10.10.21: Ubuntu 24.04 server. Admin user: soc (sudo).
- sensor-gw 10.10.10.1: network sensor and NAT gateway (Zeek, Suricata). Its alerts describe traffic of OTHER hosts.
- wazuh 10.10.10.10: the SIEM itself.
- 10.10.10.254: the SOC administrator's workstation. RDP/SSH sessions and remote administration from it are routine.
  Being routine does NOT make any action from it benign: admin credentials get stolen. Judge the behaviour.
- The Wazuh agent runs periodic configuration assessment (CIS benchmark) checks; on Windows these spawn
  PowerShell/cmd from wazuh-agent.exe and touch registry/policy settings. That pattern alone is expected.
- Every PowerShell start writes and deletes %TEMP%\\__PSScriptPolicyTest_*.ps1 (execution-policy probe).
"""

SYSTEM = f"""You are a tier-1 SOC triage analyst. You receive one bundle of related Wazuh alerts
(same host, same rule) with up to three sample events and the other alerts seen on that host within
ten minutes. Decide quickly and conservatively:

- benign: an explainable, expected cause with no attacker objective (admin routine, agent self-checks, OS noise).
- suspicious: could be an attack but the evidence is ambiguous or one-sided; a human or the investigation agent should look.
- malicious: behaviour whose only plausible purpose is an attacker objective (credential theft, persistence, defence evasion, C2).

Escalate to the investigation agent when the verdict is malicious, or suspicious with real impact.
Ground every claim in a field you were given; do not invent hosts, users or processes. If the data is
insufficient, say what is missing. Prefer specific MITRE ATT&CK technique IDs.

{ENVIRONMENT}
Always answer by calling submit_triage exactly once."""

TOOL = {
    "type": "function",
    "function": {
        "name": "submit_triage",
        "description": "Submit the triage verdict for this alert bundle.",
        "parameters": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["benign", "suspicious", "malicious"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "escalate": {"type": "boolean", "description": "Send to the investigation agent"},
                "attack_techniques": {"type": "array", "items": {"type": "string"},
                                      "description": "MITRE ATT&CK IDs, e.g. T1003.001"},
                "summary": {"type": "string", "description": "One sentence: what happened"},
                "rationale": {"type": "string", "description": "At most three sentences: why this verdict"},
                "key_evidence": {"type": "array", "items": {"type": "string"},
                                 "description": "Field=value facts that drove the verdict"},
                "open_questions": {"type": "array", "items": {"type": "string"},
                                   "description": "What an investigator should check next"},
            },
            "required": ["verdict", "confidence", "escalate", "attack_techniques", "summary", "rationale",
                         "key_evidence", "open_questions"],
        },
    },
}


_LEAK = re.compile(r'</(\w+)>\s*<parameter name="(\w+)">', re.S)


def _repair(v: dict) -> dict:
    """Some provider bridges occasionally leak the model's XML tool syntax into a string field,
    e.g. summary='...</summary>\n<parameter name="rationale">...'. Split it back into fields."""
    for k in list(v):
        if isinstance(v[k], str) and _LEAK.search(v[k]):
            parts = _LEAK.split(v[k])
            v[k] = parts[0].strip()
            for i in range(1, len(parts) - 2, 3):
                name, text = parts[i + 1], parts[i + 2]
                text = re.sub(r'</\w+>\s*$', "", text).strip()
                if name in v and not v[name]:
                    v[name] = text
                elif name not in v or name == k:
                    v[name] = text
    return v


@dataclass
class Triage:
    bundle_key: str
    host: str
    rule_id: str
    rule_description: str
    max_level: int
    alert_count: int
    first: str
    last: str
    verdict: str
    confidence: float
    escalate: bool
    attack_techniques: list[str]
    summary: str
    rationale: str
    key_evidence: list[str]
    open_questions: list[str]
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    latency_s: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


def triage(llm: LLM, model: str, b: Bundle) -> Triage:
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": "Triage this alert bundle:\n" + b.to_prompt()}]
    force = {"type": "function", "function": {"name": "submit_triage"}}
    resp, usage = llm.chat(model, messages, tools=[TOOL], tool_choice=force, max_tokens=3000,
                           reasoning_effort="low")
    choice = resp.choices[0]
    if choice.finish_reason == "length":  # ran out of budget mid-answer: retry once with more room
        resp, extra = llm.chat(model, messages, tools=[TOOL], tool_choice=force, max_tokens=8000,
                               reasoning_effort="low")
        usage.add(extra); choice = resp.choices[0]
    calls = choice.message.tool_calls or []
    if not calls:
        raise RuntimeError(f"no tool call (finish={choice.finish_reason}): {choice.message.content!r:.200}")
    v = _repair(json.loads(calls[0].function.arguments))
    return Triage(bundle_key=b.key, host=b.host, rule_id=b.rule_id, rule_description=b.rule_description,
                  max_level=b.max_level, alert_count=b.count, first=b.first, last=b.last,
                  verdict=v["verdict"], confidence=float(v.get("confidence", 0)), escalate=bool(v.get("escalate")),
                  attack_techniques=v.get("attack_techniques", []), summary=v.get("summary", ""),
                  rationale=v.get("rationale", ""), key_evidence=v.get("key_evidence", []),
                  open_questions=v.get("open_questions", []), model=model,
                  prompt_tokens=usage.prompt_tokens, completion_tokens=usage.completion_tokens,
                  cost_usd=usage.cost_usd, latency_s=round(usage.latency_s, 2))
