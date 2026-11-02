"""Investigation agent: one manual tool-use loop per incident on the Anthropic API.

- Claude Sonnet 5.5, adaptive thinking at effort "medium" (recommended for multistep tool use).
- Append-only history: each response's content goes back unchanged, so thinking blocks stay valid.
- Server-side fallback ("default"): if a safety classifier declines the security content, the API
  retries on a fallback model; fallback turns are echoed back as the docs require.
- Automatic prompt caching across turns; cost counted per attempt from usage.iterations.
- The harness, not the model, enforces a step cap; the answer arrives through submit_investigation.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from .agentloop import run_loop, short
from .config import RESULTS
from .incidents import Incident
from .llm import LLM, split_model
from .tools import DATA_NOTES, TOOL_SPECS, SocTools
from .triage import ENVIRONMENT

INVESTIGATIONS = RESULTS / "investigations"
MAX_STEPS = 16          # model turns
MAX_TOKENS = 16000      # per turn, thinking included

SUBMIT = {
    "name": "submit_investigation",
    "description": "Submit the finished investigation. Call this exactly once, when you can support a verdict.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["true_positive", "benign", "inconclusive"]},
            "confidence": {"type": "number", "description": "0.0 to 1.0"},
            "title": {"type": "string", "description": "Short incident title, e.g. 'LSASS credential dump via comsvcs.dll on win-victim'"},
            "summary": {"type": "string", "description": "3-6 sentences for the analyst on call"},
            "root_cause": {"type": "string", "description": "How it started: the initial process/session/user, or why it is benign"},
            "timeline": {"type": "array", "items": {"type": "object", "properties": {
                "time": {"type": "string"}, "host": {"type": "string"}, "event": {"type": "string"},
                "evidence": {"type": "string", "description": "the field values that show it"}},
                "required": ["time", "host", "event", "evidence"], "additionalProperties": False}},
            "scope": {"type": "object", "properties": {
                "hosts": {"type": "array", "items": {"type": "string"}},
                "accounts": {"type": "array", "items": {"type": "string"}},
                "processes": {"type": "array", "items": {"type": "string"}},
                "external_ips": {"type": "array", "items": {"type": "string"}}},
                "required": ["hosts", "accounts", "processes", "external_ips"], "additionalProperties": False},
            "iocs": {"type": "array", "items": {"type": "object", "properties": {
                "type": {"type": "string", "enum": ["ip", "domain", "url", "file_path", "hash", "process", "account", "registry", "other"]},
                "value": {"type": "string"}, "context": {"type": "string"}},
                "required": ["type", "value", "context"], "additionalProperties": False}},
            "attack_techniques": {"type": "array", "items": {"type": "string"}},
            "proposed_actions": {"type": "array", "description": "Containment/remediation for a human to approve. Empty if benign.",
                                 "items": {"type": "object", "properties": {
                                     "action": {"type": "string", "enum": ["kill_process", "isolate_host", "block_ip",
                                                                           "disable_account", "delete_file", "remove_persistence",
                                                                           "reset_credentials", "collect_forensics", "other"]},
                                     "host": {"type": "string"}, "target": {"type": "string"},
                                     "reason": {"type": "string"},
                                     "urgency": {"type": "string", "enum": ["immediate", "soon", "later"]}},
                                     "required": ["action", "host", "target", "reason", "urgency"], "additionalProperties": False}},
            "detection_gaps": {"type": "array", "items": {"type": "string"},
                               "description": "Things the SOC failed to alert on or could not see"},
            "open_questions": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["verdict", "confidence", "title", "summary", "root_cause", "timeline", "scope", "iocs",
                     "attack_techniques", "proposed_actions", "detection_gaps", "open_questions"],
        "additionalProperties": False,
    },
}

SYSTEM = f"""You are a senior SOC analyst investigating one incident in a small lab network monitored by
Wazuh (Sysmon, Windows event logs, auditd, file integrity), Zeek and Suricata. Tier-1 triage has grouped
related alerts into the incident you receive; their verdicts are leads, not conclusions.

Your job: establish what actually happened, how it started, what it touched, and whether it is a true
positive, benign, or inconclusive. Then propose containment for a human to approve. You cannot change
anything yourself: every tool is read-only.

How to work:
- Verify the key claims from triage against raw events (index "archives" holds every event, not only alerts).
- For Windows process activity, rebuild the process tree; follow it to the root (the logon session,
  service or remote session that started it).
- Check the network: connections and DNS from the affected hosts around the incident window.
- Look for scope: the same behaviour on other hosts, other accounts, persistence left behind, cleanup.
- "Benign" is a legitimate conclusion when the evidence explains the activity; say what explains it.
- Every timeline entry and claim must cite field values you actually saw in tool output.
- When you have enough to support a verdict, call submit_investigation. Do not stop without calling it.

{DATA_NOTES}
{ENVIRONMENT}"""


@dataclass
class Investigation:
    incident_id: str
    model: str
    started: str
    status: str = "running"             # complete | no_submission | refused | error
    report: dict | None = None
    steps: int = 0
    tool_calls: list[dict] = field(default_factory=list)   # name, args, chars, error, seconds
    served_by: list[str] = field(default_factory=list)     # models that produced turns (fallbacks show here)
    input_tokens: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    seconds: float = 0.0
    notes: list[str] = field(default_factory=list)


def brief(inc: Incident) -> str:
    t0 = datetime.fromisoformat(inc.first.replace("+0000", "+00:00"))
    t1 = datetime.fromisoformat(inc.last.replace("+0000", "+00:00"))
    return json.dumps({
        "incident": inc.id, "severity": inc.severity, "hosts": inc.hosts,
        "window_utc": {"first_alert": inc.first, "last_alert": inc.last,
                       "suggested_search_from": (t0 - timedelta(minutes=30)).isoformat(),
                       "suggested_search_to": (t1 + timedelta(minutes=30)).isoformat()},
        "triage_techniques": inc.techniques,
        "alert_bundles": [{k: a[k] for k in ("host", "rule_id", "level", "count", "first", "verdict", "confidence",
                                             "summary", "open_questions")} for a in inc.alerts],
    }, indent=1, ensure_ascii=False)


def investigate(llm: LLM, model: str, tools: SocTools, inc: Incident, effort: str = "medium",
                log=print) -> Investigation:
    provider, m = split_model(model)
    if provider != "anthropic":
        raise SystemExit("the investigation agent uses the Anthropic API (set INVESTIGATE_MODEL=anthropic:...)")

    def emit(e):
        if e["type"] == "tool_result":
            pass
        elif e["type"] == "tool_call":
            log(f"  step {e['step']:2d}: {e['name']}({short(e['args'])})")
        elif e["type"] == "note":
            log(f"  note: {e['text']}")

    started = datetime.now().astimezone().isoformat(timespec="seconds")
    r = run_loop(llm.anthropic(), m, SYSTEM, "Investigate this incident:\n" + brief(inc), TOOL_SPECS + [SUBMIT],
                 "submit_investigation", tools.run, effort=effort, max_steps=MAX_STEPS, max_tokens=MAX_TOKENS,
                 emit=emit)
    if r.answer:
        log(f"  step {r.steps:2d}: submit_investigation -> {r.answer.get('verdict')} ({r.answer.get('confidence')})")
    return Investigation(incident_id=inc.id, model=m, started=started, status=r.status, report=r.answer,
                         steps=r.steps, tool_calls=r.tool_calls, served_by=r.served_by, input_tokens=r.input_tokens,
                         cache_write_tokens=r.cache_write_tokens, cache_read_tokens=r.cache_read_tokens,
                         output_tokens=r.output_tokens, cost_usd=r.cost_usd, seconds=r.seconds, notes=r.notes)


def save(inv: Investigation) -> tuple[str, str]:
    INVESTIGATIONS.mkdir(parents=True, exist_ok=True)
    j = INVESTIGATIONS / f"{inv.incident_id}.json"
    md = INVESTIGATIONS / f"{inv.incident_id}.md"
    j.write_text(json.dumps(asdict(inv), indent=1, ensure_ascii=False))
    md.write_text(render(inv))
    with (RESULTS / "investigations.jsonl").open("a") as f:
        f.write(json.dumps({k: v for k, v in asdict(inv).items() if k not in ("report", "tool_calls")}
                           | {"verdict": (inv.report or {}).get("verdict"), "tool_calls": len(inv.tool_calls)}) + "\n")
    return str(j), str(md)


def render(inv: Investigation) -> str:
    r = inv.report or {}
    L = [f"# {inv.incident_id}: {r.get('title', '(no report)')}", "",
         f"**Verdict:** {r.get('verdict', inv.status)} · **confidence** {r.get('confidence', '-')} · "
         f"**model** {', '.join(inv.served_by) or inv.model} · **{inv.steps} turns, {len(inv.tool_calls)} tool calls** · "
         f"**${inv.cost_usd:.4f}** · {inv.seconds}s", ""]
    if not r:
        L += [f"Investigation ended with status `{inv.status}`.", "", *[f"- {n}" for n in inv.notes]]
        return "\n".join(L) + "\n"
    L += ["## Summary", "", r["summary"], "", "## Root cause", "", r["root_cause"], "", "## Timeline", "",
          "| Time (UTC) | Host | Event | Evidence |", "|---|---|---|---|"]
    L += [f"| {e['time']} | {e['host']} | {e['event']} | {e['evidence'].replace('|', '/')} |" for e in r["timeline"]]
    sc = r["scope"]
    L += ["", "## Scope", "", f"- Hosts: {', '.join(sc['hosts']) or '-'}", f"- Accounts: {', '.join(sc['accounts']) or '-'}",
          f"- Processes: {', '.join(sc['processes']) or '-'}", f"- External IPs: {', '.join(sc['external_ips']) or '-'}",
          "", "## Indicators", ""]
    L += [f"- `{i['type']}` **{i['value']}**: {i['context']}" for i in r["iocs"]] or ["- none"]
    L += ["", f"**ATT&CK:** {', '.join(r['attack_techniques']) or '-'}", "", "## Proposed actions (need approval)", ""]
    L += [f"- [{a['urgency']}] **{a['action']}** on {a['host']}: `{a['target']}`: {a['reason']}" for a in r["proposed_actions"]] or ["- none"]
    L += ["", "## Detection gaps", ""] + ([f"- {g}" for g in r["detection_gaps"]] or ["- none"])
    L += ["", "## Open questions", ""] + ([f"- {q}" for q in r["open_questions"]] or ["- none"])
    L += ["", "## Tool calls", "", "| Step | Tool | Arguments | Result chars |", "|---|---|---|---|"]
    L += [f"| {c['step']} | {c['name']} | `{short(c['args'])}` | {c['chars']}{' (error)' if c['error'] else ''} |" for c in inv.tool_calls]
    if inv.notes:
        L += ["", "## Harness notes", ""] + [f"- {n}" for n in inv.notes]
    return "\n".join(L) + "\n"
