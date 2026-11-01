# Phase 3: The agentic plane

Status: **poller, triage and incident grouping working**. Next: investigation agent, MCP tools,
DFIR-IRIS cases, approval-gated response.

## Setup

- **Providers.** Model strings in `.env` carry a prefix: `anthropic:claude-haiku-5-5` calls the Anthropic
  API directly, spending Anthropic credits (key: `SOC_ANTHROPIC_API_KEY` in `~/.anthropic_env`), and
  `openrouter:<id>` calls OpenRouter (key: `OPENROUTER_API_KEY` from the environment or `~/.openrouter_env`).
  Defaults: triage `anthropic:claude-haiku-5-5`, investigation `anthropic:claude-sonnet-5-5`.
- **Don't export `ANTHROPIC_API_KEY` in your interactive shell.** Claude Code would pick it up and bill
  to API credits instead of your subscription. The agent reads its key from the file, not your shell.
- Non-secret settings: `.env` (copied from `.env.example`): models, `MIN_LEVEL`, how to reach the indexer.
- Indexer access: user `soc-agent` with role `soc_agent_ro` (read-only on `wazuh-alerts-*` and
  `wazuh-archives-*`; writes and other indices return 403). Password in
  `lab/.secrets/soc-agent-indexer.txt`. The agent opens its own SSH tunnel to `127.0.0.1:9200` on the
  wazuh VM, so the indexer is never exposed on the network.

## Run

```bash
uv run --project agent python -m socagent poll   --since 2h             # bundles only, no LLM calls
uv run --project agent python -m socagent triage --since 2h --limit 10  # triage and append to the ledger
uv run --project agent python -m socagent triage                        # since the last checkpoint
uv run --project agent python -m socagent ledger                        # verdict counts and spend
uv run --project agent python -m socagent incidents                     # group escalations into incidents
uv run --project agent python -m socagent incident INC-20261101-003     # one incident as JSON
uv run --project agent python -m socagent run                           # one cycle: triage new + group
uv run --project agent python -m unittest discover -s agent/tests       # grouping rules
```

The ledger is `results/agent/triage.jsonl` (git-ignored): one line per bundle with the verdict,
techniques, evidence, tokens, **cost in USD** and latency.

## Design

- **Poller**: alerts with `rule.level ≥ MIN_LEVEL` (7), excluding compliance (`sca`) findings, grouped
  by (host, rule) so repeats cost one call. Each bundle carries up to 3 distinct samples, trimmed to
  the useful fields, plus the other rules seen on that host within ±10 minutes.
- **Triage**: Claude Haiku 5.5 at effort `low`. The answer comes through a `submit_triage` tool (verdict,
  confidence, escalate, ATT&CK IDs, summary, rationale, evidence, open questions). On the Anthropic path:
  `tool_choice: auto` + `strict: true` schema + an explicit instruction, with one re-prompt if no tool
  call comes back (forced `tool_choice` is rejected by Sonnet/Opus 5.5). The system prompt and tool are
  prompt-cached (1,360 tokens read from cache on every call after the first). `stop_reason: refusal` is
  recorded as verdict `error` and escalated to a human. On OpenRouter: forced tool call plus
  `reasoning.effort`.
  The system prompt carries the asset inventory, not knowledge of the test harness.

- **Incident grouping** (`incidents.py`, no LLM): takes the latest verdict per bundle, keeps those
  escalated or judged malicious, and merges two of them when they share an **entity** and are within
  **30 minutes**, transitively. An entity is the alerting host, or for network-sensor alerts the lab hosts
  whose IPs appear in the summary or evidence. The gateway, the SIEM and the admin workstation
  (10.10.10.254) are deliberately not entities, or they would link everything. Severity is **critical**
  when a malicious verdict carries credential access, log clearing or defence impairment (T1003, T1558,
  T1555, T1070.001, T1562, T1486, T1490), **high** for any other malicious verdict, and **medium** for
  suspicious only. IDs (`INC-YYYYMMDD-NNN`) and statuses stay stable across re-runs. Output goes to
  `results/agent/incidents.json`.

## First results (1 Nov 2026)

| Window | Bundles | Verdicts | Escalated | Cost |
|---|---|---|---|---|
| Phase 2 retest (6 attacks) | 11 | 10 malicious, 1 suspicious (Zeek cert notice) | 10 | $0.0089 |
| Pre-attack hour (admin activity only) | 6 | 2 benign, 4 suspicious | 3 | $0.0042 |

Average cost **$0.0008 per bundle**, about 6–10 s each.

Same 17 bundles, both providers (same model):

| Path | Verdicts | Escalated | Cost | Avg latency |
|---|---|---|---|---|
| OpenRouter → Haiku 5.5 | 10 malicious · 5 suspicious · 2 benign | 13 | $0.0131 | 4.2 s |
| Anthropic API → Haiku 5.5 | 10 malicious · 4 suspicious · 3 benign | 13 | $0.0136 | 5.9 s |

There were no refusals on credential-dumping content, no re-prompts and no `max_tokens` retries.

Gotchas found on the way:

- **Thinking tokens count against `max_tokens`.** With a 900-token cap, Haiku 5.5 spent the budget
  reasoning and returned truncated tool-call JSON (`finish_reason=length`). Fixed with
  `reasoning.effort=low`, a 3000-token cap and one retry at 8000 on `length`.
- **Leaked tool markup.** Once, a summary contained `</summary><parameter name="rationale">…`. Repaired
  in `_repair()` by splitting the text back into its fields.

Incident grouping on those verdicts: **13 escalations became 4 incidents**, one per real event:

| Incident | Severity | Bundles | What it is |
|---|---|---|---|
| INC-20261101-003 win-victim | critical | 7 | PowerShell → LSASS dump → scheduled task → Security log cleared |
| INC-20261101-004 lin-victim | high | 3 | cron persistence + setuid bit |
| INC-20261101-001 lin-victim | medium | 2 | test user created (benign admin action) |
| INC-20261101-002 lin-victim | medium | 1 | PowerShell package install (benign admin action) |

The two attacks stay separate because they share no host or network link. The two medium incidents
are benign. Closing them is the investigation agent's first job, and the measure of whether
investigating "suspicious" incidents is worth the money.

Observations that shape the next steps:

- **One incident, ten escalations** (solved by grouping above). Each attack bundle correctly cited its
  neighbours, so all were escalated.
- **Over-cautious on admin changes.** A test user creation and a PowerShell package install were
  escalated as "suspicious". No benign item was called malicious. Measure escalation precision in
  Phase 4 before tuning the prompt.
- Rule 92201 also fired on the PowerShell policy-probe file. The agent called it benign, and the
  tuning rule 100200 now covers 92201 too, so it no longer costs a call.
