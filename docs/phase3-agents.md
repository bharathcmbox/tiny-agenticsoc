# Phase 3: The agentic plane

Status: **poller + triage agent working**. Next: incident grouping, investigation agent, MCP tools,
DFIR-IRIS cases, approval-gated response.

## Setup

- OpenRouter key: read from `OPENROUTER_API_KEY` in the environment, falling back to `~/.openrouter_env`.
  It is never copied into the repo. Put a credit limit on the key in OpenRouter.
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
```

The ledger is `results/agent/triage.jsonl` (git-ignored): one line per bundle with the verdict,
techniques, evidence, tokens, **cost in USD** and latency.

## Design

- **Poller**: alerts with `rule.level ≥ MIN_LEVEL` (7), excluding compliance (`sca`) findings, grouped
  by (host, rule) so repeats cost one call. Each bundle carries up to 3 distinct samples, trimmed to
  the useful fields, plus the other rules seen on that host within ±10 minutes.
- **Triage**: `anthropic/claude-haiku-5.5` with reasoning effort `low`, forced `submit_triage` tool call
  (verdict, confidence, escalate, ATT&CK IDs, summary, rationale, evidence, open questions).
  The system prompt carries the asset inventory, not knowledge of the test harness.

## First results (1 Nov 2026)

| Window | Bundles | Verdicts | Escalated | Cost |
|---|---|---|---|---|
| Phase 2 retest (6 attacks) | 11 | 10 malicious, 1 suspicious (Zeek cert notice) | 10 | $0.0089 |
| Pre-attack hour (admin activity only) | 6 | 2 benign, 4 suspicious | 3 | $0.0042 |

Average cost **$0.0008 per bundle**, about 6–10 s each.

Gotchas found on the way:

- **Thinking tokens count against `max_tokens`.** With a 900-token cap, Haiku 5.5 spent the budget
  reasoning and returned truncated tool-call JSON (`finish_reason=length`). Fixed with
  `reasoning.effort=low`, a 3000-token cap and one retry at 8000 on `length`.
- **Leaked tool markup.** Once, a summary contained `</summary><parameter name="rationale">…`. Repaired
  in `_repair()` by splitting the text back into its fields.

Observations that shape the next steps:

- **One incident, ten escalations.** Each attack bundle correctly cited its neighbours, so all were
  escalated. An incident-grouping step must merge escalations per host and time window before the
  (20× pricier) investigation agent runs.
- **Over-cautious on admin changes.** A test user creation and a PowerShell package install were
  escalated as "suspicious". No benign item was called malicious. Measure escalation precision in
  Phase 4 before tuning the prompt.
- Rule 92201 also fired on the PowerShell policy-probe file. The agent called it benign, and the
  tuning rule 100200 now covers 92201 too, so it no longer costs a call.
