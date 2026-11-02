# Phase 3: The agentic plane

Status: **poller, triage, incident grouping, investigation agent, MCP server and SOC console working**.
Next: DFIR-IRIS cases, approval-gated active response, sharing the console (Tailscale or Cloudflare Tunnel).

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
uv run --project agent python -m socagent investigate                   # investigate all incidents with status 'new'
uv run --project agent python -m socagent investigate INC-20261101-003  # one incident (report in results/agent/investigations/)
uv run --project agent python -m unittest discover -s agent/tests       # grouping rules
```

The ledger is `results/agent/triage.jsonl` (git-ignored): one line per bundle with the verdict,
techniques, evidence, tokens, **cost in USD** and latency.

## SOC console and MCP (pre-sales and day-to-day use)

```bash
uv run --project agent python -m socagent console               # http://localhost:8800, prints a login link with the owner token
uv run --project agent python -m socagent token add alice --cap 1.00   # guest token, $1/day on the owner's key
uv run --project agent python -m socagent token list | revoke alice
uv run --project agent python -m socagent ask "which processes touched lsass today?"   # same agent, from the CLI
```

- **Console** (`console.py` + `static/console.html`): a natural-language search bar with a live trace of
  tool calls, then an answer with an evidence table, confidence, cost and follow-up questions. It also
  has an incident list with the investigation reports, a *Connect Claude Code* tab and a *How it works*
  tab (`docs/presales.html`, the pre-sales walkthrough). Self-contained, works offline in the lab.
- **Ask agent** (`ask.py`): Claude Sonnet 5.5 at effort `low`, max 10 turns, the same read-only tools,
  and a strict `answer` tool (markdown answer, evidence rows, confidence, follow-ups). The clock goes
  in the question so tools and system prompt cache across questions. About $0.04 and 15–20 s per
  question on the lab data.
- **MCP**: `mcp_server.py` (MCP Python SDK 2.x, `MCPServer`) exposes 7 read-only tools (the 5 investigation
  tools plus `list_incidents` and `get_investigation_report`), all annotated `readOnlyHint`. It is
  registered for this repo in `.mcp.json` (stdio, no token; Claude Code asks you to approve it once).
  The console also serves it over streamable HTTP at `/mcp/`, behind a bearer token.
- **Access and billing** (`access.py`): every request needs a token. The owner token is created on
  first start in `lab/.secrets/console-owner-token`; guest tokens are stored only as SHA-256 hashes.
  Console questions run on the owner's Anthropic key, capped per guest per UTC day (default $1). A
  guest can paste their own key, which is sent per request and never stored. MCP spends nothing: the
  caller's Claude reasons. Rate limit 6 questions per minute per principal. Spend goes to
  `results/console/spend.jsonl`. Caps are checked between model turns, so a question can overrun a
  nearly exhausted cap by one turn (a $0.03 test cap ended at $0.037).
- **Exposure**: the console binds `127.0.0.1` only. Sharing it is a networking step (Tailscale or
  Cloudflare Tunnel) on top of the token, cap and rate-limit layer that already exists.
- **Shared loop** (`agentloop.py`): the investigation agent and the Ask agent use one loop: caching,
  refusal fallback, per-attempt cost, step and spend caps, and a live event stream.

Findings from building it: the Ask agent's first question surfaced (1) an earlier LSASS dump at 22:01
that the Phase 2 matrix never counted, and (2) `wazuh-agent.exe` opening lsass with full access during
its inventory, which would have tripped new rule 100401. It is now excluded.

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

- **Investigation agent** (`investigate.py` + `tools.py`): Claude Sonnet 5.5, adaptive thinking at effort
  `medium`, in a manual tool loop capped at 16 turns. Read-only tools over the indexer:
  `search_events` (Lucene over alerts or archives), `host_timeline`, `process_tree` (Sysmon GUID chain
  to the root plus children), `network_flows` (Zeek + Suricata by community_id or IP) and `top_values`.
  Each tool result is capped at 9,000 characters. The answer is a strict `submit_investigation` call
  (verdict, timeline with cited evidence, root cause, scope, IOCs, ATT&CK, proposed actions, detection
  gaps, open questions), rendered to Markdown. Append-only history with response content echoed back
  unchanged (Sonnet 5.5 binds thinking blocks to the conversation). Automatic prompt caching across
  turns. **Server-side fallback is on** (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`):
  a safety decline on this security content retries on a fallback model. Cost is counted per attempt
  from `usage.iterations`. Proposed actions are only proposals: nothing in the agent can change a host.

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

Investigations of those four incidents (Sonnet 5.5, effort medium):

| Incident | Investigator's title | Verdict | Right? | Tool calls | Cost | Time |
|---|---|---|---|---|---|---|
| 001 | Short-lived tsoc-test account create/delete by soc via SSH from admin workstation (detection test) | benign 0.75 | ✅ | 2 | $0.041 | 23 s |
| 002 | Atomic Red Team tooling install (PowerShell 7) on lin-victim by soc from admin workstation | benign 0.70 | ✅ | 6 | $0.102 | 25 s |
| 003 | Atomic Red Team-style LSASS dump, log clear and persistence on win-victim via SSH from 10.10.10.254 | true positive 0.80 | ✅ | 4 | $0.078 | 22 s |
| 004 | Cron persistence file and SUID test binary created then deleted via sudo from soc SSH sessions | true positive 0.80 | ✅ | 5 | $0.095 | 24 s |

That's **$0.32 for all four**, with no refusals and no fallbacks needed. Things worth noting:

- On 003 the process tree took it straight to the root (`sshd.exe -z` → `powershell -c "Invoke-AtomicTest
  T1003.001 -TestNumbers 2"` → `rundll32 comsvcs.dll MiniDump 712`). It recognised the emulation framework
  but still called it a **true positive pending confirmation that the exercise was authorised**. That's
  the right call: a compromised admin account would look identical.
- The reports say what they did *not* verify (e.g. "I did not check sudoers, authorized_keys or cron
  directly"). That makes the open questions actionable.
- Cost lever: several tool results hit the 9,000-character cap, and input tokens dominate the spend
  (57–69% served from cache). Tighter default sizes and field selection are the first cost tuning.

Observations that shape the next steps:

- **One incident, ten escalations** (solved by grouping above). Each attack bundle correctly cited its
  neighbours, so all were escalated.
- **Over-cautious on admin changes.** A test user creation and a PowerShell package install were
  escalated as "suspicious". No benign item was called malicious. Measure escalation precision in
  Phase 4 before tuning the prompt.
- Rule 92201 also fired on the PowerShell policy-probe file. The agent called it benign, and the
  tuning rule 100200 now covers 92201 too, so it no longer costs a call.
