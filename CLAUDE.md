# CLAUDE.md

Hands-on agentic SOC home lab. See README.md for architecture and phase status.

## Layout
- `lab/config.env` is the single source of truth for IPs, MACs, VM sizing and versions. It is
  read by both bash and PowerShell, so keep it as plain `LAB_KEY=value` lines.
- `lab/cloud-init/<vm>/` holds NoCloud templates. Only `${LAB_*}` variables are substituted
  (envsubst with an explicit list); any other `$` is left alone.
- `lab/images/build-images.sh` runs in WSL. `lab/hyperv/*.ps1` run on Windows, elevated, from `C:\HyperV\tiny-soc`.
- `docs/phaseN-*.md` hold the per-phase runbook and verification checklist.

## Conventions
- Lab access: `ssh -i ~/.ssh/tiny-soc_ed25519 soc@<ip>`. Lab subnet 10.10.10.0/24, gateway .1, Wazuh .10.
- Never commit secrets. `lab/.secrets/` and `.env` are git-ignored.
- Atomic Red Team runs only inside lab VMs, never on the host or in WSL.
- Model access is in `agent/socagent/llm.py`, two providers: `anthropic:<model>` (Anthropic API directly;
  unprefixed `claude-*`) and `openrouter:<id>` (OpenRouter; unprefixed ids with `/`). Triage runs on
  both; the investigation agent and `ask` are Anthropic-only (`investigate.py` rejects other providers,
  `ask` uses the Anthropic client). Keep the model choice configurable (`TRIAGE_MODEL`, `INVESTIGATE_MODEL`,
  `ASK_MODEL`) and record cost per alert.

## Tests
- Agent tests live in `agent/tests/`. Run them with `cd agent && uv run pytest` (pytest is a
  uv dev dependency of the `agent/` project).
