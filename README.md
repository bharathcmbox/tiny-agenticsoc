# tiny-agenticsoc

A small but realistic **agentic SOC** home lab, built hands-on with Claude Code and as much
open-source software as possible. It runs on a single Windows 11 Pro laptop (Hyper-V + WSL2),
so it costs nothing to host. The only spend is LLM tokens through OpenRouter.

| Layer | Component |
|---|---|
| Endpoint telemetry | Wazuh agent, Sysmon ([sysmon-modular](https://github.com/olafhartong/sysmon-modular)), auditd |
| Network telemetry | Zeek, Suricata (ET Open), both with community-id |
| SIEM / XDR | Wazuh (indexer + manager + dashboard, single node) |
| Attack simulation | Atomic Red Team (Invoke-AtomicRedTeam) |
| Case management | DFIR-IRIS |
| Agentic layer | Python tool-use agents → OpenRouter, plus an MCP server exposing the same tools to Claude Code |

## Architecture

Full write-up with an interactive diagram: [docs/architecture.html](docs/architecture.html) · [docs/architecture.md](docs/architecture.md)

```
Hyper-V internal switch "LabNet" 10.10.10.0/24              Windows host / WSL2
┌──────────────────────────────────────────────┐        ┌───────────────────────────────┐
│ sensor-gw  10.10.10.1   NAT gw, DNS/DHCP      │ wan ──▶│ Default Switch → internet      │
│            Zeek + Suricata on 'mon' (mirror)  │        │                               │
│ wazuh      10.10.10.10  Wazuh all-in-one      │◀───────│ host 10.10.10.254 (LabNet)    │
│ win-victim 10.10.10.20  Sysmon + agent + ART  │ mirror │ WSL2 (mirrored networking):   │
│ lin-victim 10.10.10.21  auditd + agent + ART  │ ──────▶│   soc-agent, DFIR-IRIS,       │
└──────────────────────────────────────────────┘ sensor │   Claude Code                 │
                                                        └───────────────────────────────┘
```

* **All lab traffic goes through `sensor-gw`.** Victim NICs are also Hyper-V *port-mirror sources*,
  so Zeek and Suricata see lateral (victim↔victim) traffic as well as internet-bound traffic.
* **Containment:** `sensor-gw` drops forwarding from the lab to RFC1918, CGNAT and link-local
  ranges, so the lab can reach the internet but not your home LAN or the host. The host also
  firewall-blocks unsolicited inbound traffic from `10.10.10.0/24`.

## Phases

- [x] **0. Infra:** switch, VMs, gateway, sensors → [docs/phase0-infra.md](docs/phase0-infra.md)
- [x] **1. Telemetry:** Wazuh install, agents, Sysmon, Zeek/Suricata log shipping → [docs/phase1-telemetry.md](docs/phase1-telemetry.md)
- [x] **2. Attack sim:** 17 atomics, coverage matrix, detection fixes (7 → 12 of 17 detected) → [docs/phase2-coverage.md](docs/phase2-coverage.md)
- [ ] **3. Agent:** ingest → triage → investigate → IRIS case → human-approved response
- [ ] **4. Eval:** atomic-driven scorecard (detection, verdict accuracy, cost/latency per alert)

## Resource budget (32 GB host)

| VM | vCPU | RAM | Disk |
|---|---|---|---|
| sensor-gw | 2 | 2 GB | 30 GB |
| wazuh | 4 | 6 GB | 60 GB |
| win-victim | 2 | 2–4 GB (dynamic) | 64 GB |
| lin-victim | 1 | 1–1.5 GB (dynamic) | 20 GB |
| WSL2 (capped) | 8 | 8 GB | |

All sizing and addressing lives in [`lab/config.env`](lab/config.env).

## Quick start (Phase 0)

```bash
# WSL
./lab/images/build-images.sh
```
```powershell
# Windows, elevated
cd C:\HyperV\tiny-soc
powershell -ExecutionPolicy Bypass -File .\build-lab.ps1 -WindowsIso C:\ISO\win-eval.iso
```

See [docs/phase0-infra.md](docs/phase0-infra.md) for prerequisites and verification steps.

> ⚠️ This lab runs real attack techniques. Keep it on the isolated LabNet, never install agents
> or run atomics on your host or work machines, and snapshot before every test.
