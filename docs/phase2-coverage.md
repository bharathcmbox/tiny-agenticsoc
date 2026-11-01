# Phase 2: Attack simulation and detection coverage

Goal: run real ATT&CK techniques on the victims, measure what the SOC actually catches, and fix
the gaps. Microsoft Defender stayed **on** for the whole run.

- Plan: [`lab/atomics/phase2-plan.tsv`](../lab/atomics/phase2-plan.tsv): 11 Windows and 6 Linux tests
- Runner: [`lab/atomics/run-plan.sh`](../lab/atomics/run-plan.sh): prereqs → run → settle → cleanup, exact UTC windows
- Matrix: [`lab/atomics/matrix.py`](../lab/atomics/matrix.py): asks the Wazuh indexer what fired in each window
- Raw tables: [before tuning](coverage/phase2-before.md) · [after tuning](coverage/phase2-after.md)

Tools are pinned: Invoke-AtomicRedTeam 2.3.0, atomics at commit `d0cc590`, sysmon-modular release
`configs-a45dedb13a43`, Wazuh 4.14.9.

## Results

"Detected" means an alert at **level 7 or above**, the threshold at which the Phase 3 agents will
pick it up. Rules that fire in at least 80% of a host's windows are attributed to the test harness
and excluded (see [harness noise](#finding-3-the-test-harness-is-noisy-and-looks-malicious)).

| ID | Technique | Before | After | What changed |
|---|---|---|---|---|
| W01 | T1059.001 PowerShell encoded command | 🟢 12 | 🟢 12 | Stock rule 92057 |
| W02 | T1059.001 Known malicious cmdlets | 🟢 12 | (not retested) | Defender + stock rules |
| W03 | **T1003.001 LSASS dump (comsvcs)** | 🟡 4 | 🟢 **14** | New rules 100400–100402 |
| W04 | T1547.001 Run key | 🟢 10 | (not retested) | Stock rule 92041 |
| W05 | T1053.005 Scheduled task | 🟡 4 | 🟢 9 | New rule 100403 |
| W06 | T1218.011 rundll32 VBScript | 🟢 12 | (not retested) | Defender blocked it |
| W07 | T1105 certutil download | 🟢 12 | (not retested) | Defender blocked it |
| W08 | T1071.004 DNS beaconing | 🟡 6 | 🟡 6 | **Open gap**: network-only signal |
| W09 | T1087.001 Account discovery | 🟡 4 | (not retested) | Accepted: discovery is noisy |
| W10 | T1136.001 Create local user | 🟢 12 | (not retested) | Stock rule 92040 |
| W11 | T1070.001 Clear Security log | 🟡 5 | 🟢 12 | Rule 100404 raises stock 63103 |
| L01 | T1136.001 Create Linux user | 🟢 8 | (not retested) | Stock rule 5902 |
| L02 | T1053.003 Cron file | 🟠 0 | 🟢 10 | New rule 100300 (caveat below) |
| L03 | T1070.003 Clear bash history | 🟠 0 | (not retested) | **Open gap** |
| L04 | T1087.001 View UID 0 accounts | 🟠 0 | (not retested) | Accepted: discovery |
| L05 | T1548.001 Set setuid bit | 🟡 4 | 🟢 12 | New rule 100301 |
| L06 | T1059.004 Bash script | 🟠 0 | (not retested) | Accepted: too common to alert on |

**Score at the agent threshold: 7 of 17 before, 12 of 17 after**, with two gaps left open and three
accepted as telemetry-only. Every test produced raw telemetry. Nothing was truly invisible, which
is the point of shipping archives as well as alerts.

## Finding 1: the LSASS dump succeeded silently

`T1003.001-2` (rundll32 + `comsvcs.dll MiniDump`) is one of the most common credential-theft
techniques in real intrusions. On this lab:

- **Defender did not block it.** The dump file `lsass-comsvcs.dmp` was written.
- **Sysmon captured every step**: Event 1 (the command line), Event 10 (rundll32 opened `lsass.exe`
  with `0x1fffff` access) and Event 11 (the `.dmp` file).
- **Wazuh 4.14's stock rules alerted on none of it.** There are no rules for `comsvcs`/`MiniDump`,
  and the Event 10 rules don't cover LSASS.

Three layered rules now catch it independently, by command line, by the handle and by the
artifact, so renaming the binary or changing the dump path still leaves two of the three.

## Finding 2: auditd sees more than Wazuh alerts on

The Neo23x0 audit rules tag events with keys like `cron`, `perm_mod` and `delete`. Wazuh's stock
audit rules only alert on keys in its own CDB list, so these produced **telemetry with no alert**.
New rules:

- `100300`: any write to cron configuration (`key=cron`).
- `100301`: setuid/setgid bit set. It matches the **mode bits in the syscall** (`fchmodat` a2,
  `chmod` a1, hex with a leading digit 4–f), not the command text, so `chmod 4755`, `chmod u+s`
  and a compiled `chmod()` call all match. Validated with `wazuh-logtest`: `a2=9ed` alerts at
  level 12, `a2=1a4` does not.

On L02, rule 100300 fired twice: once when `/usr/bin/dash` created `/etc/cron.d/persistevil` and
once for the cleanup `rm`. (The first matrix only showed the `rm` because of how its window was cut;
the Phase 3 poller showed both.)

## Finding 3: the test harness is noisy, and looks malicious

Before baseline subtraction, **every** Windows test scored "detected at level 15". The cause:

| Rule | Level | Real cause |
|---|---|---|
| 92213 "Executable file dropped in folder commonly used by malware" | 15 | Every PowerShell start writes `%TEMP%\__PSScriptPolicyTest_xxxxxxxx.xxx.ps1` to probe execution policy |
| 91822 "PowerShell script used Invoke-Command" | 12 | Script block logging records the Invoke-AtomicRedTeam module's own source as it loads |
| 91816/91819/91820 | 4 | Same: the module's code, not the technique |
| 60106, 67027, … | 3 | The SSH logon the runner uses |

These need different fixes:

- **92213 is a real-world false positive.** It would fire at level 15 on any Windows host where
  anything starts PowerShell. Rule `100200` drops exactly that filename pattern from PowerShell to
  level 0. The event stays in archives.
- **The module noise is lab-only.** A real attacker loading an offensive PowerShell module *should*
  alert, so it is not suppressed in Wazuh. `matrix.py` subtracts it as a harness baseline instead.

Both make good first lessons for the Phase 3 triage agent: real alerts with benign causes.

## Finding 4: Defender helps, but it's one layer

Defender stopped 3 of 11 Windows tests (rundll32 VBScript, certutil download, malicious cmdlets),
and **quarantined parts of the atomics library on download** (webshell samples, `.sct` scriptlets,
the entire T1070.001 test definition). Its detections reach Wazuh as rules 62123/62124 at levels
12 and 3. It did **not** stop the LSASS dump.

## Open gaps (carried to Phase 3/4)

- **W08 DNS beaconing**: Zeek logged every query, but nothing alerts on regular, periodic lookups
  to one domain. This is a natural job for the investigation agent (pull `dns.log` for a host,
  check the timing) rather than a static rule.
- **L03 bash history cleared**: the atomic runs as root via sudo, and no audit record ties the
  deletion to `.bash_history`. Needs a watch rule on history files.
- Re-run the full plan in Phase 4 under the eval harness so before/after is measured on all 17.

## Reproduce

```bash
./lab/atomics/run-plan.sh lab/atomics/phase2-plan.tsv            # ~20 min
python3 lab/atomics/matrix.py results/atomics/<run>/ --md /tmp/matrix.md
# re-run a subset:
SKIP="W02 W04 ..." ./lab/atomics/run-plan.sh lab/atomics/phase2-plan.tsv
```
