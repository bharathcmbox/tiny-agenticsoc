Run: `phase2-retest-20261101T222427Z` · 6 tests · 6 detected, 0 low-signal, 0 telemetry only, 0 missed

Result key: **detected** = an alert at level ≥ 7 (reaches the agentic plane); **low-signal** = alerts only below 7; **telemetry only** = raw events but no alert; **missed** = nothing from the host in the window. Harness baseline rules (below) are excluded.

| ID | Host | Technique | Test | Result | Max level | Defender | Top alerts (level) | Raw events | Network |
|---|---|---|---|---|---|---|---|---|---|
| W01 | win-victim | T1059.001-17 | T1059.001-17 PowerShell Command Execution | 🟢 detected | 12 | no | Powershell.exe spawned a powershell process which executed a base64 en (12)<br>Windows command prompt started by an abnormal process (4)<br>Suspicious Windows cmd shell execution (3) | 492 | eve.json 1 |
| W03 | win-victim | T1003.001-2 | T1003.001-2 Dump LSASS.exe Memory using comsvcs.dll | 🟢 detected | 14 | no | LSASS dump via comsvcs.dll MiniDump: \"C:\\Windows\\System32\\rundll32 (14)<br>Process C:\\Windows\\System32\\rundll32.exe opened lsass.exe with acce (13)<br>LSASS dump file written: C:\\Users\\Administrator\\AppData\\Local\\Tem (12) | 567 | none |
| W05 | win-victim | T1053.005-2 | T1053.005-2 Scheduled task Local | 🟢 detected | 9 | no | Scheduled task created: SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\\w (9)<br>WMI query for System Information Discovery. (6)<br>Powershell process spawned Windows command shell instance (4) | 462 | none |
| L02 | lin-victim | T1053.003-3 | T1053.003-3 Cron - Add script to /etc/cron.d folder | 🟢 detected | 10 | no | auditd: cron configuration changed by /usr/bin/rm (/etc/cron.d/persist (10)<br>Successful sudo to ROOT executed. (3)<br>PAM: Login session opened. (3) | 662 | conn.log 6, dns.log 6, eve.json 6 |
| L05 | lin-victim | T1548.001-3 | T1548.001-3 Set a SetUID flag on file | 🟢 detected | 12 | no | auditd: setuid/setgid bit set by /usr/bin/chmod (auid=1000) (12)<br>Successful sudo to ROOT executed. (3)<br>PAM: Login session opened. (3) | 885 | conn.log 14, dns.log 14, eve.json 14 |
| W11 | win-victim | T1070.001 (manual) | wevtutil cl Security | 🟢 detected | 12 | no | Security audit log cleared by  (12) | 108 | eve.json 4, conn.log 2, dns.log 2 |

**Harness baseline** (fired in ≥ 80% of a host's windows, so attributed to the test harness):

- win: rule 91822 (level 12) Powershell script used "Invoke-command" cmdlet to execute sub script
- win: rule 91816 (level 4) Powershell script querying system environment variables
- win: rule 91819 (level 4) Powershell script searching filesystem
- win: rule 91820 (level 4) Powershell script recursively collected files from a filesystem search
- win: rule 60106 (level 3) Windows Logon Success
- win: rule 60137 (level 3) Windows User Logoff
- win: rule 67023 (level 3) Non service account logged off.
- win: rule 67024 (level 3) Service logon event registered from non standard service account.
- win: rule 67027 (level 3) A process was created.
- win: rule 67028 (level 3) Special privileges assigned to new logon.

