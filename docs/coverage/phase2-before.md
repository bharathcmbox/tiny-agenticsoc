Run: `phase2-20261101T215906Z` · 17 tests · 7 detected, 6 low-signal, 4 telemetry only, 0 missed

Result key: **detected** = an alert at level ≥ 7 (reaches the agentic plane); **low-signal** = alerts only below 7; **telemetry only** = raw events but no alert; **missed** = nothing from the host in the window. Harness baseline rules (below) are excluded.

| ID | Host | Technique | Test | Result | Max level | Defender | Top alerts (level) | Raw events | Network |
|---|---|---|---|---|---|---|---|---|---|
| W01 | win-victim | T1059.001-17 | T1059.001-17 PowerShell Command Execution | 🟢 detected | 12 | no | Powershell.exe spawned a powershell process which executed a base64 en (12)<br>Windows command prompt started by an abnormal process (4)<br>Suspicious Windows cmd shell execution (3) | 494 | conn.log 3 |
| W02 | win-victim | T1059.001-18 | T1059.001-18 PowerShell Invoke Known Malicious Cmdlets | 🟢 detected | 12 | yes | Windows Defender: Antimalware platform detected  potentially unwanted  (12)<br>Powershell process spawned powershell instance (4)<br>Detected WinRM activity from 0:0:0:0:0:0:0:1 to 0:0:0:0:0:0:0:1 (4) | 509 | eve.json 4, conn.log 2, dns.log 2, ssl.log 2 |
| W03 | win-victim | T1003.001-2 | T1003.001-2 Dump LSASS.exe Memory using comsvcs.dll | 🟡 low-signal | 4 | no | Powershell executing process discovery (4)<br>Powershell process spawned powershell instance (4) | 565 | conn.log 1 |
| W04 | win-victim | T1547.001-1 | T1547.001-1 Reg Key Run | 🟢 detected | 10 | no | Value added to registry key has Base64-like pattern (10)<br>Registry entry to be executed on next logon was modified using command (6)<br>Windows command prompt started by an abnormal process (4) | 434 | conn.log 3 |
| W05 | win-victim | T1053.005-2 | T1053.005-2 Scheduled task Local | 🟡 low-signal | 4 | no | Powershell process spawned Windows command shell instance (4)<br>Windows command prompt started by an abnormal process (4)<br>Process loaded taskschd.dll module. May be used to create delayed malw (4) | 438 | eve.json 4, ssl.log 2, conn.log 1 |
| W06 | win-victim | T1218.011-2 | T1218.011-2 Rundll32 execute VBscript command | 🟢 detected | 12 | yes | Windows Defender: Antimalware platform detected  potentially unwanted  (12)<br>Windows command prompt started by an abnormal process (4)<br>Detected WinRM activity from 0:0:0:0:0:0:0:1 to 0:0:0:0:0:0:0:1 (4) | 447 | conn.log 4, eve.json 3, ssl.log 2, dns.log 1 |
| W07 | win-victim | T1105-7 | T1105-7 certutil download (urlcache) | 🟢 detected | 12 | yes | Windows Defender: Antimalware platform detected  potentially unwanted  (12)<br>Windows command prompt started by an abnormal process (4)<br>Windows Defender: Antimalware platform performed an action to protect  (3) | 401 | eve.json 4, conn.log 3, ssl.log 2 |
| W08 | win-victim | T1071.004-2 | T1071.004-2 DNS Regular Beaconing | 🟡 low-signal | 6 | no | WMI query for System Information Discovery. (6)<br>Powershell process spawned powershell instance (4)<br>Service startup type was changed (3) | 594 | eve.json 12, conn.log 9, dns.log 4 |
| W09 | win-victim | T1087.001-8 | T1087.001-8 Enumerate all accounts on Windows (Local) | 🟡 low-signal | 4 | no | Windows command prompt started by an abnormal process (4)<br>Discovery activity executed (3)<br>Suspicious Windows cmd shell execution (3) | 445 | conn.log 1 |
| W10 | win-victim | T1136.001-4 | T1136.001-4 Create a new user in a command prompt | 🟢 detected | 12 | no | net1.exe executed a user creation command (12)<br>User account enabled or created (8)<br>User account disabled or deleted (8) | 449 | conn.log 1 |
| L01 | lin-victim | T1136.001-1 | T1136.001-1 Create a user account on a Linux system | 🟢 detected | 8 | no | New user added to the system. (8)<br>Group (or user) deleted from the system. (3) | 906 | conn.log 6, dns.log 6, eve.json 6 |
| L02 | lin-victim | T1053.003-3 | T1053.003-3 Cron - Add script to /etc/cron.d folder | 🟠 telemetry only | 0 | no | none | 651 | conn.log 6, dns.log 6, eve.json 6 |
| L03 | lin-victim | T1070.003-1 | T1070.003-1 Clear Bash history (rm) | 🟠 telemetry only | 0 | no | none | 633 | conn.log 6, dns.log 6, eve.json 6 |
| L04 | lin-victim | T1087.001-3 | T1087.001-3 View accounts with UID 0 | 🟠 telemetry only | 0 | no | none | 645 | conn.log 6, dns.log 6, eve.json 6 |
| L05 | lin-victim | T1548.001-3 | T1548.001-3 Set a SetUID flag on file | 🟡 low-signal | 4 | no | First time user executed sudo. (4) | 706 | conn.log 14, dns.log 14, eve.json 14 |
| L06 | lin-victim | T1059.004-1 | T1059.004-1 Create and Execute Bash Shell Script | 🟠 telemetry only | 0 | no | none | 643 | eve.json 12, conn.log 6, dns.log 6 |
| W11 | win-victim | T1070.001 (manual) | wevtutil cl Security | 🟡 low-signal | 5 | no | The audit log was cleared (5) | 111 | eve.json 5, dns.log 3, ssl.log 2, conn.log 1 |

**Harness baseline** (fired in ≥ 80% of a host's windows, so attributed to the test harness):

- lin: rule 5402 (level 3) Successful sudo to ROOT executed.
- lin: rule 5501 (level 3) PAM: Login session opened.
- lin: rule 5502 (level 3) PAM: Login session closed.
- lin: rule 5715 (level 3) sshd: authentication success.
- win: rule 92213 (level 15) Executable file dropped in folder commonly used by malware
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

