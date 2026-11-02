<#
  tiny-agenticsoc active response for Windows agents (run by tsoc-ar.cmd, which wazuh-execd invokes).
  Invoked only by a human-approved request through the Wazuh API:
      PUT /active-response {"command": "!tsoc-ar.cmd", "arguments": [action_id, action, target]}
  Protocol (wazuh-execd 4.x): read one JSON line on stdin, answer check_keys, wait for continue/abort.
  Every action is allowlisted, validated, refuses protected targets, and is reversible where it can be:
  files are quarantined (not deleted), scheduled tasks are exported before removal, isolation releases itself.
  The result is logged as one JSON line in active-responses.log for Wazuh to decode and the SOC to verify.
#>
$ErrorActionPreference = 'Stop'
$Base  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)          # ...\ossec-agent
$Log   = Join-Path $Base 'active-response\active-responses.log'
$Quar  = 'C:\ProgramData\tsoc-quarantine'
$LabInfra = @('10.10.10.1', '10.10.10.10', '10.10.10.254')
$ProtectedProcs = @('system', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'sshd',
                    'wazuh-agent', 'sysmon64', 'msmpeng', 'explorer', 'powershell')
$ProtectedUsers = @('administrator', 'system', 'defaultaccount', 'wdagutilityaccount')

function Write-Result($id, $action, $target, $status, $detail) {
  $o = [ordered]@{ version = 1; origin = @{ name = 'tsoc-ar'; module = 'active-response' }; command = 'result'
                   parameters = [ordered]@{ program = 'tsoc-ar'; action_id = $id; action = $action; target = $target
                                            status = $status; detail = $detail } }
  $line = (Get-Date -Format 'yyyy/MM/dd HH:mm:ss') + ' active-response/bin/tsoc-ar: ' + ($o | ConvertTo-Json -Compress -Depth 5)
  Add-Content -Path $Log -Value $line -Encoding ascii
}

function Move-ToQuarantine([string]$path) {
  New-Item -ItemType Directory -Force -Path $Quar | Out-Null
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
  $dest = Join-Path $Quar ((Get-Date -Format 'yyyyMMddTHHmmss_') + ($path -replace '[:\\/]', '_'))
  Move-Item -LiteralPath $path -Destination $dest
  return "moved to $dest (sha256 $hash)"
}

$actions = @{
  kill_process = {
    param($t)
    if ($t -match '^\d+$') { $p = Get-Process -Id ([int]$t) } else {
      if ($t -notmatch '^[\w.+-]{1,64}$') { throw [System.UnauthorizedAccessException]"bad process name '$t'" }
      $p = Get-Process -Name ($t -replace '\.exe$', '') -ErrorAction SilentlyContinue }
    if (-not $p) { return "no running process matched '$t'" }
    $bad = $p | Where-Object { $ProtectedProcs -contains $_.ProcessName.ToLower() }
    if ($bad) { throw [System.UnauthorizedAccessException]"refusing to kill protected process $($bad[0].ProcessName)" }
    $p | Stop-Process -Force
    "killed $(@($p).Count) process(es): " + (($p | ForEach-Object { "$($_.ProcessName)($($_.Id))" }) -join ', ')
  }
  quarantine_file = {
    param($t)
    $full = [System.IO.Path]::GetFullPath($t)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf) -or $full -match '^(?i)C:\\Windows\\|^(?i)C:\\Program Files') {
      throw [System.UnauthorizedAccessException]"refusing to quarantine '$t' (not a file, or a system path)" }
    Move-ToQuarantine $full
  }
  remove_persistence = {
    param($t)
    $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if (-not $task) { throw [System.UnauthorizedAccessException]"no scheduled task named '$t'" }
    if ($task.TaskPath -like '\Microsoft\*') { throw [System.UnauthorizedAccessException]"refusing to remove built-in task $($task.TaskPath)$t" }
    New-Item -ItemType Directory -Force -Path $Quar | Out-Null
    $xml = Join-Path $Quar ((Get-Date -Format 'yyyyMMddTHHmmss_') + "task_$t.xml")
    Export-ScheduledTask -TaskName $t -TaskPath $task.TaskPath | Set-Content -Path $xml -Encoding Unicode
    Unregister-ScheduledTask -TaskName $t -TaskPath $task.TaskPath -Confirm:$false
    "removed scheduled task $($task.TaskPath)$t (definition saved to $xml)"
  }
  disable_account = {
    param($t)
    if ($t -notmatch '^[\w.-]{1,20}$' -or $ProtectedUsers -contains $t.ToLower()) {
      throw [System.UnauthorizedAccessException]"refusing to disable account '$t'" }
    Disable-LocalUser -Name $t
    "disabled local account $t"
  }
  block_ip = {
    param($t)
    $ip = [System.Net.IPAddress]::Parse($t).ToString()
    if ($LabInfra -contains $ip) { throw [System.UnauthorizedAccessException]"refusing to block lab infrastructure $ip" }
    New-NetFirewallRule -DisplayName "tsoc block $ip (in)"  -Group 'tsoc' -Direction Inbound  -RemoteAddress $ip -Action Block | Out-Null
    New-NetFirewallRule -DisplayName "tsoc block $ip (out)" -Group 'tsoc' -Direction Outbound -RemoteAddress $ip -Action Block | Out-Null
    "blocked $ip in and out (firewall group 'tsoc')"
  }
  isolate_host = {
    param($t)
    $min = if ($t) { [int]$t } else { 30 }
    if ($min -lt 1 -or $min -gt 240) { throw 'isolation minutes must be 1-240' }
    $allow = @('10.10.10.10', '10.10.10.254')
    # Remember the current default policy so release restores it exactly
    $prof = Get-NetFirewallProfile -Profile Domain,Private,Public | Select-Object Name, DefaultInboundAction, DefaultOutboundAction
    New-Item -ItemType Directory -Force -Path $Quar | Out-Null
    $prof | ConvertTo-Json | Set-Content (Join-Path $Quar 'isolation-profile.json')
    New-NetFirewallRule -DisplayName 'tsoc isolate allow (in)'  -Group 'tsoc-isolate' -Direction Inbound  -RemoteAddress $allow -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName 'tsoc isolate allow (out)' -Group 'tsoc-isolate' -Direction Outbound -RemoteAddress $allow -Action Allow | Out-Null
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block -Enabled True
    # Allow rules that already exist would still let traffic out; disable them for the isolation window
    Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True | Where-Object { $_.Group -ne 'tsoc-isolate' } |
      Select-Object -ExpandProperty Name | Set-Content (Join-Path $Quar 'isolation-disabled-rules.txt')
    Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True | Where-Object { $_.Group -ne 'tsoc-isolate' } | Disable-NetFirewallRule
    $release = Join-Path $PSScriptRoot 'tsoc-release.ps1'
    $at = (Get-Date).AddMinutes($min)
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$release`""
    Register-ScheduledTask -TaskName 'tsoc-auto-release' -TaskPath '\tsoc\' -Action $act -Trigger (New-ScheduledTaskTrigger -Once -At $at) -User 'SYSTEM' -Force | Out-Null
    "isolated: only the SIEM (10.10.10.10) and admin workstation (10.10.10.254) can talk to this host; auto-release at $($at.ToString('HH:mm')) ($min min)"
  }
  release_host = {
    param($t)
    & (Join-Path $PSScriptRoot 'tsoc-release.ps1')
    Get-NetFirewallRule -Group 'tsoc' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    'released: isolation and IP blocks removed, firewall defaults restored'
  }
}

$msg = [Console]::In.ReadLine() | ConvertFrom-Json
if ($msg.command -ne 'add') { exit 0 }
$a = @($msg.parameters.extra_args) + @('', '', '')
$id, $action, $target = $a[0], $a[1], $a[2]
[Console]::Out.WriteLine((@{ version = 1; origin = @{ name = 'tsoc-ar'; module = 'active-response' }; command = 'check_keys'
                             parameters = @{ keys = @($id) } } | ConvertTo-Json -Compress -Depth 4))
[Console]::Out.Flush()
$reply = [Console]::In.ReadLine() | ConvertFrom-Json
if ($reply.command -ne 'continue') { Write-Result $id $action $target 'aborted' 'execd abort'; exit 0 }
try {
  if ($id -notmatch '^act-[a-f0-9]{12}$' -or -not $actions.ContainsKey($action)) {
    throw [System.UnauthorizedAccessException]"unknown action '$action' or bad action id" }
  $detail = & $actions[$action] $target
  Write-Result $id $action $target 'done' ([string]$detail)
} catch [System.UnauthorizedAccessException] {
  Write-Result $id $action $target 'refused' $_.Exception.Message
} catch {
  Write-Result $id $action $target 'failed' ("$($_.Exception.GetType().Name): $($_.Exception.Message)")
}
