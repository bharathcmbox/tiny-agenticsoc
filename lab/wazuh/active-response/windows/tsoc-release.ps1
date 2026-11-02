# Undo tsoc isolation: restore firewall default actions, re-enable the rules isolation disabled,
# remove the isolation rules and the auto-release task. Safe to run when not isolated.
$ErrorActionPreference = 'SilentlyContinue'
$Quar = 'C:\ProgramData\tsoc-quarantine'
$prof = Join-Path $Quar 'isolation-profile.json'
if (Test-Path $prof) {
  foreach ($p in (Get-Content $prof -Raw | ConvertFrom-Json)) {
    $in  = @('NotConfigured', 'Allow', 'Block')[[int]$p.DefaultInboundAction]
    $out = @('NotConfigured', 'Allow', 'Block')[[int]$p.DefaultOutboundAction]
    Set-NetFirewallProfile -Name $p.Name -DefaultInboundAction $in -DefaultOutboundAction $out
  }
  Remove-Item $prof
} else {
  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
}
$list = Join-Path $Quar 'isolation-disabled-rules.txt'
if (Test-Path $list) { Get-Content $list | ForEach-Object { Enable-NetFirewallRule -Name $_ }; Remove-Item $list }
Get-NetFirewallRule -Group 'tsoc-isolate' | Remove-NetFirewallRule
Unregister-ScheduledTask -TaskName 'tsoc-auto-release' -TaskPath '\tsoc\' -Confirm:$false
