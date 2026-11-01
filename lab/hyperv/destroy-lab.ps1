#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Tear down the tiny-agenticsoc lab: VMs and their disks. Use -All to also remove
  the LabNet switch, host IP and firewall rule. Base image and seeds are kept.
#>
param([switch]$All, [switch]$Force)
$ErrorActionPreference = "Stop"
$C = @{}
Get-Content (Join-Path $PSScriptRoot "config.env") | Where-Object { $_ -match '^\s*(LAB_[A-Z0-9_]+)=(.*)$' } | ForEach-Object { $C[$Matches[1]] = $Matches[2].Trim() }

$names = "sensor-gw", "wazuh", "lin-victim", "win-victim"
$vms = Get-VM -Name $names -ErrorAction SilentlyContinue
Write-Host "Will delete VMs + disks: $($vms.Name -join ', ')" -ForegroundColor Yellow
if ($All) { Write-Host "Also removing switch $($C.LAB_SWITCH), host IP $($C.LAB_HOST_IP), firewall rule" -ForegroundColor Yellow }
if (-not $Force -and (Read-Host "Type 'destroy' to continue") -ne 'destroy') { Write-Host "Aborted."; exit 1 }

foreach ($vm in $vms) {
  if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
  Get-VMSnapshot -VM $vm | Remove-VMSnapshot
  Remove-VM -VM $vm -Force
  $dir = Join-Path $C.LAB_WIN_DIR "vms\$($vm.Name)"
  if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
}

if ($All) {
  Get-NetFirewallRule -DisplayName "tiny-soc: block unsolicited inbound from lab" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Get-NetIPAddress -IPAddress $C.LAB_HOST_IP -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
  Get-VMSwitch -Name $C.LAB_SWITCH -ErrorAction SilentlyContinue | Remove-VMSwitch -Force
}
Write-Host "Lab destroyed."
