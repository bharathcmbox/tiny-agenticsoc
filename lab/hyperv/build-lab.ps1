#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Phase 0, step 2 (run on Windows, elevated): build the tiny-agenticsoc Hyper-V lab.

.DESCRIPTION
  Creates the internal "LabNet" switch, gives the host 10.10.10.254 on it, blocks
  unsolicited inbound traffic from the lab to the host, then builds:
    sensor-gw   NAT gateway + DNS/DHCP + Zeek/Suricata (mirror destination NIC)
    wazuh       Wazuh all-in-one (installed in Phase 1)
    lin-victim  Linux ART target            (mirror source)
    win-victim  Windows ART target from ISO (mirror source, installed manually)
  Idempotent: existing VMs are left alone.

  Run lab/images/build-images.sh in WSL first; it copies this script, config.env,
  the base VHDX and the seed ISOs into $LAB_WIN_DIR.

.EXAMPLE
  .\build-lab.ps1 -WindowsIso C:\ISO\SERVER_EVAL_x64FRE_en-us.iso
.EXAMPLE
  .\build-lab.ps1 -SkipWindows
#>
param(
  [string]$WindowsIso = "",
  [switch]$SkipWindows,
  [int]$GatewayTimeoutMin = 15
)
$ErrorActionPreference = "Stop"

# --- config ----------------------------------------------------------------
$cfgPath = Join-Path $PSScriptRoot "config.env"
if (-not (Test-Path $cfgPath)) { throw "config.env not found next to this script. Run build-images.sh in WSL first." }
$C = @{}
Get-Content $cfgPath | Where-Object { $_ -match '^\s*(LAB_[A-Z0-9_]+)=(.*)$' } | ForEach-Object { $C[$Matches[1]] = $Matches[2].Trim() }
$LabDir = $C.LAB_WIN_DIR
function Mac([string]$m) { ($m -replace '[:-]', '').ToUpper() }
function Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
  throw "Hyper-V PowerShell module missing. Enable it: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All (then reboot)."
}
if (-not (Get-VMSwitch -Name $C.LAB_WAN_SWITCH -ErrorAction SilentlyContinue)) {
  throw "Hyper-V switch '$($C.LAB_WAN_SWITCH)' not found (it provides internet to sensor-gw)."
}

# --- network ---------------------------------------------------------------
Step "Internal switch $($C.LAB_SWITCH)"
if (-not (Get-VMSwitch -Name $C.LAB_SWITCH -ErrorAction SilentlyContinue)) {
  New-VMSwitch -Name $C.LAB_SWITCH -SwitchType Internal | Out-Null
}
$ifAlias = "vEthernet ($($C.LAB_SWITCH))"
if (-not (Get-NetIPAddress -InterfaceAlias $ifAlias -IPAddress $C.LAB_HOST_IP -ErrorAction SilentlyContinue)) {
  New-NetIPAddress -InterfaceAlias $ifAlias -IPAddress $C.LAB_HOST_IP -PrefixLength ([int]$C.LAB_PREFIX) | Out-Null
}
# Host-initiated connections (dashboard, SSH, API) still work: the firewall is stateful.
$fwName = "tiny-soc: block unsolicited inbound from lab"
if (-not (Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $fwName -Direction Inbound -Action Block `
    -RemoteAddress $C.LAB_SUBNET -Profile Any | Out-Null
}

# --- helpers ---------------------------------------------------------------
function New-LabDisk([string]$Name, [int]$SizeGB, [string]$FromBase) {
  $dir = Join-Path $LabDir "vms\$Name"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $vhd = Join-Path $dir "$Name.vhdx"
  if ($FromBase) {
    Copy-Item $FromBase $vhd
    # Files written from WSL can carry the sparse flag, which Hyper-V refuses to mount.
    fsutil sparse setflag $vhd 0 | Out-Null
    Resize-VHD -Path $vhd -SizeBytes ([int64]$SizeGB * 1GB)
  } else {
    New-VHD -Path $vhd -SizeBytes ([int64]$SizeGB * 1GB) -Dynamic | Out-Null
  }
  return $vhd
}

function New-LabVM {
  param([string]$Name, [int]$Cpu, [int]$MemMB, [int]$MaxMemMB = 0, [string]$Vhd, [object[]]$Nics, [switch]$Linux)
  New-VM -Name $Name -Generation 2 -MemoryStartupBytes ([int64]$MemMB * 1MB) -VHDPath $Vhd `
         -Path (Join-Path $LabDir "vms") | Out-Null
  Get-VMNetworkAdapter -VMName $Name | Remove-VMNetworkAdapter
  foreach ($n in $Nics) {
    Add-VMNetworkAdapter -VMName $Name -Name $n.Name -SwitchName $n.Switch -StaticMacAddress (Mac $n.Mac)
    if ($n.Mirror) { Set-VMNetworkAdapter -VMName $Name -Name $n.Name -PortMirroring $n.Mirror }
  }
  Set-VMProcessor -VMName $Name -Count $Cpu
  if ($MaxMemMB -gt $MemMB) {
    # Dynamic: reserve only startup RAM, balloon up to max under load
    Set-VMMemory -VMName $Name -DynamicMemoryEnabled $true -MinimumBytes ([int64]$MemMB * 1MB) `
                 -StartupBytes ([int64]$MemMB * 1MB) -MaximumBytes ([int64]$MaxMemMB * 1MB)
  } else {
    Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false
  }
  Set-VM -Name $Name -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
  if ($Linux) {
    Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
  }
}

function New-LabLinuxVM {
  param([string]$Name, [int]$Cpu, [int]$MemMB, [int]$MaxMemMB = 0, [int]$DiskGB, [object[]]$Nics)
  if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { Write-Host "    $Name exists - skipping"; return $false }
  $seed = Join-Path $LabDir "seeds\$Name-seed.iso"
  if (-not (Test-Path $seed)) { throw "missing $seed - run build-images.sh in WSL" }
  $vhd = New-LabDisk $Name $DiskGB (Join-Path $LabDir "base\ubuntu-base.vhdx")
  New-LabVM -Name $Name -Cpu $Cpu -MemMB $MemMB -MaxMemMB $MaxMemMB -Vhd $vhd -Nics $Nics -Linux
  Add-VMDvdDrive -VMName $Name -Path $seed
  Set-VMFirmware -VMName $Name -FirstBootDevice (Get-VMHardDiskDrive -VMName $Name)
  return $true
}

$lab = $C.LAB_SWITCH; $wan = $C.LAB_WAN_SWITCH

# --- sensor-gw first: everything else needs its NAT + DNS -------------------
Step "sensor-gw"
New-LabLinuxVM -Name sensor-gw -Cpu $C.LAB_GW_CPU -MemMB $C.LAB_GW_MEM_MB -DiskGB $C.LAB_GW_DISK_GB -Nics @(
  @{ Name = "wan"; Switch = $wan; Mac = $C.LAB_GW_WAN_MAC },
  @{ Name = "lan"; Switch = $lab; Mac = $C.LAB_GW_LAN_MAC },
  @{ Name = "mon"; Switch = $lab; Mac = $C.LAB_GW_MON_MAC; Mirror = "Destination" }
) | Out-Null
if ((Get-VM sensor-gw).State -ne 'Running') { Start-VM sensor-gw }

Step "Waiting for lab DNS on $($C.LAB_GW_IP) (cloud-init installs packages first; up to $GatewayTimeoutMin min)"
$deadline = (Get-Date).AddMinutes($GatewayTimeoutMin)
while ($true) {
  try { Resolve-DnsName -Name "example.com" -Server $C.LAB_GW_IP -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; break }
  catch {
    if ((Get-Date) -gt $deadline) { throw "sensor-gw DNS not answering. Check the VM console (vmconnect localhost sensor-gw) and /var/log/cloud-init-output.log" }
    Start-Sleep -Seconds 10
  }
}
Write-Host "    gateway is up (Zeek/Suricata keep installing in the background: /var/log/tiny-soc-setup.log)"

# --- wazuh + lin-victim -----------------------------------------------------
Step "wazuh"
New-LabLinuxVM -Name wazuh -Cpu $C.LAB_WAZUH_CPU -MemMB $C.LAB_WAZUH_MEM_MB -DiskGB $C.LAB_WAZUH_DISK_GB -Nics @(
  @{ Name = "lan"; Switch = $lab; Mac = $C.LAB_WAZUH_MAC }
) | Out-Null
if ((Get-VM wazuh).State -ne 'Running') { Start-VM wazuh }

Step "lin-victim"
New-LabLinuxVM -Name lin-victim -Cpu $C.LAB_LIN_CPU -MemMB $C.LAB_LIN_MEM_MB -MaxMemMB ([int]$C.LAB_LIN_MEM_MAX_MB) -DiskGB $C.LAB_LIN_DISK_GB -Nics @(
  @{ Name = "lan"; Switch = $lab; Mac = $C.LAB_LIN_MAC; Mirror = "Source" }
) | Out-Null
if ((Get-VM lin-victim).State -ne 'Running') { Start-VM lin-victim }

# --- win-victim -------------------------------------------------------------
if (-not $SkipWindows) {
  Step "win-victim"
  if (Get-VM -Name win-victim -ErrorAction SilentlyContinue) {
    Write-Host "    win-victim exists - skipping"
  } elseif (-not $WindowsIso -or -not (Test-Path $WindowsIso)) {
    Write-Warning "No -WindowsIso given (or not found). Re-run later with -WindowsIso <path> to create win-victim."
  } else {
    $vhd = New-LabDisk win-victim $C.LAB_WIN_DISK_GB $null
    New-LabVM -Name win-victim -Cpu $C.LAB_WIN_CPU -MemMB $C.LAB_WIN_MEM_MB -MaxMemMB ([int]$C.LAB_WIN_MEM_MAX_MB) -Vhd $vhd -Nics @(
      @{ Name = "lan"; Switch = $lab; Mac = $C.LAB_WIN_MAC; Mirror = "Source" }
    )
    Set-VMKeyProtector -VMName win-victim -NewLocalKeyProtector
    Enable-VMTPM -VMName win-victim
    Add-VMDvdDrive -VMName win-victim -Path $WindowsIso
    Set-VMFirmware -VMName win-victim -FirstBootDevice (Get-VMDvdDrive -VMName win-victim)
    Write-Host "    created. Install Windows interactively: vmconnect localhost win-victim (press a key at 'Press any key to boot from CD')"
  }
}

Step "Done"
Get-VM sensor-gw, wazuh, lin-victim, win-victim -ErrorAction SilentlyContinue |
  Format-Table Name, State, CPUUsage, @{n='MemGB';e={[math]::Round($_.MemoryAssigned/1GB,1)}}, Uptime -AutoSize
Write-Host @"
Next (from WSL):
  ssh -i ~/.ssh/tiny-soc_ed25519 soc@$($C.LAB_GW_IP) 'cloud-init status --wait; tail -n3 /var/log/tiny-soc-setup.log'
  See docs/phase0-infra.md for the verification checklist, then checkpoint the VMs:
  Get-VM sensor-gw,wazuh,lin-victim | Checkpoint-VM -SnapshotName phase0-clean
"@
