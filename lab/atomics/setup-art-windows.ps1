#Requires -RunAsAdministrator
<#
  tiny-agenticsoc Phase 2: run ONCE inside win-victim as Administrator.
    1. OpenSSH server, key-only, reachable only from the lab host (10.10.10.254), so Claude
       and the eval harness can drive atomics remotely
    2. Invoke-AtomicRedTeam + powershell-yaml at pinned PSGallery versions
    3. Atomics from a pinned atomic-red-team commit (sha256-checked)
  Defender stays ON: it may quarantine parts of the atomics archive. That is reported, not fatal.
#>
param(
  [string]$PubKey = '__LAB_SSH_PUBKEY__',
  [string]$AllowFrom = '10.10.10.254'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ArtCommit = 'd0cc590bc44b0057562de9089f7f8e01f9d67a3f'
$ArtSha256 = '7190909F0A7AC02D433094743E09A8D6A70AB2E92E4F2D4FC89626079CD1F963'
$IartVer   = '2.3.0'
$YamlVer   = '0.4.9'
$ArtDir    = 'C:\AtomicRedTeam'
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
if ($PubKey -notmatch '^ssh-(ed25519|rsa) ') { throw 'Pass the lab public key: -PubKey "ssh-ed25519 AAAA..."' }

Step 'OpenSSH server (key-only, lab host only)'
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
$cfg = 'C:\ProgramData\ssh\sshd_config'
Set-Service sshd -StartupType Automatic
Start-Service sshd   # first start generates host keys and sshd_config
# Disable passwords in the global section (the stock file has '#PasswordAuthentication yes' there)
$lines = Get-Content $cfg
if (-not ($lines -match '^PasswordAuthentication no')) {
  $lines -replace '^#?PasswordAuthentication .*', 'PasswordAuthentication no' | Set-Content $cfg -Encoding ascii
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -PropertyType String -Force `
  -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" | Out-Null
$ak = 'C:\ProgramData\ssh\administrators_authorized_keys'
Set-Content -Path $ak -Value $PubKey -Encoding ascii
icacls.exe $ak /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Set-NetFirewallRule -RemoteAddress $AllowFrom
Restart-Service sshd

Step "Invoke-AtomicRedTeam $IartVer (PSGallery, pinned)"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module powershell-yaml -RequiredVersion $YamlVer -Scope AllUsers -Force
Install-Module Invoke-AtomicRedTeam -RequiredVersion $IartVer -Scope AllUsers -Force

Step "Atomics at commit $($ArtCommit.Substring(0,7))"
New-Item -ItemType Directory -Force -Path $ArtDir | Out-Null
$tgz = Join-Path $ArtDir "art-$ArtCommit.tar.gz"
try {
  Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/redcanaryco/atomic-red-team/archive/$ArtCommit.tar.gz" -OutFile $tgz
} catch { throw "Download failed (Defender may have blocked the archive): $($_.Exception.Message)" }
if (-not (Test-Path $tgz)) { throw 'Archive vanished after download: Defender quarantined it. Check Protection history.' }
$h = (Get-FileHash -Algorithm SHA256 $tgz).Hash
if ($h -ne $ArtSha256) { throw "Checksum mismatch for atomics archive (got $h)" }
& tar.exe -xzf $tgz -C $ArtDir --strip-components=1 "atomic-red-team-$ArtCommit/atomics" 2>$null
$tarExit = $LASTEXITCODE
Set-Content -Path (Join-Path $ArtDir 'COMMIT') -Value $ArtCommit -Encoding ascii
Remove-Item $tgz -ErrorAction SilentlyContinue

$prof = $PROFILE.AllUsersAllHosts
New-Item -ItemType File -Force -Path $prof | Out-Null
Set-Content -Path $prof -Encoding ascii -Value @'
Import-Module Invoke-AtomicRedTeam -ErrorAction SilentlyContinue
$PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder'] = 'C:\AtomicRedTeam\atomics'
'@

Step 'Summary'
$n = (Get-ChildItem "$ArtDir\atomics" -Directory -Filter 'T*').Count
Write-Host "Atomics: $n techniques"
if ($tarExit -ne 0) { Write-Warning "tar reported errors: Defender likely quarantined some atomics files. That is expected with Defender on." }
Get-Service sshd | Format-Table Name, Status -AutoSize
Write-Host 'Done. Tell Claude to connect over SSH.' -ForegroundColor Green
