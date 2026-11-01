#Requires -RunAsAdministrator
<#
  tiny-agenticsoc Phase 1: endpoint telemetry for win-victim. Run INSIDE the VM as Administrator.
    1. Sysmon (Microsoft-signed binary) + sysmon-modular "balanced" config (pinned, sha256-checked)
    2. PowerShell script block logging (4104) and process-creation command lines (4688)
    3. Wazuh agent 4.14.9 (sha256-checked), enrolled to 10.10.10.10 in group "windows"
  Safe to re-run: Sysmon config is updated in place, the agent is reinstalled over itself.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with a progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Manager      = '10.10.10.10'
$Group        = 'windows'
$AgentName    = 'win-victim'
$WazuhVersion = '4.14.9'
$WazuhMsiSha  = 'E3F18109D36C98C2F861F210FC6661226D99251B79321C5D7FF27821B906EA49'
$SysmonCfgUrl = 'https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig.xml'
$SysmonCfgSha = '64BEC37BA849C5F2934A55D2A29E7DDFAE46A30D56F7F2908D1F8A454898797E'
$Dir          = 'C:\Tools'

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Get-Verified([string]$Url, [string]$Path, [string]$Sha256) {
  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Path
  if ($Sha256) {
    $h = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
    if ($h -ne $Sha256) { throw "Checksum mismatch for $Path (got $h)" }
  }
}
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

Step 'Sysmon'
Get-Verified 'https://download.sysinternals.com/files/Sysmon.zip' "$Dir\Sysmon.zip" $null
Expand-Archive -Path "$Dir\Sysmon.zip" -DestinationPath "$Dir\Sysmon" -Force
$exe = "$Dir\Sysmon\Sysmon64.exe"
$sig = Get-AuthenticodeSignature $exe
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
  throw "Sysmon64.exe signature check failed: $($sig.Status) $($sig.SignerCertificate.Subject)"
}
Get-Verified $SysmonCfgUrl "$Dir\Sysmon\sysmonconfig.xml" $SysmonCfgSha
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
  & $exe -c "$Dir\Sysmon\sysmonconfig.xml" | Out-Null
} else {
  & $exe -accepteula -i "$Dir\Sysmon\sysmonconfig.xml" | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon install/update failed (exit $LASTEXITCODE)" }

Step 'PowerShell script block logging + process command-line auditing'
$sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $sb -Force | Out-Null
Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Value 1 -Type DWord
$au = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $au -Force | Out-Null
Set-ItemProperty -Path $au -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null

Step "Wazuh agent $WazuhVersion"
$msi = "$Dir\wazuh-agent-$WazuhVersion-1.msi"
Get-Verified "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi" $msi $WazuhMsiSha
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
  '/i', "`"$msi`"", '/q',
  "WAZUH_MANAGER=$Manager", "WAZUH_AGENT_GROUP=$Group", "WAZUH_AGENT_NAME=$AgentName")
if ($p.ExitCode -ne 0) { throw "msiexec failed (exit $($p.ExitCode))" }
Restart-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ((Get-Service WazuhSvc).Status -ne 'Running') { Start-Service WazuhSvc }

Step 'Summary'
Get-Service Sysmon64, WazuhSvc | Format-Table Name, Status -AutoSize
$e = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1
Write-Host ("Latest Sysmon event: ID {0} at {1}" -f $e.Id, $e.TimeCreated)
Write-Host 'Done. Tell Claude to verify from the Wazuh side.' -ForegroundColor Green
