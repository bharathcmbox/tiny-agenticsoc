#!/usr/bin/env bash
# Phase 2: install Atomic Red Team on a lab Linux VM (run as root, INSIDE the lab only).
# Everything is pinned: PowerShell from Microsoft's signed apt repo, Invoke-AtomicRedTeam and
# powershell-yaml at exact PSGallery versions, atomics from a fixed git commit (sha256-checked).
# No download-and-execute: the module is installed by PowerShellGet, the atomics are YAML data.
set -euo pipefail
ART_COMMIT="${ART_COMMIT:-d0cc590bc44b0057562de9089f7f8e01f9d67a3f}"
ART_SHA256="${ART_SHA256:-7190909f0a7ac02d433094743e09a8d6a70ab2e92e4f2d4fc89626079cd1f963}"
IART_VERSION="${IART_VERSION:-2.3.0}"
YAML_VERSION="${YAML_VERSION:-0.4.9}"
DEST=/opt/AtomicRedTeam
export DEBIAN_FRONTEND=noninteractive

# PowerShell 7 (Microsoft signed apt repo)
if ! command -v pwsh >/dev/null; then
  . /etc/os-release
  curl -fsSLo /tmp/packages-microsoft-prod.deb "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb"
  dpkg -i /tmp/packages-microsoft-prod.deb >/dev/null
  apt-get update -qq && apt-get install -y -qq powershell >/dev/null
fi

# Module (pinned versions from PSGallery)
pwsh -NoProfile -NonInteractive -Command "
  \$ErrorActionPreference='Stop'
  Set-PSRepository PSGallery -InstallationPolicy Trusted
  Install-Module powershell-yaml -RequiredVersion $YAML_VERSION -Scope AllUsers -Force
  Install-Module Invoke-AtomicRedTeam -RequiredVersion $IART_VERSION -Scope AllUsers -Force
  Get-Module -ListAvailable Invoke-AtomicRedTeam | Select-Object -First 1 Name,Version | Format-Table -HideTableHeaders"

# Atomics (pinned commit, checksum-verified, atomics/ folder only)
mkdir -p "$DEST"
TGZ=/tmp/art-$ART_COMMIT.tar.gz
[[ -f $TGZ ]] || curl -fsSL -o "$TGZ" "https://github.com/redcanaryco/atomic-red-team/archive/$ART_COMMIT.tar.gz"
echo "$ART_SHA256  $TGZ" | sha256sum -c --quiet
rm -rf "$DEST/atomics"
tar -xzf "$TGZ" -C "$DEST" --strip-components=1 "atomic-red-team-$ART_COMMIT/atomics"
echo "$ART_COMMIT" > "$DEST/COMMIT"

# Import the module and point it at the atomics in every pwsh session
mkdir -p /opt/microsoft/powershell/7
cat > /opt/microsoft/powershell/7/profile.ps1 <<'PS'
Import-Module Invoke-AtomicRedTeam -ErrorAction SilentlyContinue
$PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder'] = '/opt/AtomicRedTeam/atomics'
PS
echo "ART ready: $(ls "$DEST/atomics" | grep -c '^T') techniques at commit ${ART_COMMIT:0:7}"
