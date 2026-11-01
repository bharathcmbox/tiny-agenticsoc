#!/usr/bin/env bash
# Install + enroll a Wazuh agent on a lab Ubuntu VM. Run as root: install-linux-agent.sh <group> [manager_ip]
set -euo pipefail
GROUP="${1:?group (sensor|linux)}"; MANAGER="${2:-10.10.10.10}"; VERSION="${WAZUH_VERSION:-4.14.9}"  # must be <= manager version
export DEBIAN_FRONTEND=noninteractive
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq
WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_GROUP="$GROUP" WAZUH_AGENT_NAME="$(hostname)" apt-get install -y -qq "wazuh-agent=$VERSION-1"
# pin: don't let unattended upgrades move the agent ahead of the manager
apt-mark hold wazuh-agent >/dev/null
systemctl daemon-reload && systemctl enable --now wazuh-agent
echo "agent installed on $(hostname), group=$GROUP"
