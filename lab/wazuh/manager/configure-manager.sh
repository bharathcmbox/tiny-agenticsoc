#!/usr/bin/env bash
# Phase 1: post-install config for the Wazuh all-in-one node. Run on the wazuh VM as root. Idempotent.
#   - archives on (index ALL events, not only alerts) so agents can query raw Zeek/Sysmon/audit data
#   - agent groups sensor/linux/windows with centralized agent.conf
#   - local rules
set -euo pipefail
SRC="${1:-/tmp/tiny-soc-wazuh}"
OSSEC=/var/ossec/etc/ossec.conf

# archives: manager writes archives.json, filebeat ships it to wazuh-archives-* indices
sed -i 's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' "$OSSEC"
python3 - <<'PY'
import re
p='/etc/filebeat/filebeat.yml'; s=open(p).read()
s=re.sub(r'(archives:\s*\n\s*enabled:\s*)false', r'\1true', s)
open(p,'w').write(s)
PY

# groups
for g in sensor linux windows; do
  /var/ossec/bin/agent_groups -l | grep -qx "  $g" || /var/ossec/bin/agent_groups -a -g "$g" -q || true
  if [[ -f "$SRC/groups/$g/agent.conf" ]]; then
    install -o wazuh -g wazuh -m 660 "$SRC/groups/$g/agent.conf" "/var/ossec/etc/shared/$g/agent.conf"
  fi
done

install -o wazuh -g wazuh -m 660 "$SRC/manager/local_rules.xml" /var/ossec/etc/rules/local_rules.xml
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager filebeat
echo "manager configured"
