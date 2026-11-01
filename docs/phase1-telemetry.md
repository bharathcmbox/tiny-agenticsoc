# Phase 1: Telemetry into Wazuh

Goal: every telemetry source lands in Wazuh. Detections go to `wazuh-alerts-*`, and the raw
events (Zeek, Suricata metadata, Sysmon, auditd) go to `wazuh-archives-*` so the agents can
query them later.

| Source | Host | Wazuh group | How |
|---|---|---|---|
| Suricata `eve.json` | sensor-gw | `sensor` | JSON localfile, built-in Suricata rules (86600+) |
| Zeek conn/dns/http/ssl/files/notice/weird | sensor-gw | `sensor` | JSON localfile, label `zeek.log`, local rules 1001xx |
| dnsmasq queries | sensor-gw | `sensor` | journald |
| auditd (Neo23x0 ruleset) + FIM | lin-victim | `linux` | audit localfile |
| Sysmon + PowerShell + Security | win-victim | `windows` | eventchannel |

All agent config is centralized: `lab/wazuh/groups/<group>/agent.conf` is pushed by the manager.
Local rules live in `lab/wazuh/manager/local_rules.xml`.

## 1. Install Wazuh (all-in-one) on `wazuh`

```bash
K=~/.ssh/tiny-soc_ed25519
ssh -i $K soc@10.10.10.10 'curl -fsSO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash wazuh-install.sh -a'
```

Store the generated credentials locally (git-ignored):

```bash
ssh -i $K soc@10.10.10.10 'sudo tar -xOf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt' > lab/.secrets/wazuh-passwords.txt
chmod 600 lab/.secrets/wazuh-passwords.txt
```

## 2. Configure the manager (archives, groups, rules)

```bash
scp -i $K -r lab/wazuh soc@10.10.10.10:/tmp/tiny-soc-wazuh
ssh -i $K soc@10.10.10.10 'sudo bash /tmp/tiny-soc-wazuh/manager/configure-manager.sh /tmp/tiny-soc-wazuh'
```

## 3. Linux agents

```bash
# auditd rules on the victim (Neo23x0/auditd)
ssh -i $K soc@10.10.10.21 'curl -fsSL https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -o /tmp/a.rules && sudo install -m 640 /tmp/a.rules /etc/audit/rules.d/audit.rules && sudo augenrules --load'

for h in "10.10.10.1 sensor" "10.10.10.21 linux"; do set -- $h
  scp -i $K lab/wazuh/install-linux-agent.sh soc@$1:/tmp/
  ssh -i $K soc@$1 "sudo bash /tmp/install-linux-agent.sh $2"
done
```

## 4. Windows agent + Sysmon

See `lab/wazuh/windows/` (step 3 of Phase 1).

## Notes and gotchas

- **The indexer listens on 127.0.0.1:9200 only** (installer default). Query it from the wazuh VM,
  or through an SSH tunnel: `ssh -i $K -L 9200:127.0.0.1:9200 soc@10.10.10.10`. Phase 3 decides
  whether the agents use a tunnel or a dedicated read-only user on a LAN bind.
- **Zeek field names.** Wazuh's index template maps `data.id` as a keyword, so Zeek's dotted
  `id.orig_h`-style fields were rejected by the indexer ("Cannot index event" in
  `/var/log/filebeat/filebeat`). sensor-gw's `local.zeek` renames them to Suricata's names
  (`src_ip`, `src_port`, `dest_ip`, `dest_port`), so both sensors share one schema and join on
  `community_id`.
- Credentials are extracted with
  `sudo tar -xOf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt`. They are kept
  only in `lab/.secrets/`.

## Verify

Dashboard: `https://10.10.10.10` (user `admin`, password in `lab/.secrets/wazuh-passwords.txt`).
The certificate is self-signed, so accept the browser warning.

- [x] `sudo /var/ossec/bin/agent_control -l` on wazuh lists sensor-gw and lin-victim as **Active**
- [x] Suricata test alert (see the phase0 doc) shows as rule 86601 in `wazuh-alerts-*`
- [x] Zeek events appear in `wazuh-archives-*`, and the Suricata alert joins its Zeek `conn` record on `data.community_id`
- [x] `sudo useradd testuser && sudo userdel testuser` on lin-victim produces user-management alerts, and auditd events land in archives
- [ ] Windows: Sysmon event ID 1 (process create) from win-victim in archives
