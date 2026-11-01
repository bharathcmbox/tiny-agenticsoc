# Phase 0: Lab infrastructure

Goal: four VMs on an isolated Hyper-V network. All lab traffic routes through `sensor-gw`,
which runs Zeek and Suricata on a port-mirror NIC.

## Prerequisites

1. **Hyper-V enabled** (Windows 11 Pro). If `Get-Command New-VM` fails in PowerShell, run this
   elevated, then reboot:
   `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All`
2. **Cap WSL memory and switch to mirrored networking** so the VMs have room and WSL can reach
   `10.10.10.0/24`:
   ```powershell
   copy \\wsl.localhost\Ubuntu\home\<you>\githubcode\tiny-agenticsoc\lab\wslconfig.example $env:USERPROFILE\.wslconfig
   wsl --shutdown
   ```
   (Mirrored mode changes how WSL networking behaves for your other projects too. It is usually
   fine, but it's worth knowing.)
3. **Windows evaluation ISO** for `win-victim`, from the Microsoft Evaluation Center. Either:
   * Windows 11 Enterprise eval (90 days): most realistic as a workstation target
   * Windows Server 2022/2025 eval (180 days): lasts longer between rebuilds

## Build

```bash
# 1. WSL: download + verify the Ubuntu image, convert to VHDX, render cloud-init seed ISOs
./lab/images/build-images.sh
```
This creates `~/.ssh/tiny-soc_ed25519` (lab SSH key) and `lab/.secrets/console-password`
(git-ignored), and stages everything in `C:\HyperV\tiny-soc`.

```powershell
# 2. Windows, elevated PowerShell
cd C:\HyperV\tiny-soc
powershell -ExecutionPolicy Bypass -File .\build-lab.ps1 -WindowsIso C:\ISO\<eval>.iso
```
The script starts `sensor-gw` first and waits for its DNS to answer, then starts the rest.
Install Windows in `win-victim` by hand (`vmconnect localhost win-victim`). It gets
`10.10.10.20` from the gateway's DHCP.

## Verify

From WSL:

```bash
K=~/.ssh/tiny-soc_ed25519
# cloud-init finished cleanly everywhere
for ip in 10.10.10.1 10.10.10.10 10.10.10.21; do ssh -i $K soc@$ip 'hostname; cloud-init status'; done

# gateway: NAT, DNS, sensors
ssh -i $K soc@10.10.10.1 'sudo nft list ruleset | head -20; systemctl is-active dnsmasq zeek suricata; tail -2 /var/log/tiny-soc-setup.log'

# victim reaches the internet through the gateway, but NOT the host/home LAN
ssh -i $K soc@10.10.10.21 'curl -sI https://example.com | head -1; ping -c1 -W2 192.168.1.1 || echo "blocked (good)"'

# sensors see victim traffic (generate some, then look)
# (testmynids.org has lapsed; send the 'uid=0(root)' string ourselves - rule 2100498 matches it in any direction)
ssh -i $K soc@10.10.10.21 'curl -s -o /dev/null -d "uid=0(root) gid=0(root)" http://example.com/'
ssh -i $K soc@10.10.10.1  'sudo tail -n 3 /var/log/suricata/fast.log
  sudo grep "\"event_type\":\"alert\"" /var/log/suricata/eve.json | tail -1 | jq -c "{sig:.alert.signature, community_id}"
  sudo tail -n 1 /opt/zeek/logs/current/conn.log | jq -c "{orig:.\"id.orig_h\", resp:.\"id.resp_h\", community_id}"'
# the Suricata alert and the Zeek conn record should share the same community_id
```

Checklist:

- [ ] `cloud-init status` → `done` on all three Linux VMs
- [ ] `dnsmasq`, `zeek` and `suricata` are active on sensor-gw
- [ ] lin-victim can reach the internet, and private ranges are blocked
- [ ] Suricata `fast.log` shows `GPL ATTACK_RESPONSE id check returned root`
- [ ] Zeek `dns.log` / `conn.log` contain lin-victim traffic, as JSON with `community_id`
- [ ] win-victim installed, has `10.10.10.20`, and can browse the internet
- [ ] Checkpoint: `Get-VM sensor-gw,wazuh,lin-victim,win-victim | Checkpoint-VM -SnapshotName phase0-clean`

## Troubleshooting

| Symptom | Fix |
|---|---|
| Hyper-V: "virtual disk ... sparse" error | `fsutil sparse setflag <vhdx> 0` (the script already does this for copied disks) |
| Ubuntu VM doesn't boot / Secure Boot violation | Check `Get-VMFirmware <vm>` shows template `MicrosoftUEFICertificateAuthority` |
| Gateway wait times out | `vmconnect localhost sensor-gw`, log in as `soc` with the console password, read `/var/log/cloud-init-output.log`. Usually the Default Switch has no internet (VPN on the host?) |
| Zeek/Suricata not running | `/var/log/tiny-soc-setup.log` on sensor-gw. Re-run `sudo /usr/local/sbin/setup-sensors.sh` |
| Sensors see no victim traffic | `Get-VMNetworkAdapter -VMName lin-victim,sensor-gw \| ft VMName,Name,PortMirroringMode` should show Source on victims and Destination on `mon` |
| `Unable to allocate N MB of RAM (0x800705AA)` | The host is short on free RAM. Check with `Get-VMMemory -VMName *`; victims should be dynamic. Apply new sizes with `Set-VMMemory` while the VM is **off**, then check the result. Closing Chrome tabs helps |
| "Press any key to boot from CD" ignores keys | Click inside the VM screen first. Or start the VM and send Enter through WMI: `$kb = Get-CimAssociatedInstance -InputObject (Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='win-victim'") -ResultClassName Msvm_Keyboard; 1..30 \| % { Invoke-CimMethod -InputObject $kb -MethodName TypeKey -Arguments @{keyCode=0x0D}; sleep -m 500 }` |
| Windows Setup defaults to Core | In the edition list, pick **Standard Evaluation (Desktop Experience)** |
| WSL can't reach 10.10.10.x | Confirm `.wslconfig` has `networkingMode=mirrored` and that you ran `wsl --shutdown` |

Rebuild from scratch: `.\destroy-lab.ps1` (VMs only) or `.\destroy-lab.ps1 -All` (also the switch, host IP and firewall rule).
