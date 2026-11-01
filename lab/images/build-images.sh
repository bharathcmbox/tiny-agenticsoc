#!/usr/bin/env bash
# Phase 0, step 1 (run in WSL): build everything Hyper-V needs.
#   - downloads + verifies the Ubuntu cloud image, converts it to a base VHDX
#   - renders cloud-init templates and packs one NoCloud seed ISO per Linux VM
#   - copies the PowerShell scripts + config to the Windows lab dir
# Re-runnable: the image is cached; seeds are regenerated every run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CFG="$ROOT/lab/config.env"
# shellcheck disable=SC1090
set -a; source <(grep -E '^LAB_[A-Z0-9_]+=' "$CFG" | sed -E 's/=(.*)$/="\1"/'); set +a

CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/tiny-soc"
SECRETS="$ROOT/lab/.secrets"
OUT="$LAB_WIN_DIR_WSL"
SSH_KEY="${LAB_SSH_KEY:-$HOME/.ssh/tiny-soc_ed25519}"
LINUX_VMS=(sensor-gw wazuh lin-victim)

log() { printf '\033[1;34m[build-images]\033[0m %s\n' "$*"; }

# --- prerequisites ---------------------------------------------------------
missing=()
command -v qemu-img    >/dev/null || missing+=(qemu-utils)
command -v genisoimage >/dev/null || missing+=(genisoimage)
command -v envsubst    >/dev/null || missing+=(gettext-base)
if ((${#missing[@]})); then
  log "installing: ${missing[*]}"
  sudo apt-get update -qq && sudo apt-get install -y -qq "${missing[@]}"
fi

mkdir -p "$CACHE" "$SECRETS" "$OUT/base" "$OUT/seeds"

# --- SSH key + console password -------------------------------------------
if [[ ! -f "$SSH_KEY" ]]; then
  log "creating lab SSH key $SSH_KEY"
  ssh-keygen -t ed25519 -N '' -C "tiny-soc-lab" -f "$SSH_KEY" >/dev/null
fi
if [[ ! -f "$SECRETS/console-password" ]]; then
  log "generating console password -> lab/.secrets/console-password"
  (umask 077; openssl rand -base64 18 | tr -d '/+=' > "$SECRETS/console-password")
fi
LAB_SSH_PUBKEY="$(cat "$SSH_KEY.pub")"
LAB_PASSWD_HASH="$(openssl passwd -6 -stdin < "$SECRETS/console-password")"
export LAB_SSH_PUBKEY LAB_PASSWD_HASH

# --- Ubuntu cloud image -> base VHDX --------------------------------------
IMG="$CACHE/$(basename "$LAB_UBUNTU_IMG_URL")"
want="$(curl -fsSL "$LAB_UBUNTU_SUMS_URL" | awk -v f="*$(basename "$IMG")" '$2==f {print $1}')"
[[ -n "$want" ]] || { echo "could not find checksum for $(basename "$IMG")" >&2; exit 1; }
if [[ ! -f "$IMG" ]] || [[ "$(sha256sum "$IMG" | cut -d' ' -f1)" != "$want" ]]; then
  log "downloading $(basename "$IMG")"
  curl -fL --progress-bar -o "$IMG.part" "$LAB_UBUNTU_IMG_URL"
  [[ "$(sha256sum "$IMG.part" | cut -d' ' -f1)" == "$want" ]] || { echo "checksum mismatch" >&2; exit 1; }
  mv "$IMG.part" "$IMG"
fi
log "image verified (sha256 $want)"

BASE_VHDX="$CACHE/ubuntu-$LAB_UBUNTU_RELEASE-base.vhdx"
if [[ ! -f "$BASE_VHDX" || "$IMG" -nt "$BASE_VHDX" ]]; then
  log "converting to VHDX"
  qemu-img convert -p -O vhdx -o subformat=dynamic "$IMG" "$BASE_VHDX.part"
  mv "$BASE_VHDX.part" "$BASE_VHDX"
fi
if ! cmp -s "$BASE_VHDX" "$OUT/base/ubuntu-base.vhdx" 2>/dev/null; then
  log "copying base VHDX to $LAB_WIN_DIR\\base"
  cp "$BASE_VHDX" "$OUT/base/ubuntu-base.vhdx"
fi

# --- cloud-init seed ISOs --------------------------------------------------
# Only substitute LAB_* variables; leave every other $ in the templates alone.
VARS="$(compgen -v | grep '^LAB_' | sed 's/^/$/' | tr '\n' ' ')"
for vm in "${LINUX_VMS[@]}"; do
  src="$ROOT/lab/cloud-init/$vm"
  dst="$CACHE/seed/$vm"
  rm -rf "$dst"; mkdir -p "$dst"
  envsubst "$VARS" < "$src/user-data"      > "$dst/user-data"
  envsubst "$VARS" < "$src/network-config" > "$dst/network-config"
  printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$vm" "$(date +%s)" "$vm" > "$dst/meta-data"
  if grep -q '\${LAB_' "$dst"/*; then
    echo "unrendered variable in $vm seed:" >&2; grep -n '\${LAB_' "$dst"/* >&2; exit 1
  fi
  genisoimage -quiet -output "$OUT/seeds/$vm-seed.iso" -volid cidata -joliet -rock \
    "$dst/user-data" "$dst/meta-data" "$dst/network-config"
  log "seed ISO: $LAB_WIN_DIR\\seeds\\$vm-seed.iso"
done

# --- hand-off to Windows ---------------------------------------------------
cp "$ROOT/lab/hyperv/build-lab.ps1" "$ROOT/lab/hyperv/destroy-lab.ps1" "$CFG" "$OUT/"

cat <<EOF

Done. Next, in an *elevated* PowerShell on Windows:

  cd $LAB_WIN_DIR
  powershell -ExecutionPolicy Bypass -File .\\build-lab.ps1 -WindowsIso C:\\path\\to\\windows-eval.iso

SSH (from WSL, once VMs are up):  ssh -i $SSH_KEY soc@$LAB_GW_IP
Console login (Hyper-V window):   soc / \$(cat lab/.secrets/console-password)
EOF
