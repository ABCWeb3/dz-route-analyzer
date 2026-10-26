#!/usr/bin/env bash
# Create a Debian 13 LXC on Proxmox VE and install DZ Route Analyzer.
set -Eeuo pipefail

APP_REPO="https://github.com/ABCWeb3/dz-route-analyzer.git"
DEFAULT_CTID="213"
DEFAULT_HOSTNAME="dz-route-analyzer"
DEFAULT_BRIDGE="vmbr0"
DEFAULT_STORAGE="local-lvm"
DEFAULT_TEMPLATE_STORAGE="local"
DEFAULT_CORES="2"
DEFAULT_MEMORY="1024"
DEFAULT_SWAP="512"
DEFAULT_DISK="8"
DEFAULT_DNS="1.1.1.1"

die() { echo "ERROR: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required Proxmox command not found: $1"; }
prompt() {
  local var_name="$1" label="$2" default="$3" value
  read -r -p "$label [$default]: " value
  printf -v "$var_name" '%s' "${value:-$default}"
}

[[ $EUID -eq 0 ]] || die "Run on the Proxmox VE host as root."
need_cmd pct
need_cmd pveam
need_cmd pvesm
need_cmd awk
need_cmd grep

echo
echo "DZ Route Analyzer - Proxmox LXC installer"
echo "This creates a NEW container. It does not modify or delete existing containers."
echo "Use an unused static IP address and ensure it is reserved/excluded from DHCP."
echo

prompt CTID "Container ID (CTID)" "$DEFAULT_CTID"
[[ "$CTID" =~ ^[0-9]+$ ]] || die "CTID must be numeric."
pct status "$CTID" >/dev/null 2>&1 && die "CTID $CTID already exists. Choose another ID."
prompt HOSTNAME "Container hostname" "$DEFAULT_HOSTNAME"
[[ "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$ ]] || die "Invalid hostname."
prompt IP_CIDR "Static IPv4 address with CIDR (example 192.168.1.113/24)" ""
[[ "$IP_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] || die "Enter an IPv4 address with CIDR, e.g. 192.168.1.113/24."
IP_ONLY="${IP_CIDR%%/*}"
awk -v ip="$IP_ONLY" 'BEGIN { n=split(ip,a,"."); for(i=1;i<=n;i++) if(a[i]>255 || a[i]<0) exit 1; if(n!=4) exit 1 }' || die "Invalid IPv4 address."
prompt GATEWAY "IPv4 gateway" "192.168.1.1"
[[ "$GATEWAY" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "Enter a valid-looking IPv4 gateway."
awk -v ip="$GATEWAY" 'BEGIN { n=split(ip,a,"."); for(i=1;i<=n;i++) if(a[i]>255 || a[i]<0) exit 1; if(n!=4) exit 1 }' || die "Invalid gateway address."
prompt BRIDGE "Proxmox network bridge" "$DEFAULT_BRIDGE"
prompt ROOTFS_STORAGE "Container rootfs storage" "$DEFAULT_STORAGE"
prompt TEMPLATE_STORAGE "Storage for Debian template" "$DEFAULT_TEMPLATE_STORAGE"
prompt CORES "CPU cores" "$DEFAULT_CORES"
prompt MEMORY "Memory in MiB" "$DEFAULT_MEMORY"
prompt SWAP "Swap in MiB" "$DEFAULT_SWAP"
prompt DISK "Root disk size in GiB" "$DEFAULT_DISK"
prompt DNS "DNS server" "$DEFAULT_DNS"

for v in "$CORES" "$MEMORY" "$SWAP" "$DISK"; do [[ "$v" =~ ^[0-9]+$ ]] || die "CPU, memory, swap and disk values must be numeric."; done
(( CORES > 0 && MEMORY >= 256 && DISK >= 4 )) || die "Use at least 1 core, 256 MiB RAM and 4 GiB disk."
pvesm status --storage "$ROOTFS_STORAGE" >/dev/null 2>&1 || die "Storage '$ROOTFS_STORAGE' is unavailable."
pvesm status --storage "$TEMPLATE_STORAGE" >/dev/null 2>&1 || die "Template storage '$TEMPLATE_STORAGE' is unavailable."
ip link show "$BRIDGE" >/dev/null 2>&1 || die "Network bridge '$BRIDGE' does not exist on this node."

echo
echo "Configuration summary:"
printf '  CTID: %s\n  Hostname: %s\n  Static IP: %s\n  Gateway: %s\n  Bridge: %s\n  Rootfs storage: %s\n  Template storage: %s\n' "$CTID" "$HOSTNAME" "$IP_CIDR" "$GATEWAY" "$BRIDGE" "$ROOTFS_STORAGE" "$TEMPLATE_STORAGE"
read -r -p "Create this container and install the app? Type YES to continue: " CONFIRM
[[ "$CONFIRM" == "YES" ]] || die "Cancelled by user."

echo "[1/5] Finding or downloading Debian 13 LXC template..."
TEMPLATE="$(pveam available --section system | awk '$2 ~ /^debian-13-standard_.*_amd64\.tar\.(zst|gz|xz)$/ {print $2}' | sort -V | tail -n1)"
if [[ -z "$TEMPLATE" ]]; then
  pveam update
  TEMPLATE="$(pveam available --section system | awk '$2 ~ /^debian-13-standard_.*_amd64\.tar\.(zst|gz|xz)$/ {print $2}' | sort -V | tail -n1)"
fi
[[ -n "$TEMPLATE" ]] || die "Could not find a Debian 13 standard template in Proxmox repositories."
if ! pvesm list "$TEMPLATE_STORAGE" --content vztmpl | awk '{print $1}' | grep -Fxq "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE"; then
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi
TEMPLATE_VOL="$TEMPLATE_STORAGE:vztmpl/$TEMPLATE"

echo "[2/5] Creating unprivileged Debian LXC..."
pct create "$CTID" "$TEMPLATE_VOL" \
  --hostname "$HOSTNAME" \
  --unprivileged 1 \
  --cores "$CORES" \
  --memory "$MEMORY" \
  --swap "$SWAP" \
  --rootfs "$ROOTFS_STORAGE:$DISK" \
  --net0 "name=eth0,bridge=$BRIDGE,ip=$IP_CIDR,gw=$GATEWAY,type=veth" \
  --nameserver "$DNS" \
  --onboot 1 \
  --start 1

cleanup_on_error() {
  echo "Installation failed. Container $CTID was left in place for inspection; it was NOT automatically deleted." >&2
}
trap cleanup_on_error ERR

echo "[3/5] Waiting for container networking..."
sleep 5
pct exec "$CTID" -- bash -lc 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git'
echo "[4/5] Cloning the application and running its installer..."
pct exec "$CTID" -- bash -lc "git clone '$APP_REPO' /opt/dz-route-analyzer && cd /opt/dz-route-analyzer && bash install.sh"

echo "[5/5] Checking service..."
pct exec "$CTID" -- systemctl --no-pager --full status dz-route-analyzer.service || true

echo
echo "Installation flow finished."
echo "Container: $CTID ($HOSTNAME)"
echo "Dashboard: http://$IP_ONLY:8088"
echo "Check from Proxmox: pct exec $CTID -- systemctl status dz-route-analyzer"
echo "Logs: pct exec $CTID -- journalctl -u dz-route-analyzer -n 100 --no-pager"
echo
echo "Note: ICMP probes depend on Proxmox/LXC kernel and security policies. Test Ping and Traceroute in the dashboard."
