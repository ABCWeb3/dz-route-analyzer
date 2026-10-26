# DZ Route Analyzer

A lightweight network diagnostics dashboard designed to run directly on Debian 13 inside a Proxmox LXC container. **Docker is not required.**

## Features

- Web dashboard and JSON API powered by FastAPI.
- Ping measurements: latency, packet loss, and command errors reported separately.
- Traceroute diagnostics.
- Configurable targets and test settings.
- One-command installation and a systemd service for automatic startup.

## Requirements

- Debian 13 (Trixie) or a compatible Debian release.
- Root/sudo access for the installer to install system packages and register the service.
- Network access to install Python packages.
- A network policy that permits the required ICMP/UDP probes.

## Install with one command

Review `install.sh` before running it, then execute from the cloned repository:

```bash
sudo bash install.sh
```

The installer installs system dependencies, creates a Python virtual environment, installs requirements, writes a local `.env` if absent, registers and starts the `dz-route-analyzer` systemd service.

To clone and install on a fresh Debian LXC:

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/ABCWeb3/dz-route-analyzer.git
cd dz-route-analyzer
sudo bash install.sh
```

## Create a fresh Proxmox LXC and install automatically

Run the following script **on the Proxmox VE host as root**. It creates a new unprivileged Debian 13 LXC, configures a static IPv4 address, installs Git and the application, and enables the systemd service. It does not install Docker.

Review `proxmox-install.sh` before running it. Download and execute it on the Proxmox host:

```bash
apt-get update
apt-get install -y curl
curl -fsSLo proxmox-install.sh https://raw.githubusercontent.com/ABCWeb3/dz-route-analyzer/main/proxmox-install.sh
less proxmox-install.sh
bash proxmox-install.sh
```

The script interactively asks for the CT ID, hostname, static IPv4 address **with CIDR** (for example `192.168.1.113/24`), gateway, bridge, storage, CPU, RAM, disk size, and DNS server. It shows a summary and requires typing `YES` before creating the container. Use an unused IP address and reserve it or exclude it from the DHCP pool.

Defaults are CT ID `213`, bridge `vmbr0`, rootfs storage `local-lvm`, template storage `local`, 2 CPU cores, 1024 MiB RAM, 512 MiB swap, 8 GiB disk, and DNS `1.1.1.1`. Change these at the prompts to match your Proxmox node.

After installation, open `http://<STATIC-IP>:8088`. If a step fails, the script deliberately leaves the new container in place for troubleshooting rather than deleting it automatically. Check the service with:

```bash
pct exec <CTID> -- systemctl status dz-route-analyzer
pct exec <CTID> -- journalctl -u dz-route-analyzer -n 100 --no-pager
```

The script creates a standard unprivileged container; it does not enable privileged mode or weaken the host's LXC security settings. ICMP Ping/Traceroute behavior can still depend on the Proxmox host's kernel and container security policy.

## Open the dashboard

By default, the dashboard listens on port `8088`. Open:

```text
http://<LXC-IP>:8088
```

For example, if the container address is `192.168.1.113`, use `http://192.168.1.113:8088`.

## Service commands

```bash
sudo systemctl status dz-route-analyzer
sudo journalctl -u dz-route-analyzer -f
sudo systemctl restart dz-route-analyzer
sudo systemctl stop dz-route-analyzer
```

## Configuration

The installer creates `.env` from `.env.example` only if it does not already exist.

- `WEB_HOST`: bind address (default `0.0.0.0`)
- `WEB_PORT`: web port (default `8088`)
- `PING_COUNT`: ping packets per test (default `10`)
- `AUTO_TEST_INTERVAL_MINUTES`: reserved for scheduled testing (default `15`)
- `TZ`: time zone (default `Africa/Algiers`)

After changing configuration, restart the service:

```bash
sudo systemctl restart dz-route-analyzer
```

## API

- `GET /api/status` — service and configuration status.
- `GET /api/ping?host=1.1.1.1` — run a ping test against a host.
- `GET /api/traceroute?host=1.1.1.1` — run a bounded traceroute.

Only use the tool against systems and networks you are authorized to test. Host input is validated and command execution uses argument arrays rather than a shell.

## Troubleshooting

- If the page does not load, check `systemctl status dz-route-analyzer`, `journalctl -u dz-route-analyzer -n 100`, the configured port, and the LXC firewall.
- If a probe returns an execution error, do not interpret it as measured packet loss.
- Some routers do not respond to traceroute probes; `*` hops do not necessarily mean the destination is unreachable.
- If the service cannot create ICMP sockets, verify the LXC's security policy and the systemd capability configuration rather than enabling privileged containers.

## Project structure

```text
app/main.py                 FastAPI application and dashboard
requirements.txt            Python dependencies
.env.example                Example configuration
install.sh                  One-command Debian installer
proxmox-install.sh          Proxmox host script to create and install a Debian LXC
dz-route-analyzer.service   systemd unit template
```

## License

See [LICENSE](LICENSE) if a license file is added to this repository.
