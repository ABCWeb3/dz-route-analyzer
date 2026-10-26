# DZ Route Analyzer

A lightweight native Debian 13 / Proxmox LXC dashboard for discovering IPv4 prefixes announced by configured ASNs, collecting repeatable measurements, and comparing historical latency and packet loss. Docker is not required.

## What it does

- Discovers IPv4 prefixes announced in public routing data via RIPEstat.
- Defaults to `AS36947` (Telecom Algeria / Algérie Télécom); verify the ASN against current routing data before drawing conclusions. `AS33779` belongs to Wataniya Telecom / Ooredoo Algeria, not Algérie Télécom.
- Stores discovered prefixes, individual measurements, and collection runs in a local SQLite database at `data/measurements.sqlite3`.
- Runs a scheduled collection cycle (default every 15 minutes) and also offers a manual collection action.
- Measures a representative IPv4 address per discovered prefix, up to a configurable maximum each cycle.
- Shows historical measurements and a preliminary ranking based on observed packet loss, latency, and sample count.
- Retains the existing ping and traceroute diagnostic endpoints and the native systemd service.

## Important measurement limits

This tool discovers prefixes announced by an ASN; that does not mean every address in a prefix is assigned, reachable, or equivalent in performance. It deliberately does **not** scan every address in a prefix. Each cycle measures one deterministic representative address per selected prefix, so rankings are preliminary and depend on whether that sample responds to ICMP. A failed/no-response ping is not proof that the address is unused or that the prefix is poor: routers and hosts can filter ICMP. Collect data over multiple days and use other permitted protocols or provider-approved targets before making operational decisions.

RIPEstat is a public routing-data source, not an Algeria Telecom internal inventory. Prefixes can change, and public routing datasets can be incomplete or delayed. Configure only ASNs you have a reason to compare. Use the measurements responsibly and do not conduct broad port scans or unauthorized probing.

## Install with one command

For an existing Debian LXC or Debian host, review the script first and then run it from a clone:

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/ABCWeb3/dz-route-analyzer.git
cd dz-route-analyzer
sudo bash install.sh
```

The installer installs system packages, creates a Python virtual environment and a local `.env` file if one does not exist, registers the systemd service, and starts the dashboard.

## Create a new Proxmox LXC

Run on the Proxmox VE host as root. This creates a **new** unprivileged Debian 13 LXC; it does not replace or modify an existing container:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ABCWeb3/dz-route-analyzer/main/proxmox-install.sh)"
```

The interactive installer asks for container ID, hostname, static IPv4/CIDR, gateway, bridge, storage, CPU, memory, disk, and DNS. Use an unused static address and reserve it or exclude it from DHCP. Review `proxmox-install.sh` before execution if you need to audit its actions.

Open `http://<LXC-IP>:8088` after installation.

## Configuration

The installer creates `.env` from `.env.example` only if it does not already exist. Existing local settings are preserved during a normal reinstall.

| Variable | Default | Purpose |
|---|---|---|
| `WEB_HOST` | `0.0.0.0` | Dashboard bind address |
| `WEB_PORT` | `8088` | Dashboard port |
| `AUTO_TEST_INTERVAL_MINUTES` | `15` | Time between scheduled collection cycles (minimum 5) |
| `PING_COUNT` | `5` | ICMP packets per target measurement |
| `TARGET_ASNS` | `AS33779` | Comma-separated ASNs to discover |
| `MAX_PREFIXES_PER_CYCLE` | `20` | Maximum prefixes sampled each cycle |
| `TZ` | `Africa/Algiers` | Host/container timezone setting |

After changing configuration, restart the service:

```bash
sudo systemctl restart dz-route-analyzer
```

## Dashboard and API

- `GET /` — historical dashboard and preliminary prefix ranking.
- `GET /api/status` — service configuration and collection summary.
- `GET /api/collect` — manually trigger one discovery/measurement cycle.
- `GET /api/prefixes` — active prefixes and aggregated historical metrics.
- `GET /api/history?limit=100` — recent measurements; optionally add `prefix=203.0.113.0/24`.
- `GET /api/runs?limit=20` — collection run history.
- `GET /api/ping?host=1.1.1.1` — manual ping diagnostic.
- `GET /api/traceroute?host=1.1.1.1` — bounded traceroute diagnostic.

The API runs on the local network by default. Do not expose it directly to the public internet without adding authentication and access controls.

## Service commands

```bash
sudo systemctl status dz-route-analyzer
sudo journalctl -u dz-route-analyzer -f
sudo systemctl restart dz-route-analyzer
```

On the Proxmox host, for CTID 213:

```bash
pct exec 213 -- systemctl status dz-route-analyzer
pct exec 213 -- journalctl -u dz-route-analyzer -n 100 --no-pager
```

## Updating an existing installation

The updater makes a timestamped backup of `.env` and `data/` under `/root/`, pulls the latest GitHub code, installs dependencies, and restarts the service. Run it inside the existing LXC as root:

```bash
cd /opt/dz-route-analyzer
sudo bash update.sh
```

If the repository was cloned to a different path, substitute that path. If the update fails, the backup path is printed before the update begins.

If the repository was cloned to a different path, substitute that path for `/opt/dz-route-analyzer`.

## Project structure

```text
app/main.py                 FastAPI dashboard, discovery, SQLite, and probes
requirements.txt            Python dependencies
.env.example                Example configuration
install.sh                  Native Debian installer
proxmox-install.sh          Proxmox LXC installer
dz-route-analyzer.service   systemd unit template
```
