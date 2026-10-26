# DZ Route Analyzer

A lightweight FastAPI dashboard for recording the **public IPv4 address observed for your own internet connection** and comparing connection performance over time. Designed for a Debian LXC on Proxmox.

## What it records

- External IPv4 observed via public-IP check services, with a timestamp.
- The broad first-octet group (for example, `41.x.x.x`, `105.x.x.x`) and a convenient approximate `/24` label.
- Latency, packet loss and ping jitter to stable targets (defaults: `1.1.1.1` and `8.8.8.8`).
- Historical observations, changes of observed IP, and summary performance per broad IP group.
- SQLite history stored in `data/measurements.sqlite3`.

The collector runs automatically every 15 minutes by default. Use **Collect now** on the dashboard to record a sample immediately.

## Installation

### Option A — Create a new Debian 13 LXC on Proxmox (recommended for a fresh install)

Run this on the **Proxmox host as root**. The installer asks for a CTID, static IP, gateway, bridge and storage, then creates the container and installs the app. It will **not overwrite an existing CTID**. Choose an unused IP that is excluded from DHCP.

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ABCWeb3/dz-route-analyzer/main/proxmox-install.sh)"
```

The script defaults to CTID `213` and bridge `vmbr0`; change the answers to match your network. The existing lab deployment already uses CTID `213`, so choose a different CTID if you are installing another copy.

### Option B — Install inside an existing Debian LXC

Run inside the Debian container as root. The container needs internet access and `git` installed.

```bash
apt-get update && apt-get install -y git ca-certificates
git clone https://github.com/ABCWeb3/dz-route-analyzer.git /opt/dz-route-analyzer
cd /opt/dz-route-analyzer
bash install.sh
```

If `/opt/dz-route-analyzer` already exists, do not clone over it; use the update instructions below instead.

## Dashboard

For the current lab deployment, open [http://192.168.1.213:8088](http://192.168.1.213:8088). For a new container, use its configured IP and port `8088`.

## Update an existing installation

Run on the Proxmox host for the current container ID `213`:

```bash
pct exec 213 -- bash -lc 'cd /opt/dz-route-analyzer && git pull --ff-only && bash update.sh'
```

The updater backs up `.env` and the SQLite data before updating. If the service does not start after updating, inspect it with:

```bash
pct exec 213 -- systemctl status dz-route-analyzer --no-pager
pct exec 213 -- journalctl -u dz-route-analyzer -n 100 --no-pager
```

For another CTID, replace `213` with that container's ID.

## Configuration

Optional environment variables in `.env`:

- `WEB_HOST`: web bind address, default `0.0.0.0`.
- `WEB_PORT`: dashboard port, default `8088`.
- `AUTO_TEST_INTERVAL_MINUTES`: collection interval, default `15` (minimum 5).
- `PING_COUNT`: pings per target, default `5`.
- `PROBE_TARGETS`: comma-separated IP targets, default `1.1.1.1,8.8.8.8`.
- `TZ`: system timezone preference; database timestamps are stored in UTC.

## Important limitations

- The IP is the address seen by an external IP-check service. If the ISP uses CGNAT, it may not be the exact address assigned to the OPNsense WAN interface.
- The `/24` label is only a convenient grouping of the observed address. It does not claim to be Algérie Télécom's actual BGP route prefix.
- A broad group is not guaranteed to be faster or better everywhere. Compare multiple samples at similar times; latency and packet loss can vary with congestion, destination and routing.
- The app records changes in observed IP, but cannot prove that a modem reboot caused a change.
- Rebooting the modem does not guarantee that Algérie Télécom will assign a preferred IP group.
- The collector measures your own connection; it does not scan Algérie Télécom address ranges.

## Dashboard API

- `GET /api/status`
- `GET /api/progress`
- `GET /api/collect`
- `GET /api/groups`
- `GET /api/history?limit=100`
- `GET /api/probes?limit=100`
- `GET /api/ping?host=1.1.1.1`

## Data and privacy

Measurements are stored locally in SQLite. The collector makes outbound requests to public-IP check services and sends ICMP echo requests to configured targets. It does not scan public address ranges.
