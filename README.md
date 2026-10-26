# DZ Route Analyzer

A lightweight FastAPI dashboard for recording the **public IPv4 address observed for your own internet connection** and comparing connection performance over time. Designed for a Debian LXC on Proxmox.

## What it records

- External IPv4 observed via public-IP check services, with a timestamp.
- The broad first-octet group (for example, \`41.x.x.x\`, \`105.x.x.x\`) and a convenient approximate \`/24\` label.
- Latency, packet loss and ping jitter to stable targets (defaults: \`1.1.1.1\` and \`8.8.8.8\`).
- Historical observations, changes of observed IP, and summary performance per broad IP group.
- SQLite history stored in \`data/measurements.sqlite3\`.

The collector runs automatically every 15 minutes by default. Use **Collect now** on the dashboard to record a sample immediately.

## Important limitations

- The IP is the address seen by an external IP-check service. If the ISP uses CGNAT, it may not be the exact address assigned to the OPNsense WAN interface.
- The \`/24\` label is only a convenient grouping of the observed address. It does not claim to be Algérie Télécom's actual BGP route prefix.
- A broad group is not guaranteed to be faster or better everywhere. Compare multiple samples at similar times; latency and packet loss can vary with congestion, destination and routing.
- The app records changes in observed IP, but cannot prove that a modem reboot caused a change.
- Rebooting the modem does not guarantee that Algérie Télécom will assign a preferred IP group.
- This version no longer treats random sample addresses from all ASN-announced prefixes as a proxy for your own connection.

## Install

On the Proxmox host, use the repository's installer for the intended LXC workflow. Existing deployment in the lab uses LXC ID \`213\`, IP \`192.168.1.213\`, dashboard port \`8088\`.

## Update an existing installation

Run on the Proxmox host:

\`\`\`bash
pct exec 213 -- bash -lc 'cd /opt/dz-route-analyzer && git pull --ff-only && bash update.sh'
\`\`\`

The updater preserves \`.env\` and the SQLite database. If the service does not start after updating, inspect it with:

\`\`\`bash
pct exec 213 -- systemctl status dz-route-analyzer --no-pager
pct exec 213 -- journalctl -u dz-route-analyzer -n 100 --no-pager
\`\`\`

## Configuration

Optional environment variables in \`.env\`:

- \`WEB_HOST\`: web bind address, default \`0.0.0.0\`.
- \`WEB_PORT\`: dashboard port, default \`8088\`.
- \`AUTO_TEST_INTERVAL_MINUTES\`: collection interval, default \`15\` (minimum 5).
- \`PING_COUNT\`: pings per target, default \`5\`.
- \`PROBE_TARGETS\`: comma-separated IP targets, default \`1.1.1.1,8.8.8.8\`.
- \`TZ\`: system timezone preference; database timestamps are stored in UTC.

## Dashboard and API

- Dashboard: \`http://192.168.1.213:8088\` in the current lab deployment.
- \`GET /api/status\`
- \`GET /api/collect\`
- \`GET /api/groups\`
- \`GET /api/history?limit=100\`
- \`GET /api/probes?limit=100\`
- \`GET /api/ping?host=1.1.1.1\`

## Data and privacy

Measurements are stored locally in SQLite. The collector makes outbound requests to public-IP check services and sends ICMP echo requests to configured targets. It does not scan Algérie Télécom address ranges.
