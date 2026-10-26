from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

APP_NAME = "DZ Route Analyzer"
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8088"))
PING_COUNT = max(1, min(int(os.getenv("PING_COUNT", "5")), 20))
AUTO_TEST_INTERVAL_MINUTES = max(5, int(os.getenv("AUTO_TEST_INTERVAL_MINUTES", "15")))
PROBE_TARGETS = [x.strip() for x in os.getenv("PROBE_TARGETS", "1.1.1.1,8.8.8.8").split(",") if x.strip()]
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "measurements.sqlite3"))
cycle_lock = threading.Lock()


def connect_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS ip_observations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, observed_at TEXT NOT NULL,
          public_ip TEXT NOT NULL, ip_group TEXT NOT NULL, prefix24 TEXT NOT NULL,
          source TEXT NOT NULL DEFAULT 'external-ip-check'
        );
        CREATE INDEX IF NOT EXISTS idx_ip_observations_time ON ip_observations(observed_at);
        CREATE INDEX IF NOT EXISTS idx_ip_observations_ip ON ip_observations(public_ip);
        CREATE TABLE IF NOT EXISTS probe_results (
          id INTEGER PRIMARY KEY AUTOINCREMENT, observation_id INTEGER NOT NULL,
          tested_at TEXT NOT NULL, target TEXT NOT NULL, ok INTEGER NOT NULL,
          avg_ms REAL, min_ms REAL, max_ms REAL, loss_pct REAL, jitter_ms REAL, error TEXT,
          FOREIGN KEY(observation_id) REFERENCES ip_observations(id)
        );
        CREATE INDEX IF NOT EXISTS idx_probe_observation ON probe_results(observation_id);
        CREATE TABLE IF NOT EXISTS collection_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL,
          finished_at TEXT, public_ip TEXT, status TEXT NOT NULL, details TEXT DEFAULT ''
        );
        """)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_public_ip() -> str:
    # This is the IPv4 address seen by the external service. With CGNAT it may
    # differ from the address assigned directly to the OPNsense WAN interface.
    urls = ("https://api.ipify.org", "https://checkip.amazonaws.com")
    errors = []
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DZ-Route-Analyzer/2.0"})
            with urllib.request.urlopen(req, timeout=8) as response:
                value = response.read(128).decode("ascii", "ignore").strip()
            parsed = ipaddress.ip_address(value)
            if parsed.version == 4 and not parsed.is_private and not parsed.is_loopback:
                return str(parsed)
            errors.append("Service returned a non-public IPv4 address")
        except Exception as exc:
            errors.append(str(exc))
    raise RuntimeError("Could not determine external public IPv4: " + " | ".join(errors))


def classify_ip(value: str) -> tuple[str, str]:
    addr = ipaddress.ip_address(value)
    if addr.version != 4:
        raise ValueError("Only IPv4 addresses are supported")
    octets = value.split(".")
    return octets[0] + ".x.x.x", ".".join(octets[:3]) + ".0/24"


def measure_ip(target: str) -> dict[str, Any]:
    if not shutil.which("ping"):
        return {"ok": False, "error": "ping is not installed"}
    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["ping", "-n", "-4", "-c", str(PING_COUNT), "-W", "2", target],
            capture_output=True, text=True, timeout=PING_COUNT * 3 + 5, check=False
        )
        output = proc.stdout + "\n" + proc.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": str(exc), "duration_ms": round((time.monotonic()-started)*1000)}
    summary = re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received,\s*(\d+(?:\.\d+)?)% packet loss", output)
    rtt = re.search(r"(?:rtt|round-trip) min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?", output)
    loss = float(summary.group(3)) if summary else None
    metrics = {"min": float(rtt.group(1)), "avg": float(rtt.group(2)),
               "max": float(rtt.group(3)), "jitter": float(rtt.group(4)) if rtt and rtt.group(4) else None} if rtt else {}
    return {
        "ok": bool(rtt) and proc.returncode == 0, "target": target,
        "avg_ms": metrics.get("avg"), "min_ms": metrics.get("min"),
        "max_ms": metrics.get("max"), "jitter_ms": metrics.get("jitter"),
        "loss_pct": loss, "duration_ms": round((time.monotonic()-started)*1000),
        "error": None if rtt else (output.strip()[-500:] or "No ping summary returned")
    }


def run_collection() -> dict[str, Any]:
    if not cycle_lock.acquire(blocking=False):
        return {"ok": False, "message": "A collection cycle is already running"}
    started = now_iso()
    run_id = None
    try:
        with connect_db() as db:
            cur = db.execute("INSERT INTO collection_runs(started_at,status) VALUES(?,?)", (started, "running"))
            run_id = cur.lastrowid
        public_ip = get_public_ip()
        ip_group, prefix24 = classify_ip(public_ip)
        with connect_db() as db:
            cur = db.execute(
                "INSERT INTO ip_observations(observed_at,public_ip,ip_group,prefix24) VALUES(?,?,?,?)",
                (now_iso(), public_ip, ip_group, prefix24)
            )
            observation_id = cur.lastrowid
        results = []
        for target in PROBE_TARGETS:
            result = measure_ip(target)
            results.append({"target": target, "ok": result.get("ok", False),
                            "avg_ms": result.get("avg_ms"), "loss_pct": result.get("loss_pct"),
                            "jitter_ms": result.get("jitter_ms"), "error": result.get("error")})
            with connect_db() as db:
                db.execute("""INSERT INTO probe_results
                  (observation_id,tested_at,target,ok,avg_ms,min_ms,max_ms,loss_pct,jitter_ms,error)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (observation_id, now_iso(), target, int(bool(result.get("ok"))),
                   result.get("avg_ms"), result.get("min_ms"), result.get("max_ms"),
                   result.get("loss_pct"), result.get("jitter_ms"), result.get("error")))
        details = " | ".join(x["target"] + ": " + str(x.get("error")) for x in results if x.get("error"))
        with connect_db() as db:
            db.execute("UPDATE collection_runs SET finished_at=?,public_ip=?,status=?,details=? WHERE id=?",
                       (now_iso(), public_ip, "completed", details, run_id))
        return {"ok": True, "public_ip": public_ip, "ip_group": ip_group,
                "prefix24": prefix24, "probes": results, "observed_at": started}
    except Exception as exc:
        if run_id is not None:
            with connect_db() as db:
                db.execute("UPDATE collection_runs SET finished_at=?,status='failed',details=? WHERE id=?",
                           (now_iso(), str(exc), run_id))
        return {"ok": False, "error": str(exc)}
    finally:
        cycle_lock.release()


async def scheduler():
    while True:
        await asyncio.to_thread(run_collection)
        await asyncio.sleep(AUTO_TEST_INTERVAL_MINUTES * 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(scheduler())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title=APP_NAME, version="2.0.0", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DZ Route Analyzer</title><style>
:root{color-scheme:dark;font-family:system-ui,sans-serif}body{margin:0;background:#0b1220;color:#e5e7eb}
main{max-width:1150px;margin:30px auto;padding:0 18px}h1{margin-bottom:4px}.muted{color:#9ca3af}
.card{background:#111c2f;border:1px solid #263449;border-radius:14px;padding:18px;margin:16px 0;overflow:auto}
button{font:inherit;border-radius:8px;padding:10px 13px;border:1px solid #34445c;background:#2563eb;color:white;cursor:pointer;margin:4px}
table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:10px;border-bottom:1px solid #263449;white-space:nowrap}
.metric{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}.metric div{background:#0b1220;padding:14px;border-radius:10px}
.metric b{font-size:1.4rem;display:block;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d16;padding:14px;border-radius:8px}
</style></head><body><main><h1>🇩🇿 DZ Route Analyzer</h1>
<p class="muted">Track your connection's observed public IPv4 address and measure latency/loss over time.</p>
<section class="card"><h2>Current connection observation</h2><div class="metric" id="metrics"><div>Loading…</div></div>
<button onclick="collect()">Collect now</button><button onclick="refreshAll()">Refresh history</button>
<p class="muted" id="message">Automatic collection every configured interval.</p></section>
<section class="card"><h2>Performance by observed IP group</h2>
<p class="muted">Groups such as 41.x.x.x are based on the first IPv4 octet. The /24 label is only a convenient grouping, not a claim about the ISP's routed prefix. Prefer groups with repeated samples; routing and congestion can change.</p>
<table><thead><tr><th>IP group</th><th>Samples</th><th>Distinct IPs</th><th>Avg latency</th><th>Avg packet loss</th><th>Last seen</th></tr></thead><tbody id="groups"><tr><td colspan="6">Loading…</td></tr></tbody></table></section>
<section class="card"><h2>Observed public IP history</h2><table><thead><tr><th>Time (UTC)</th><th>Public IP</th><th>Group</th><th>Approx. /24</th><th>Targets measured</th></tr></thead><tbody id="history"><tr><td colspan="5">Loading…</td></tr></tbody></table></section>
<section class="card"><h2>Recent probe results</h2><table><thead><tr><th>Time (UTC)</th><th>Public IP</th><th>Target</th><th>Latency</th><th>Loss</th><th>Jitter</th><th>Status</th></tr></thead><tbody id="probes"><tr><td colspan="7">Loading…</td></tr></tbody></table></section>
<section class="card"><h2>Service status</h2><pre id="status">Loading…</pre></section>
<script>
async function get(path){const r=await fetch(path);const d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
function esc(v){return String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function ms(v){return v==null?'—':Number(v).toFixed(2)+' ms'}
function pct(v){return v==null?'—':Number(v).toFixed(1)+'%'}
async function refreshAll(){try{
const [s,g,h,p]=await Promise.all([get('/api/status'),get('/api/groups'),get('/api/history?limit=80'),get('/api/probes?limit=100')]);
const c=s.current||{};
document.querySelector('#metrics').innerHTML=[['Observed public IP',c.public_ip],['IP group',c.ip_group],['Approx. /24',c.prefix24],['Last observation',c.observed_at],['IP changes recorded',s.ip_changes],['Collection interval',s.interval_minutes+' min']].map(x=>'<div><span class="muted">'+esc(x[0])+'</span><b>'+esc(x[1])+'</b></div>').join('');
document.querySelector('#groups').innerHTML=g.items.map(x=>'<tr><td>'+esc(x.ip_group)+'</td><td>'+esc(x.samples)+'</td><td>'+esc(x.distinct_ips)+'</td><td>'+ms(x.avg_ms)+'</td><td>'+pct(x.avg_loss_pct)+'</td><td>'+esc(x.last_seen)+'</td></tr>').join('')||'<tr><td colspan="6">No observations yet.</td></tr>';
document.querySelector('#history').innerHTML=h.items.map(x=>'<tr><td>'+esc(x.observed_at)+'</td><td>'+esc(x.public_ip)+'</td><td>'+esc(x.ip_group)+'</td><td>'+esc(x.prefix24)+'</td><td>'+esc(x.probe_count)+'</td></tr>').join('')||'<tr><td colspan="5">No history yet.</td></tr>';
document.querySelector('#probes').innerHTML=p.items.map(x=>'<tr><td>'+esc(x.tested_at)+'</td><td>'+esc(x.public_ip)+'</td><td>'+esc(x.target)+'</td><td>'+ms(x.avg_ms)+'</td><td>'+pct(x.loss_pct)+'</td><td>'+ms(x.jitter_ms)+'</td><td>'+esc(x.ok?'OK':'Incomplete')+'</td></tr>').join('')||'<tr><td colspan="7">No probe results yet.</td></tr>';
document.querySelector('#status').textContent=JSON.stringify(s,null,2);
}catch(e){document.querySelector('#message').textContent=String(e)}}
async function collect(){const m=document.querySelector('#message');m.textContent='Checking public IP and measuring fixed targets…';try{const d=await get('/api/collect');m.textContent=JSON.stringify(d);await refreshAll()}catch(e){m.textContent=String(e)}}
refreshAll();setInterval(refreshAll,60000);
</script></main></body></html>"""


@app.get("/api/status")
def status() -> dict[str, Any]:
    with connect_db() as db:
        current = db.execute("SELECT * FROM ip_observations ORDER BY id DESC LIMIT 1").fetchone()
        count = db.execute("SELECT COUNT(*) FROM ip_observations").fetchone()[0]
        changes = db.execute("""SELECT COUNT(*) FROM (
          SELECT public_ip,LAG(public_ip) OVER (ORDER BY id) AS prev
          FROM ip_observations) WHERE prev IS NOT NULL AND public_ip != prev""").fetchone()[0]
        last_run = db.execute("SELECT * FROM collection_runs ORDER BY id DESC LIMIT 1").fetchone()
    return {"app": APP_NAME, "version": "2.0.0", "mode": "native", "platform": "Debian LXC",
            "web_host": WEB_HOST, "web_port": WEB_PORT, "ping_count": PING_COUNT,
            "interval_minutes": AUTO_TEST_INTERVAL_MINUTES, "probe_targets": PROBE_TARGETS,
            "database": DB_PATH, "observations": count, "ip_changes": changes,
            "current": dict(current) if current else None, "last_run": dict(last_run) if last_run else None,
            "note": "Public IP observed by an external service; may differ from OPNsense WAN address under CGNAT.",
            "tools": {"ping": shutil.which("ping") is not None}}


@app.get("/api/collect")
def collect() -> dict[str, Any]:
    return run_collection()


@app.get("/api/groups")
def groups() -> dict[str, Any]:
    with connect_db() as db:
        rows = db.execute("""
          SELECT o.ip_group, COUNT(DISTINCT o.id) AS samples,
                 COUNT(DISTINCT o.public_ip) AS distinct_ips,
                 AVG(p.avg_ms) AS avg_ms, AVG(p.loss_pct) AS avg_loss_pct,
                 MAX(o.observed_at) AS last_seen
          FROM ip_observations o LEFT JOIN probe_results p ON p.observation_id=o.id
          GROUP BY o.ip_group ORDER BY
            CASE WHEN AVG(p.avg_ms) IS NULL THEN 1 ELSE 0 END,
            AVG(p.loss_pct) ASC, AVG(p.avg_ms) ASC
        """).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/history")
def history(limit: int = Query(default=100, ge=1, le=1000)) -> dict[str, Any]:
    with connect_db() as db:
        rows = db.execute("""
          SELECT o.id,o.observed_at,o.public_ip,o.ip_group,o.prefix24,
                 COUNT(p.id) AS probe_count
          FROM ip_observations o LEFT JOIN probe_results p ON p.observation_id=o.id
          GROUP BY o.id ORDER BY o.id DESC LIMIT ?
        """, (limit,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/probes")
def probes(limit: int = Query(default=100, ge=1, le=1000)) -> dict[str, Any]:
    with connect_db() as db:
        rows = db.execute("""
          SELECT p.*,o.public_ip,o.ip_group FROM probe_results p
          JOIN ip_observations o ON o.id=p.observation_id
          ORDER BY p.id DESC LIMIT ?
        """, (limit,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/ping")
def ping(host: str = Query(default="1.1.1.1", min_length=1, max_length=253)) -> dict[str, Any]:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(status_code=400, detail="Enter an IP address for this diagnostic endpoint")
    result = measure_ip(host)
    result["host"] = host
    return result
