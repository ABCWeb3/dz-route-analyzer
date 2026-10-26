from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.parse
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
ASN_LIST = [x.strip().upper() for x in os.getenv("TARGET_ASNS", "AS33779").split(",") if x.strip()]
MAX_PREFIXES = max(1, min(int(os.getenv("MAX_PREFIXES_PER_CYCLE", "20")), 100))
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "measurements.sqlite3"))
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$")
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
        CREATE TABLE IF NOT EXISTS prefixes (
          prefix TEXT PRIMARY KEY, asn TEXT NOT NULL, name TEXT DEFAULT '',
          first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS measurements (
          id INTEGER PRIMARY KEY AUTOINCREMENT, tested_at TEXT NOT NULL,
          prefix TEXT NOT NULL, target_ip TEXT NOT NULL, asn TEXT NOT NULL,
          ok INTEGER NOT NULL, avg_ms REAL, min_ms REAL, max_ms REAL,
          loss_pct REAL, duration_ms INTEGER, error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_measurements_prefix_time ON measurements(prefix, tested_at);
        CREATE INDEX IF NOT EXISTS idx_measurements_time ON measurements(tested_at);
        CREATE TABLE IF NOT EXISTS runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL,
          finished_at TEXT, discovered INTEGER DEFAULT 0, tested INTEGER DEFAULT 0,
          status TEXT NOT NULL, details TEXT DEFAULT ''
        );
        """)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_host(host: str) -> str:
    host = host.strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        if not HOST_RE.fullmatch(host):
            raise HTTPException(status_code=400, detail="Invalid host or IP address")
        return host


def run_command(args: list[str], timeout: int = 20) -> dict[str, Any]:
    started = time.monotonic()
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": str(exc), "duration_ms": round((time.monotonic()-started)*1000), "stdout": "", "stderr": ""}
    return {"ok": result.returncode == 0, "returncode": result.returncode,
            "duration_ms": round((time.monotonic()-started)*1000),
            "stdout": result.stdout.strip(), "stderr": result.stderr.strip(),
            "error": None if result.returncode == 0 else "Probe command failed; not automatically packet loss"}


def discover_prefixes(asn: str) -> list[dict[str, str]]:
    url = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + urllib.parse.quote(asn)
    req = urllib.request.Request(url, headers={"User-Agent": "DZ-Route-Analyzer/1.1 (network measurement)"})
    with urllib.request.urlopen(req, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    result = []
    for item in payload.get("data", {}).get("prefixes", []):
        raw = item.get("prefix", "")
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.prefixlen >= 31:
            continue
        result.append({"prefix": str(net), "asn": asn, "name": item.get("timelines", [{}])[0].get("endtime", "") if item.get("timelines") else ""})
    return result


def sample_ip(prefix: str) -> str:
    net = ipaddress.ip_network(prefix)
    # Deterministic representative sample; never scan the full prefix.
    hosts = net.num_addresses - 2
    offset = min(max(1, hosts // 2), 65534)
    return str(net.network_address + offset)


def measure_ip(target: str) -> dict[str, Any]:
    if not shutil.which("ping"):
        return {"ok": False, "error": "ping is not installed"}
    result = run_command(["ping", "-n", "-4", "-c", str(PING_COUNT), "-W", "2", target], timeout=PING_COUNT * 3 + 5)
    output = result.get("stdout", "") + "\n" + result.get("stderr", "")
    summary = re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received,\s*(\d+(?:\.\d+)?)% packet loss", output)
    rtt = re.search(r"rtt min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)", output)
    result.update({"target_ip": target, "packet_loss_percent": float(summary.group(3)) if summary else None,
                   "packets_transmitted": int(summary.group(1)) if summary else None,
                   "packets_received": int(summary.group(2)) if summary else None,
                   "rtt_ms": {"min": float(rtt.group(1)), "avg": float(rtt.group(2)), "max": float(rtt.group(3))} if rtt else None,
                   "output": output})
    return result


def run_collection() -> dict[str, Any]:
    if not cycle_lock.acquire(blocking=False):
        return {"ok": False, "message": "A collection cycle is already running"}
    started = now_iso()
    run_id = None
    tested = 0
    try:
        with connect_db() as db:
            cur = db.execute("INSERT INTO runs(started_at,status) VALUES(?,?)", (started, "running"))
            run_id = cur.lastrowid
        discovered: dict[str, dict[str, str]] = {}
        errors = []
        for asn in ASN_LIST:
            try:
                for p in discover_prefixes(asn):
                    discovered[p["prefix"]] = p
            except Exception as exc:
                errors.append(f"{asn}: {exc}")
        with connect_db() as db:
            for p in discovered.values():
                db.execute("""INSERT INTO prefixes(prefix,asn,name,first_seen,last_seen,active) VALUES(?,?,?,?,?,1)
                    ON CONFLICT(prefix) DO UPDATE SET asn=excluded.asn,last_seen=excluded.last_seen,active=1""",
                    (p["prefix"], p["asn"], p["name"], started, started))
            if discovered:
                placeholders = ",".join("?" for _ in discovered)
                db.execute("UPDATE prefixes SET active=0 WHERE prefix NOT IN (" + placeholders + ")", tuple(discovered))
            else:
                db.execute("UPDATE prefixes SET active=0")
        candidates = sorted(discovered.values(), key=lambda p: (ipaddress.ip_network(p["prefix"]).prefixlen, p["prefix"]))[:MAX_PREFIXES]
        for p in candidates:
            target = sample_ip(p["prefix"])
            result = measure_ip(target)
            rtt = result.get("rtt_ms") or {}
            with connect_db() as db:
                db.execute("""INSERT INTO measurements(tested_at,prefix,target_ip,asn,ok,avg_ms,min_ms,max_ms,loss_pct,duration_ms,error)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (now_iso(), p["prefix"], target, p["asn"], int(bool(rtt) and result.get("ok", False)),
                     rtt.get("avg"), rtt.get("min"), rtt.get("max"), result.get("packet_loss_percent"),
                     result.get("duration_ms"), result.get("error") or (None if rtt else "No RTT summary returned")))
            tested += 1
        details = "; ".join(errors) if errors else ("No prefixes returned by the configured ASN" if not discovered else "")
        with connect_db() as db:
            db.execute("UPDATE runs SET finished_at=?,discovered=?,tested=?,status=?,details=? WHERE id=?",
                       (now_iso(), len(discovered), tested, "completed" if discovered else "failed", details, run_id))
        return {"ok": bool(discovered), "discovered": len(discovered), "tested": tested, "errors": errors}
    except Exception as exc:
        if run_id is not None:
            with connect_db() as db:
                db.execute("UPDATE runs SET finished_at=?,tested=?,status='failed',details=? WHERE id=?",
                           (now_iso(), tested, str(exc), run_id))
        return {"ok": False, "error": str(exc), "tested": tested}
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


app = FastAPI(title=APP_NAME, version="1.1.0", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DZ Route Analyzer</title><style>
:root{color-scheme:dark;font-family:system-ui,sans-serif}body{margin:0;background:#0b1220;color:#e5e7eb}
main{max-width:1100px;margin:32px auto;padding:0 18px}h1{margin-bottom:4px}.muted{color:#9ca3af}
.card{background:#111c2f;border:1px solid #263449;border-radius:14px;padding:18px;margin:16px 0;overflow:auto}
button{font:inherit;border-radius:8px;padding:10px 13px;border:1px solid #34445c;background:#2563eb;color:white;cursor:pointer;margin:4px}
table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{text-align:left;padding:10px;border-bottom:1px solid #263449;white-space:nowrap}
.metric{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.metric div{background:#0b1220;padding:14px;border-radius:10px}
.metric b{font-size:1.45rem;display:block}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d16;padding:14px;border-radius:8px}
</style></head><body><main><h1>🇩🇿 DZ Route Analyzer</h1>
<p class="muted">Algerie Telecom IPv4 prefix discovery · historical measurements · cautious ranking</p>
<section class="card"><h2>Collection overview</h2><div class="metric" id="metrics"><div>Loading…</div></div>
<button onclick="refreshAll()">Refresh data</button><button onclick="collect()">Run collection now</button><p class="muted" id="message">Automatic collection interval is shown in service status.</p></section>
<section class="card"><h2>Best observed prefixes</h2><p class="muted">Ranked by historical measurements; one representative IP per prefix per cycle. A single sample does not represent every IP in a prefix.</p>
<table><thead><tr><th>Rank</th><th>Prefix</th><th>ASN</th><th>Tests</th><th>Avg latency</th><th>Avg loss</th><th>Last measured</th></tr></thead><tbody id="prefixes"><tr><td colspan="7">Loading…</td></tr></tbody></table></section>
<section class="card"><h2>Measurement history</h2><table><thead><tr><th>Time (UTC)</th><th>Prefix</th><th>Test IP</th><th>Latency</th><th>Loss</th><th>Status</th></tr></thead><tbody id="history"><tr><td colspan="6">Loading…</td></tr></tbody></table></section>
<section class="card"><h2>Collection runs</h2><pre id="runs">Loading…</pre></section>
<section class="card"><h2>Service status</h2><pre id="status">Loading…</pre></section>
<script>
async function get(path){const r=await fetch(path);const d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
function esc(v){return String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function refreshAll(){try{const [s,p,h,r]=await Promise.all([get('/api/status'),get('/api/prefixes'),get('/api/history?limit=50'),get('/api/runs?limit=10')]);
document.querySelector('#metrics').innerHTML=[['Active prefixes',p.active_prefixes],['Measured prefixes',p.items.length],['Measurements',p.total_measurements],['Last collection',p.last_run||'—']].map(x=>'<div><span class="muted">'+esc(x[0])+'</span><b>'+esc(x[1])+'</b></div>').join('');
document.querySelector('#prefixes').innerHTML=p.items.map((x,i)=>'<tr><td>'+(i+1)+'</td><td>'+esc(x.prefix)+'</td><td>'+esc(x.asn)+'</td><td>'+esc(x.tests)+'</td><td>'+esc(x.avg_ms==null?'—':Number(x.avg_ms).toFixed(2)+' ms')+'</td><td>'+esc(x.loss_pct==null?'—':Number(x.loss_pct).toFixed(1)+'%')+'</td><td>'+esc(x.last_measured)+'</td></tr>').join('')||'<tr><td colspan="7">No measurements yet. Run a collection or check ASN/network access.</td></tr>';
document.querySelector('#history').innerHTML=h.items.map(x=>'<tr><td>'+esc(x.tested_at)+'</td><td>'+esc(x.prefix)+'</td><td>'+esc(x.target_ip)+'</td><td>'+esc(x.avg_ms==null?'—':Number(x.avg_ms).toFixed(2)+' ms')+'</td><td>'+esc(x.loss_pct==null?'—':Number(x.loss_pct).toFixed(1)+'%')+'</td><td>'+esc(x.ok?'Measured':'Incomplete')+'</td></tr>').join('')||'<tr><td colspan="6">No history yet.</td></tr>';
document.querySelector('#runs').textContent=JSON.stringify(r.items,null,2);document.querySelector('#status').textContent=JSON.stringify(s,null,2);
}catch(e){document.querySelector('#message').textContent=String(e)}}
async function collect(){const m=document.querySelector('#message');m.textContent='Discovering prefixes and measuring samples…';try{const d=await get('/api/collect');m.textContent=JSON.stringify(d);await refreshAll()}catch(e){m.textContent=String(e)}}
refreshAll();setInterval(refreshAll,60000);
</script></main></body></html>"""


@app.get("/api/status")
def status() -> dict[str, Any]:
    with connect_db() as db:
        count = db.execute("SELECT COUNT(*) FROM prefixes WHERE active=1").fetchone()[0]
        measurements = db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0]
        last = db.execute("SELECT finished_at,status,details FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    return {"app": APP_NAME, "version": "1.1.0", "mode": "native", "platform": "Debian LXC",
            "web_host": WEB_HOST, "web_port": WEB_PORT, "ping_count": PING_COUNT,
            "auto_test_interval_minutes": AUTO_TEST_INTERVAL_MINUTES, "target_asns": ASN_LIST,
            "max_prefixes_per_cycle": MAX_PREFIXES, "database": DB_PATH,
            "active_prefixes": count, "measurements": measurements,
            "last_run": dict(last) if last else None,
            "tools": {"ping": shutil.which("ping") is not None, "traceroute": shutil.which("traceroute") is not None}}


@app.get("/api/collect")
def collect() -> dict[str, Any]:
    return run_collection()


@app.get("/api/prefixes")
def prefixes() -> dict[str, Any]:
    with connect_db() as db:
        active = db.execute("SELECT COUNT(*) FROM prefixes WHERE active=1").fetchone()[0]
        total = db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0]
        last = db.execute("SELECT finished_at FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        rows = db.execute("""
          SELECT p.prefix,p.asn,p.active,COUNT(m.id) AS tests,AVG(m.avg_ms) AS avg_ms,
                 AVG(m.loss_pct) AS loss_pct,MAX(m.tested_at) AS last_measured
          FROM prefixes p LEFT JOIN measurements m ON m.prefix=p.prefix
          WHERE p.active=1 GROUP BY p.prefix,p.asn
          ORDER BY CASE WHEN AVG(m.avg_ms) IS NULL THEN 1 ELSE 0 END,
                   AVG(m.loss_pct) ASC, AVG(m.avg_ms) ASC, COUNT(m.id) DESC
        """).fetchall()
    return {"active_prefixes": active, "total_measurements": total,
            "last_run": last["finished_at"] if last and last["finished_at"] else None,
            "items": [dict(r) for r in rows]}


@app.get("/api/history")
def history(limit: int = Query(default=100, ge=1, le=1000), prefix: str | None = None) -> dict[str, Any]:
    with connect_db() as db:
        if prefix:
            try:
                prefix = str(ipaddress.ip_network(prefix, strict=False))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid IPv4 prefix")
            rows = db.execute("SELECT * FROM measurements WHERE prefix=? ORDER BY id DESC LIMIT ?", (prefix, limit)).fetchall()
        else:
            rows = db.execute("SELECT * FROM measurements ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/runs")
def runs(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
    with connect_db() as db:
        rows = db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/ping")
def ping(host: str = Query(default="1.1.1.1", min_length=1, max_length=253)) -> dict[str, Any]:
    host = validate_host(host)
    if not shutil.which("ping"):
        raise HTTPException(status_code=503, detail="ping is not installed")
    result = measure_ip(host)
    result["host"] = host
    return result


@app.get("/api/traceroute")
def traceroute(host: str = Query(default="1.1.1.1", min_length=1, max_length=253)) -> dict[str, Any]:
    host = validate_host(host)
    executable = shutil.which("traceroute")
    if not executable:
        raise HTTPException(status_code=503, detail="traceroute is not installed")
    result = run_command([executable, "-n", "-m", "15", "-w", "1", host], timeout=25)
    result["host"] = host
    result["output"] = result["stdout"] + ("\n" + result["stderr"] if result["stderr"] else "")
    return result
