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
progress_lock = threading.Lock()
collection_progress = {"active": False, "percent": 0, "message": "جاهز لجمع البيانات", "updated_at": None}


def set_progress(percent: int, message: str, active: bool = True):
    with progress_lock:
        collection_progress.update({"active": active, "percent": percent, "message": message, "updated_at": now_iso()})


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
    set_progress(5, "جارٍ الاتصال بخدمة التحقق من عنوان الإنترنت")
    try:
        with connect_db() as db:
            cur = db.execute("INSERT INTO collection_runs(started_at,status) VALUES(?,?)", (started, "running"))
            run_id = cur.lastrowid
        public_ip = get_public_ip()
        set_progress(25, "تم رصد عنوان الإنترنت؛ جارٍ تصنيف المجموعة")
        ip_group, prefix24 = classify_ip(public_ip)
        with connect_db() as db:
            cur = db.execute(
                "INSERT INTO ip_observations(observed_at,public_ip,ip_group,prefix24) VALUES(?,?,?,?)",
                (now_iso(), public_ip, ip_group, prefix24)
            )
            observation_id = cur.lastrowid
        results = []
        total_targets = max(1, len(PROBE_TARGETS))
        for index, target in enumerate(PROBE_TARGETS):
            set_progress(35 + int(index * 55 / total_targets), "جارٍ قياس زمن الاستجابة وفقدان الحزم")
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
        set_progress(95, "جارٍ حفظ النتائج في السجل التاريخي")
        details = " | ".join(x["target"] + ": " + str(x.get("error")) for x in results if x.get("error"))
        with connect_db() as db:
            db.execute("UPDATE collection_runs SET finished_at=?,public_ip=?,status=?,details=? WHERE id=?",
                       (now_iso(), public_ip, "completed", details, run_id))
        set_progress(100, "اكتملت عملية القياس بنجاح", active=False)
        return {"ok": True, "public_ip": public_ip, "ip_group": ip_group,
                "prefix24": prefix24, "probes": results, "observed_at": started}
    except Exception as exc:
        set_progress(100, "تعذّر إكمال العملية: " + str(exc), active=False)
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


app = FastAPI(title=APP_NAME, version="2.1.0", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """<!doctype html>
<html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0b1020"><title>DZ Route Analyzer</title>
<style>
:root{color-scheme:dark;--bg:#090e1b;--panel:#111a2c;--panel2:#0d1526;--line:#24324a;--text:#edf3ff;--muted:#8fa1bb;--blue:#7aa7ff;--cyan:#62d8e8;--green:#6ee7b7;--amber:#f7c66b;--red:#fb8791;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% -10%,#18305a 0,transparent 38%),var(--bg);color:var(--text);min-height:100vh}
main{max-width:1380px;margin:auto;padding:28px 24px 50px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:25px}
.brand{display:flex;align-items:center;gap:13px}.logo{display:grid;place-items:center;width:48px;height:48px;border-radius:15px;background:linear-gradient(135deg,#2463eb,#22b8cf);font-size:25px;box-shadow:0 8px 25px #2463eb35}
h1{font-size:clamp(22px,3vw,31px);letter-spacing:-.7px;margin:0}.subtitle{color:var(--muted);font-size:13px;margin-top:5px}
.actions{display:flex;gap:8px;flex-wrap:wrap}button{font:inherit;font-size:13px;font-weight:650;border:1px solid var(--line);background:#17243a;color:var(--text);padding:11px 15px;border-radius:11px;cursor:pointer;transition:.18s}
button:hover{border-color:#5d8de5;transform:translateY(-1px)}button.primary{background:linear-gradient(135deg,#3978f6,#2860d8);border-color:#4a83f7}button:disabled{opacity:.6;cursor:wait;transform:none}
.statusline{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;margin:0 0 18px}.dot{width:8px;height:8px;background:var(--green);border-radius:50%;box-shadow:0 0 12px #6ee7b766}.dot.busy{background:var(--amber);box-shadow:0 0 12px #f7c66b66}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px}.panel{background:linear-gradient(145deg,#131e32f5,#0e1728f5);border:1px solid var(--line);border-radius:18px;padding:20px;min-width:0;box-shadow:0 12px 35px #00000012}
.span12{grid-column:span 12}.span8{grid-column:span 8}.span7{grid-column:span 7}.span6{grid-column:span 6}.span5{grid-column:span 5}.span4{grid-column:span 4}
.panelhead{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:18px}.panel h2{font-size:15px;margin:0;font-weight:750;letter-spacing:.1px}.hint{font-size:12px;color:var(--muted);line-height:1.55;margin:6px 0 0}.eyebrow{text-transform:uppercase;letter-spacing:1.4px;font-size:10px;color:var(--muted);font-weight:800}
.iphero{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}.ipvalue{font-size:clamp(28px,4vw,43px);font-weight:800;letter-spacing:-1.5px;margin:8px 0 4px;overflow-wrap:anywhere}.groupbadge{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;background:#203657;border:1px solid #345582;border-radius:9px;color:#b8d4ff;font-size:12px;font-weight:750}
.bigstats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:20px}.stat{padding:14px;background:#0b1323;border:1px solid #1d2a40;border-radius:13px;min-width:0}.stat label{font-size:11px;color:var(--muted);display:block;margin-bottom:9px}.stat strong{font-size:20px;display:block;letter-spacing:-.4px;overflow-wrap:anywhere}.stat small{font-size:11px;color:var(--muted);display:block;margin-top:5px}
.pill{font-size:10px;font-weight:800;padding:5px 8px;border-radius:7px;background:#142f2b;color:var(--green);white-space:nowrap}.pill.warn{background:#3a2c16;color:var(--amber)}.pill.error{background:#3b1c29;color:var(--red)}
.chartwrap{height:215px;position:relative}.chartwrap svg{width:100%;height:100%;overflow:visible}.chartlegend{display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin-top:8px}.legenddot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px}
.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;white-space:nowrap;font-size:12px}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:#8295b1;font-weight:800;padding:11px 12px;border-bottom:1px solid var(--line)}td{padding:13px 12px;border-bottom:1px solid #202c40;color:#dbe6f8}tbody tr:hover{background:#ffffff05}tbody tr:last-child td{border-bottom:0}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.good{color:var(--green)}.bad{color:var(--red)}.empty{text-align:center;padding:25px;color:var(--muted)}
.barcell{min-width:120px}.barbg{height:5px;border-radius:9px;background:#24324a;overflow:hidden;margin-top:7px}.barfill{height:100%;border-radius:9px;background:linear-gradient(90deg,#5d9cff,#60d8e7)}
.targetlist{display:grid;gap:11px}.target{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:13px;background:#0b1323;border:1px solid #202e45;border-radius:12px}.targetname{font-size:13px;font-weight:750}.targetsub{font-size:11px;color:var(--muted);margin-top:4px}.targetmetrics{text-align:right}.targetmetrics strong{font-size:15px;display:block}.targetmetrics small{color:var(--muted);font-size:11px}
.footnote{color:var(--muted);font-size:11px;line-height:1.65;margin-top:16px}.notice{border:1px solid #3b4a65;background:#121f34;padding:13px 15px;border-radius:12px;color:#b8c8df;font-size:12px;line-height:1.6;margin-top:16px}
@media(max-width:900px){.span8,.span7,.span6,.span5,.span4{grid-column:span 12}.bigstats{grid-template-columns:repeat(2,minmax(0,1fr))}.top{align-items:flex-start;flex-direction:column}.actions{width:100%}}
@media(max-width:480px){main{padding:18px 12px 35px}.panel{padding:15px;border-radius:15px}.bigstats{gap:8px}.stat{padding:11px}.stat strong{font-size:17px}.ipvalue{font-size:30px}.actions button{flex:1}}
</style></head><body><main>
<header class="top"><div class="brand"><div class="logo">⌁</div><div><h1>DZ Route Analyzer</h1><div class="subtitle">Internet connection intelligence · Algérie Télécom</div></div></div>
<div class="actions"><select id="languageSelect" aria-label="Language" onchange="setLanguage(this.value)" style="font:inherit;font-size:13px;font-weight:700;border:1px solid var(--line);background:#17243a;color:var(--text);padding:10px 12px;border-radius:11px"><option value="en">🇬🇧 English</option><option value="fr">🇫🇷 Français</option><option value="ar">🇩🇿 العربية</option></select><button onclick="refreshAll()">↻ Refresh</button><button class="primary" id="collectBtn" onclick="collect()">▶ Collect now</button></div></header>
<div class="statusline"><span id="statusDot" class="dot"></span><span id="statusText">Connecting to collector…</span><span id="updated" style="margin-left:auto"></span></div>
<section class="panel" style="margin-bottom:16px;padding:15px 18px"><div style="display:flex;align-items:center;gap:12px"><span id="progressIcon" style="font-size:18px;color:var(--cyan)">◌</span><div style="flex:1;min-width:0"><div id="progressMessage" style="font-size:13px;font-weight:700">جاهز لجمع البيانات</div><div style="height:6px;background:#26354c;border-radius:99px;overflow:hidden;margin-top:9px"><div id="progressBar" style="height:100%;width:0;background:linear-gradient(90deg,#3978f6,#62d8e8);border-radius:99px;transition:width .3s"></div></div></div><strong id="progressPercent" style="font-size:13px;min-width:38px;text-align:right">0%</strong></div></section>
<div class="grid">
<section class="panel span12"><div class="iphero"><div><div class="eyebrow">Current observed public IPv4</div><div class="ipvalue mono" id="currentIP">—</div><div id="currentGroup" class="groupbadge">◉ Waiting for first observation</div></div><div><div class="eyebrow">Last observation</div><div id="currentTime" style="font-size:14px;font-weight:700;margin-top:9px">—</div><div class="hint" id="changeText">Changes are recorded automatically</div></div></div>
<div class="bigstats"><div class="stat"><label>Recorded observations</label><strong id="observations">—</strong><small>Historical samples</small></div><div class="stat"><label>IP changes</label><strong id="changes">—</strong><small>Detected between samples</small></div><div class="stat"><label>Average latency</label><strong id="avgLatency">—</strong><small>Latest collection cycle</small></div><div class="stat"><label>Average packet loss</label><strong id="avgLoss">—</strong><small>Latest collection cycle</small></div></div></section>
<section class="panel span7"><div class="panelhead"><div><h2>Latency timeline</h2><p class="hint">Response time to monitored targets over recent observations</p></div><span class="pill" id="sampleBadge">0 samples</span></div><div class="chartwrap" id="chart"><div class="empty">Collecting measurements…</div></div><div class="chartlegend"><span><i class="legenddot" style="background:#7aa7ff"></i>1.1.1.1</span><span><i class="legenddot" style="background:#62d8e8"></i>8.8.8.8</span></div></section>
<section class="panel span5"><div class="panelhead"><div><h2>Latest target health</h2><p class="hint">Latency and packet loss for the latest sample</p></div></div><div class="targetlist" id="targetList"><div class="empty">No measurements yet</div></div><div class="footnote">A target may ignore ICMP. Compare both targets and look at repeated results rather than one sample.</div></section>
<section class="panel span12"><div class="panelhead"><div><h2>Performance by IP group</h2><p class="hint">Compare observed groups using repeated measurements. Lower latency and packet loss are generally preferable.</p></div></div><div class="tablewrap"><table><thead><tr><th>IP group</th><th>Samples</th><th>Distinct IPs</th><th>Average latency</th><th>Average loss</th><th>Last observed</th></tr></thead><tbody id="groups"><tr><td colspan="6" class="empty">Loading group data…</td></tr></tbody></table></div></section>
<details class="panel span12"><summary style="cursor:pointer;font-weight:750;font-size:14px">عرض سجل عناوين IP التفصيلي</summary><div style="margin-top:16px"><div class="panelhead"><div><h2>Public IP history</h2><p class="hint">Each row is one collection cycle. Times are displayed in your browser's local timezone.</p></div><span class="pill" id="historyBadge">Recent records</span></div><div class="tablewrap"><table><thead><tr><th>Observed at</th><th>Public IP</th><th>Group</th><th>Approx. /24</th><th>Targets tested</th></tr></thead><tbody id="history"><tr><td colspan="5" class="empty">Loading history…</td></tr></tbody></table></div></div></details>
<details class="panel span12"><summary style="cursor:pointer;font-weight:750;font-size:14px">عرض تفاصيل اختبارات الاتصال</summary><div style="margin-top:16px"><div class="panelhead"><div><h2>Probe details</h2><p class="hint">Latest ping results, including failures and packet loss</p></div></div><div class="tablewrap"><table><thead><tr><th>Time</th><th>Public IP</th><th>Target</th><th>Average</th><th>Min / Max</th><th>Loss</th><th>Jitter</th><th>Result</th></tr></thead><tbody id="probes"><tr><td colspan="8" class="empty">Loading probe details…</td></tr></tbody></table></div>
<div class="notice">Interpretation note: the displayed address is the public IPv4 seen by an external check service. If Algérie Télécom uses CGNAT, this can differ from the address assigned to the OPNsense WAN interface. The approximate /24 is a display grouping, not confirmation of the ISP's actual routed prefix.</div></div></details>
</div><p class="footnote">DZ Route Analyzer · Local SQLite history · Automatic collection every <span id="interval">15</span> minutes · Data is retained on this server.</p>
<script>

const translations={
en:{
"عرض سجل عناوين IP التفصيلي":"Show detailed public IP history",
"عرض تفاصيل اختبارات الاتصال":"Show connection test details",
"Internet connection intelligence · Algérie Télécom":"Internet connection insights · Algérie Télécom",
"↻ Refresh":"↻ Refresh","▶ Collect now":"▶ Collect now","Collecting…":"Collecting…",
"Current observed public IPv4":"Your public IP address","◉ Waiting for first observation":"◉ Waiting for first check",
"Last observation":"Last check","Changes are recorded automatically":"Your connection is monitored automatically",
"Recorded observations":"Measurements saved","Historical samples":"Saved over time","IP changes":"IP changes detected","Detected between samples":"Since monitoring began","Average latency":"Average latency","Latest collection cycle":"Latest test cycle","Average packet loss":"Average packet loss",
"Latency timeline":"Connection speed over time","Response time to monitored targets over recent observations":"Response time to monitored servers","Latest target health":"Connection quality","Latency and packet loss for the latest sample":"Latency and packet loss in the latest test","Performance by IP group":"Performance by IP group","Compare observed groups using repeated measurements. Lower latency and packet loss are generally preferable.":"Compare groups across repeated tests. Lower latency and packet loss are usually better.",
"IP group":"IP group","Samples":"Samples","Distinct IPs":"Unique IPs","Average loss":"Average loss","Last observed":"Last checked",
"Public IP history":"Public IP history","Each row is one collection cycle. Times are displayed in your browser's local timezone.":"Each row is one test. Times use your browser's local timezone.",
"Probe details":"Connection test details","Latest ping results, including failures and packet loss":"Latest ping results, including failures and packet loss",
"Interpretation note: the displayed address is the public IPv4 seen by an external check service. If Algérie Télécom uses CGNAT, this can differ from the address assigned to the OPNsense WAN interface. The approximate /24 is a display grouping, not confirmation of the ISP's actual routed prefix.":"Note: this is the public IPv4 address seen by an external service. With CGNAT, it may differ from the address on your OPNsense WAN interface. The approximate /24 is only a display group, not the ISP's confirmed route.",
"Latency timeline":"Latency over time","Latest target health":"Target status","Current observed public IPv4":"Public IPv4 address",
"Waiting for first sample":"Waiting for first measurement","◉ No IP observed yet":"◉ No IP detected yet","Collector connected · automatic monitoring enabled":"Monitoring active · automatic checks enabled","Collector needs attention":"Monitoring needs attention","Could not load dashboard data":"Could not load dashboard data","Collection failed":"Measurement failed","Collection completed":"Measurement completed",
"Loading group data…":"Loading group data…","No groups recorded yet. Start a collection to begin.":"No groups yet. Run your first test to get started.","No history yet.":"No history yet.","A target may ignore ICMP. Compare both targets and look at repeated results rather than one sample.":"A target may ignore ICMP. Compare both targets across repeated tests, not just one sample.",
"Loading group data…":"Loading group data…","Collecting measurements…":"Collecting measurements…","Latency chart will appear after the first successful ping.":"Your chart will appear after the first successful test.","No measurements yet":"No measurements yet","No results for the latest sample yet.":"No results for the latest test yet.","Recent records":"Recent records","Historical samples":"Saved measurements","Changes are recorded automatically":"Your connection is checked automatically",
"● Reachable":"● Reachable","● Incomplete":"● Incomplete","OK":"OK","Incomplete":"Incomplete","minutes · Data is retained on this server.":"minutes · Data is retained on this server.",
"Collecting connection measurements":"Collecting connection measurements",
"observed address changes since monitoring began":"observed address changes since monitoring began",
"جاهز لجمع البيانات":"Ready to measure your connection","جارٍ الاتصال بخدمة التحقق من عنوان الإنترنت":"Checking your public IP address","تم رصد عنوان الإنترنت؛ جارٍ تصنيف المجموعة":"Public IP found; identifying its group","جارٍ قياس زمن الاستجابة وفقدان الحزم":"Measuring latency and packet loss","جارٍ حفظ النتائج في السجل التاريخي":"Saving results to your history","اكتملت عملية القياس بنجاح":"Measurement completed successfully","تعذّر إكمال العملية":"Could not complete the measurement"
},
fr:{
"عرض سجل عناوين IP التفصيلي":"Afficher l’historique détaillé des IP publiques",
"عرض تفاصيل اختبارات الاتصال":"Afficher les détails des tests réseau",
"Internet connection intelligence · Algérie Télécom":"Analyse de connexion · Algérie Télécom",
"↻ Refresh":"↻ Actualiser","▶ Collect now":"▶ Tester maintenant","Collecting…":"Mesure en cours…",
"Current observed public IPv4":"Votre adresse IP publique","◉ Waiting for first observation":"◉ En attente du premier test",
"Last observation":"Dernière mesure","Changes are recorded automatically":"Votre connexion est surveillée automatiquement",
"Recorded observations":"Mesures enregistrées","Historical samples":"Historique des mesures","IP changes":"Changements d’IP","Detected between samples":"Depuis le début du suivi","Average latency":"Latence moyenne","Latest collection cycle":"Dernier test","Average packet loss":"Perte moyenne de paquets",
"Latency timeline":"Évolution de la latence","Response time to monitored targets over recent observations":"Temps de réponse des serveurs suivis","Latest target health":"État de la connexion","Latency and packet loss for the latest sample":"Latence et pertes lors du dernier test","Performance by IP group":"Performances par groupe IP","Compare observed groups using repeated measurements. Lower latency and packet loss are generally preferable.":"Comparez les groupes sur plusieurs tests. Une latence et des pertes plus faibles sont préférables.",
"IP group":"Groupe IP","Samples":"Mesures","Distinct IPs":"IP distinctes","Average loss":"Perte moyenne","Last observed":"Dernière mesure",
"Public IP history":"Historique des IP publiques","Each row is one collection cycle. Times are displayed in your browser's local timezone.":"Chaque ligne correspond à un test. Les heures suivent le fuseau de votre navigateur.",
"Probe details":"Détails des tests réseau","Latest ping results, including failures and packet loss":"Derniers résultats ping, y compris les échecs et pertes",
"Interpretation note: the displayed address is the public IPv4 seen by an external check service. If Algérie Télécom uses CGNAT, this can differ from the address assigned to the OPNsense WAN interface. The approximate /24 is a display grouping, not confirmation of the ISP's actual routed prefix.":"Remarque : l’adresse affichée est l’IPv4 publique vue par un service externe. Avec le CGNAT, elle peut différer de celle de l’interface WAN OPNsense. Le /24 est un regroupement indicatif, pas la route confirmée du fournisseur.",
"Waiting for first sample":"En attente de la première mesure","◉ No IP observed yet":"◉ Aucune IP détectée","Collector connected · automatic monitoring enabled":"Suivi actif · tests automatiques activés","Collector needs attention":"Le suivi nécessite une vérification","Could not load dashboard data":"Impossible de charger les données","Collection failed":"Échec de la mesure","Collection completed":"Mesure terminée",
"Loading group data…":"Chargement des groupes…","No groups recorded yet. Start a collection to begin.":"Aucun groupe. Lancez un premier test pour commencer.","No history yet.":"Aucun historique.","A target may ignore ICMP. Compare both targets and look at repeated results rather than one sample.":"Une cible peut ignorer ICMP. Comparez les deux cibles sur plusieurs tests, pas sur un seul.",
"Loading group data…":"Chargement des groupes…","Collecting measurements…":"Mesures en cours…","Latency chart will appear after the first successful ping.":"Le graphique apparaîtra après un premier test réussi.","No measurements yet":"Aucune mesure","No results for the latest sample yet.":"Aucun résultat pour le dernier test.","Recent records":"Derniers enregistrements",
"minutes · Data is retained on this server.":"minutes · Les données sont conservées sur ce serveur.",
"Collecting connection measurements":"Mesure de la connexion en cours",
"observed address changes since monitoring began":"changements d’adresse détectés depuis le début du suivi",
"جاهز لجمع البيانات":"Prêt à mesurer la connexion","جارٍ الاتصال بخدمة التحقق من عنوان الإنترنت":"Vérification de l’adresse IP publique","تم رصد عنوان الإنترنت؛ جارٍ تصنيف المجموعة":"IP détectée ; classement du groupe","جارٍ قياس زمن الاستجابة وفقدان الحزم":"Mesure de la latence et des pertes","جارٍ حفظ النتائج في السجل التاريخي":"Enregistrement des résultats","اكتملت عملية القياس بنجاح":"Mesure terminée avec succès","تعذّر إكمال العملية":"Impossible de terminer la mesure"
},
ar:{
"Internet connection intelligence · Algérie Télécom":"تحليل اتصال الإنترنت · اتصالات الجزائر",
"↻ Refresh":"↻ تحديث","▶ Collect now":"▶ ابدأ القياس الآن","Collecting…":"جارٍ القياس…",
"Current observed public IPv4":"عنوان الإنترنت العام الحالي","◉ Waiting for first observation":"◉ في انتظار أول قياس",
"Last observation":"آخر قياس","Changes are recorded automatically":"تتم مراقبة الاتصال تلقائيًا",
"Recorded observations":"القياسات المحفوظة","Historical samples":"سجل القياسات","IP changes":"تغيّرات عنوان IP","Detected between samples":"منذ بدء المراقبة","Average latency":"متوسط زمن الاستجابة","Latest collection cycle":"آخر اختبار","Average packet loss":"متوسط فقدان الحزم",
"Latency timeline":"تطور زمن الاستجابة","Response time to monitored targets over recent observations":"زمن الاستجابة للخوادم التي تتم مراقبتها","Latest target health":"حالة الاتصال","Latency and packet loss for the latest sample":"زمن الاستجابة وفقدان الحزم في آخر اختبار","Performance by IP group":"الأداء حسب مجموعة IP","Compare observed groups using repeated measurements. Lower latency and packet loss are generally preferable.":"قارن المجموعات عبر عدة اختبارات؛ انخفاض زمن الاستجابة وفقدان الحزم أفضل عادةً.",
"IP group":"مجموعة IP","Samples":"عدد القياسات","Distinct IPs":"عناوين IP مختلفة","Average loss":"متوسط الفقدان","Last observed":"آخر رصد",
"Public IP history":"سجل عناوين IP العامة","Each row is one collection cycle. Times are displayed in your browser's local timezone.":"يمثل كل صف اختبارًا واحدًا. يُعرض الوقت حسب المنطقة الزمنية للمتصفح.",
"Probe details":"تفاصيل اختبارات الاتصال","Latest ping results, including failures and packet loss":"أحدث نتائج Ping، بما فيها حالات الفشل وفقدان الحزم",
"Interpretation note: the displayed address is the public IPv4 seen by an external check service. If Algérie Télécom uses CGNAT, this can differ from the address assigned to the OPNsense WAN interface. The approximate /24 is a display grouping, not confirmation of the ISP's actual routed prefix.":"ملاحظة: العنوان المعروض هو عنوان IPv4 العام الذي تراه خدمة خارجية. عند استخدام CGNAT قد يختلف عن عنوان WAN في OPNsense. مجموعة ‎/24‎ تقريبية للعرض وليست تأكيدًا للمسار الفعلي لدى المزوّد.",
"Waiting for first sample":"في انتظار أول قياس","◉ No IP observed yet":"◉ لم يُرصد عنوان IP بعد","Collector connected · automatic monitoring enabled":"المراقبة نشطة · القياس التلقائي مفعّل","Collector needs attention":"تحتاج المراقبة إلى التحقق","Could not load dashboard data":"تعذّر تحميل بيانات لوحة التحكم","Collection failed":"فشل القياس","Collection completed":"اكتمل القياس",
"Loading group data…":"جارٍ تحميل بيانات المجموعات…","No groups recorded yet. Start a collection to begin.":"لا توجد مجموعات بعد. ابدأ أول اختبار للانطلاق.","No history yet.":"لا يوجد سجل بعد.","A target may ignore ICMP. Compare both targets and look at repeated results rather than one sample.":"قد لا يستجيب أحد الخوادم لطلبات ICMP. قارن نتائج الخادمين عبر عدة اختبارات بدلًا من الاعتماد على اختبار واحد.",
"Loading group data…":"جارٍ تحميل بيانات المجموعات…","Collecting measurements…":"جارٍ جمع القياسات…","Latency chart will appear after the first successful ping.":"سيظهر الرسم بعد نجاح أول اختبار.","No measurements yet":"لا توجد قياسات بعد","No results for the latest sample yet.":"لا توجد نتائج للاختبار الأخير بعد.","Recent records":"السجلات الأخيرة",
"minutes · Data is retained on this server.":"دقيقة · تُحفظ البيانات على هذا الخادم.",
"Collecting connection measurements":"جارٍ قياس الاتصال",
"observed address changes since monitoring began":"تغيّرًا في عنوان IP منذ بدء المراقبة",
"جاهز لجمع البيانات":"جاهز لقياس الاتصال","جارٍ الاتصال بخدمة التحقق من عنوان الإنترنت":"جارٍ التحقق من عنوان الإنترنت العام","تم رصد عنوان الإنترنت؛ جارٍ تصنيف المجموعة":"تم رصد العنوان؛ جارٍ تحديد مجموعته","جارٍ قياس زمن الاستجابة وفقدان الحزم":"جارٍ قياس زمن الاستجابة وفقدان الحزم","جارٍ حفظ النتائج في السجل التاريخي":"جارٍ حفظ النتائج في السجل","اكتملت عملية القياس بنجاح":"اكتمل القياس بنجاح","تعذّر إكمال العملية":"تعذّر إكمال القياس"
}};
const originalText=new WeakMap();
const originalSummary=new WeakMap();
function setLanguage(lang){
 if(!translations[lang])lang='en';
 document.documentElement.lang=lang;document.documentElement.dir=lang==='ar'?'rtl':'ltr';
 document.body.dir=lang==='ar'?'rtl':'ltr';
 document.querySelectorAll('.top,.brand,.actions,.statusline,.iphero,.panelhead,.target,.targetmetrics').forEach(el=>{el.style.direction=lang==='ar'?'rtl':'ltr'});
 document.querySelectorAll('th').forEach(el=>el.style.textAlign=lang==='ar'?'right':'left');
 document.querySelectorAll('td').forEach(el=>el.style.textAlign=lang==='ar'?'right':'left');
 const select=document.querySelector('#languageSelect');if(select&&select.value!==lang)select.value=lang;
 try{localStorage.setItem('dzra-language',lang)}catch(e){}
 translatePage(lang);
}
function translatePage(lang){
 const dict=translations[lang]||translations.en;
 const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
 let node;while(node=walker.nextNode()){
  if(!originalText.has(node))originalText.set(node,node.nodeValue);
  const original=originalText.get(node).trim();
  if(!original)continue;
  const translated=dict[original];
  if(translated){const leading=originalText.get(node).match(/^\s*/)?.[0]||'';const trailing=originalText.get(node).match(/\s*$/)?.[0]||'';const desired=leading+translated+trailing;if(node.nodeValue!==desired)node.nodeValue=desired;}
 }
 document.querySelectorAll('summary').forEach(el=>{
  if(!originalSummary.has(el))originalSummary.set(el,el.textContent.trim());
  const original=originalSummary.get(el);
  const translated=dict[original];
  if(translated&&el.textContent.trim()!==translated)el.textContent=translated;
 });
}
const languageObserver=new MutationObserver(records=>{if(records.some(r=>r.type==='childList')){const lang=document.documentElement.lang||'en';translatePage(lang)}});
languageObserver.observe(document.body,{childList:true,subtree:true});

async function get(path){const r=await fetch(path);const d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
function esc(v){return String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function n(v,d=1){return v==null?'—':Number(v).toFixed(d)}
function ms(v){return v==null?'—':n(v,2)+' ms'}
function pct(v){return v==null?'—':n(v,1)+'%'}
function date(v){if(!v)return '—';const d=new Date(v);return isNaN(d)?esc(v):d.toLocaleString([], {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'})}
function fullDate(v){if(!v)return '—';const d=new Date(v);return isNaN(d)?esc(v):d.toLocaleString()}
function cell(v,cls){return '<td'+(cls?' class="'+cls+'"':'')+'>'+esc(v)+'</td>'}
function renderChart(items){
 const el=document.querySelector('#chart');const ordered=items.slice().reverse();const valid=ordered.filter(x=>x.avg_ms!=null);
 document.querySelector('#sampleBadge').textContent=valid.length+' measurements';
 if(!valid.length){el.innerHTML='<div class="empty">Latency chart will appear after the first successful ping.</div>';return}
 const W=700,H=205,L=44,R=12,T=14,B=29,plotW=W-L-R,plotH=H-T-B;
 const max=Math.max(10,...valid.map(x=>Number(x.avg_ms)||0))*1.15;
 const grid=[0,.25,.5,.75,1].map(q=>{const y=T+plotH*q;return '<line x1="'+L+'" y1="'+y+'" x2="'+(W-R)+'" y2="'+y+'" stroke="#26354c" stroke-dasharray="3 5"/><text x="'+(L-8)+'" y="'+(y+4)+'" fill="#8092ad" font-size="10" text-anchor="end">'+n(max*(1-q),0)+'</text>'}).join('');
 const line=(target,color)=>{const vals=ordered.map((o,i)=>{const p=(o.probes||[]).find(z=>z.target===target&&z.avg_ms!=null);return p?{i,v:Number(p.avg_ms)}:null}).filter(Boolean);if(!vals.length)return '';const pts=vals.map(p=>(L+(ordered.length<2?plotW/2:p.i/(ordered.length-1)*plotW))+','+(T+plotH-(p.v/max*plotH))).join(' ');return '<polyline points="'+pts+'" fill="none" stroke="'+color+'" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>'+vals.map(p=>'<circle cx="'+(L+(ordered.length<2?plotW/2:p.i/(ordered.length-1)*plotW))+'" cy="'+(T+plotH-p.v/max*plotH)+'" r="3" fill="'+color+'" stroke="#111a2c" stroke-width="1.5"/>').join('')};
 const labels=ordered.length?'<text x="'+L+'" y="'+(H-7)+'" fill="#8092ad" font-size="10">'+esc(date(ordered[0].observed_at))+'</text><text x="'+(W-R)+'" y="'+(H-7)+'" fill="#8092ad" font-size="10" text-anchor="end">'+esc(date(ordered[ordered.length-1].observed_at))+'</text>':'';
 el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="Latency history chart">'+grid+line('1.1.1.1','#7aa7ff')+line('8.8.8.8','#62d8e8')+labels+'</svg>';
}
async function refreshProgress(){
 try{const p=await get('/api/progress');document.querySelector('#progressMessage').textContent=p.message||'جاهز لجمع البيانات';document.querySelector('#progressPercent').textContent=(p.percent||0)+'%';document.querySelector('#progressBar').style.width=(p.percent||0)+'%';document.querySelector('#progressIcon').textContent=p.active?'◌':'✓';document.querySelector('#progressIcon').style.color=p.active?'var(--cyan)':'var(--green)';}catch(e){}
}
async function refreshAll(){
 try{
 const [s,g,h,p]=await Promise.all([get('/api/status'),get('/api/groups'),get('/api/history?limit=60'),get('/api/probes?limit=120')]);
 const c=s.current||{},latest=h.items[0],latestProbes=p.items.filter(x=>latest&&x.observation_id===latest.id);
 document.querySelector('#currentIP').textContent=c.public_ip||'Waiting for first sample';
 document.querySelector('#currentGroup').textContent=c.ip_group?'◉ '+c.ip_group:'◉ No IP observed yet';
 document.querySelector('#currentTime').textContent=fullDate(c.observed_at);
 document.querySelector('#changeText').textContent=(s.ip_changes||0)+' observed address changes since monitoring began';
 document.querySelector('#observations').textContent=s.observations??0;
 document.querySelector('#changes').textContent=s.ip_changes??0;
 const good=latestProbes.filter(x=>x.avg_ms!=null),avg=good.length?good.reduce((a,x)=>a+Number(x.avg_ms),0)/good.length:null;
 const loss=latestProbes.filter(x=>x.loss_pct!=null),lossAvg=loss.length?loss.reduce((a,x)=>a+Number(x.loss_pct),0)/loss.length:null;
 document.querySelector('#avgLatency').textContent=ms(avg);document.querySelector('#avgLoss').textContent=pct(lossAvg);
 document.querySelector('#interval').textContent=s.interval_minutes||15;
 document.querySelector('#statusText').textContent=s.last_run&&s.last_run.status==='failed'?'Collector needs attention':'Collector connected · automatic monitoring enabled';
 document.querySelector('#statusDot').className='dot'+(s.last_run&&s.last_run.status==='failed'?' busy':'');
 document.querySelector('#updated').textContent='Updated '+new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
 document.querySelector('#targetList').innerHTML=latestProbes.map(x=>'<div class="target"><div><div class="targetname mono">'+esc(x.target)+'</div><div class="targetsub">'+(x.ok?'<span class="good">● Reachable</span>':'<span class="bad">● Incomplete</span>')+'</div></div><div class="targetmetrics"><strong>'+ms(x.avg_ms)+'</strong><small>Loss '+pct(x.loss_pct)+'</small></div></div>').join('')||'<div class="empty">No results for the latest sample yet.</div>';
 document.querySelector('#groups').innerHTML=g.items.map(x=>'<tr>'+cell(x.ip_group,'mono')+cell(x.samples)+cell(x.distinct_ips)+'<td class="barcell">'+ms(x.avg_ms)+'<div class="barbg"><div class="barfill" style="width:'+Math.max(0,Math.min(100,100-(Number(x.avg_ms)||0)*2))+'%"></div></div></td>'+cell(pct(x.avg_loss_pct),Number(x.avg_loss_pct)>0?'bad':'good')+cell(date(x.last_seen))+'</tr>').join('')||'<tr><td colspan="6" class="empty">No groups recorded yet. Start a collection to begin.</td></tr>';
 document.querySelector('#historyBadge').textContent=h.items.length+' recent records';
 document.querySelector('#history').innerHTML=h.items.map(x=>'<tr>'+cell(date(x.observed_at))+cell(x.public_ip,'mono')+cell(x.ip_group,'mono')+cell(x.prefix24,'mono')+cell(x.probe_count)+'</tr>').join('')||'<tr><td colspan="5" class="empty">No history yet.</td></tr>';
 document.querySelector('#probes').innerHTML=p.items.map(x=>'<tr>'+cell(date(x.tested_at))+cell(x.public_ip,'mono')+cell(x.target,'mono')+cell(ms(x.avg_ms))+cell((x.min_ms==null?'—':n(x.min_ms,2))+' / '+(x.max_ms==null?'—':n(x.max_ms,2))+' ms')+cell(pct(x.loss_pct),Number(x.loss_pct)>0?'bad':'good')+cell(ms(x.jitter_ms))+cell(x.ok?'OK':'Incomplete',x.ok?'good':'bad')+'</tr>').join('')||'<tr><td colspan="8" class="empty">No probe details yet.</td></tr>';
 renderChart(h.items.map(o=>{
  const probes=p.items.filter(x=>x.observation_id===o.id);
  const values=probes.filter(x=>x.avg_ms!=null).map(x=>Number(x.avg_ms));
  const avg_ms=values.length?values.reduce((sum,value)=>sum+value,0)/values.length:null;
  return {...o,avg_ms,probes};
 }));
 }catch(e){document.querySelector('#statusText').textContent='Could not load dashboard data';document.querySelector('#statusDot').className='dot busy';console.error(e)}
}
async function collect(){
 const b=document.querySelector('#collectBtn'),t=document.querySelector('#statusText');
 b.disabled=true;b.textContent='Collecting…';t.textContent='Collecting connection measurements';document.querySelector('#statusDot').className='dot busy';
 const poll=setInterval(refreshProgress,500);
 try{const d=await get('/api/collect');if(!d.ok&&d.message){t.textContent=d.message}else if(!d.ok){t.textContent='Collection failed'}else{t.textContent='Collection completed · '+d.public_ip}await refreshAll();await refreshProgress()}
 catch(e){t.textContent='Collection failed';document.querySelector('#progressMessage').textContent='تعذّر إكمال العملية'}
 finally{clearInterval(poll);b.disabled=false;b.textContent='▶ Collect now';document.querySelector('#statusDot').className='dot';}
}
let activeLanguage='en';try{activeLanguage=localStorage.getItem('dzra-language')||'en'}catch(e){}setLanguage(activeLanguage);
refreshAll();refreshProgress();setInterval(refreshAll,60000);setInterval(refreshProgress,1500);
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
    return {"app": APP_NAME, "version": "2.1.0", "mode": "native", "platform": "Debian LXC",
            "web_host": WEB_HOST, "web_port": WEB_PORT, "ping_count": PING_COUNT,
            "interval_minutes": AUTO_TEST_INTERVAL_MINUTES, "probe_targets": PROBE_TARGETS,
            "database": DB_PATH, "observations": count, "ip_changes": changes,
            "current": dict(current) if current else None, "last_run": dict(last_run) if last_run else None,
            "note": "Public IP observed by an external service; may differ from OPNsense WAN address under CGNAT.",
            "tools": {"ping": shutil.which("ping") is not None}}


@app.get("/api/progress")
def progress() -> dict[str, Any]:
    with progress_lock:
        return dict(collection_progress)


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
