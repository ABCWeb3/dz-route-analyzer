from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

APP_NAME = "DZ Route Analyzer"
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8088"))
PING_COUNT = max(1, min(int(os.getenv("PING_COUNT", "10")), 30))
AUTO_TEST_INTERVAL_MINUTES = max(1, int(os.getenv("AUTO_TEST_INTERVAL_MINUTES", "15")))

app = FastAPI(title=APP_NAME, version="1.0.0")

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$")


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
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"Command timed out after {timeout} seconds",
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout": "",
            "stderr": "",
        }
    except OSError as exc:
        return {
            "ok": False,
            "error": f"Could not execute command: {exc}",
            "duration_ms": round((time.monotonic() - started) * 1000),
            "stdout": "",
            "stderr": "",
        }

    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "error": None if result.returncode == 0 else "Probe command failed; this is not automatically packet loss",
    }


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DZ Route Analyzer</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif}body{margin:0;background:#0b1220;color:#e5e7eb}
main{max-width:900px;margin:40px auto;padding:0 18px}h1{margin-bottom:6px}.muted{color:#9ca3af}
.card{background:#111c2f;border:1px solid #263449;border-radius:14px;padding:18px;margin:16px 0}
input,button{font:inherit;border-radius:8px;padding:10px;border:1px solid #34445c}
input{background:#0b1220;color:#fff;width:min(65%,360px)}button{background:#2563eb;color:white;cursor:pointer;margin:4px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080d16;padding:14px;border-radius:8px}
</style></head><body><main><h1>🇩🇿 DZ Route Analyzer</h1>
<p class="muted">Network diagnostics running directly on Debian — no Docker required.</p>
<section class="card"><h2>Service status</h2><button onclick="status()">Refresh status</button><pre id="status">Loading…</pre></section>
<section class="card"><h2>Ping test</h2><input id="host" value="1.1.1.1" aria-label="Host or IP address">
<button onclick="probe('ping')">Run Ping</button><button onclick="probe('traceroute')">Run Traceroute</button>
<pre id="result">Choose a test to begin.</pre></section>
<script>
async function status(){const el=document.querySelector('#status');el.textContent='Loading…';try{const r=await fetch('/api/status');el.textContent=JSON.stringify(await r.json(),null,2)}catch(e){el.textContent=String(e)}}
async function probe(kind){const el=document.querySelector('#result');el.textContent='Running…';try{const h=document.querySelector('#host').value;const r=await fetch('/api/'+kind+'?host='+encodeURIComponent(h));const data=await r.json();el.textContent=JSON.stringify(data,null,2)}catch(e){el.textContent=String(e)}}
status();
</script></main></body></html>"""


@app.get("/api/status")
def status() -> dict[str, Any]:
    return {
        "app": APP_NAME,
        "version": "1.0.0",
        "mode": "native",
        "platform": "Debian LXC",
        "web_host": WEB_HOST,
        "web_port": WEB_PORT,
        "ping_count": PING_COUNT,
        "auto_test_interval_minutes": AUTO_TEST_INTERVAL_MINUTES,
        "tools": {
            "ping": shutil.which("ping") is not None,
            "traceroute": shutil.which("traceroute") is not None,
            "tracepath": shutil.which("tracepath") is not None,
        },
    }


@app.get("/api/ping")
def ping(host: str = Query(default="1.1.1.1", min_length=1, max_length=253)) -> dict[str, Any]:
    host = validate_host(host)
    if not shutil.which("ping"):
        raise HTTPException(status_code=503, detail="ping is not installed")
    result = run_command(["ping", "-n", "-4", "-c", str(PING_COUNT), "-W", "2", host], timeout=PING_COUNT * 3 + 5)
    output = result["stdout"] + ("\n" + result["stderr"] if result["stderr"] else "")
    # Only report loss when ping produced its packet summary. Command/capability failures are errors.
    summary = re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received,\s*(\d+(?:\.\d+)?)% packet loss", output)
    if summary:
        result["packets_transmitted"] = int(summary.group(1))
        result["packets_received"] = int(summary.group(2))
        result["packet_loss_percent"] = float(summary.group(3))
        rtt = re.search(r"rtt min/avg/max(?:/mdev)? = ([\d.]+)/([\d.]+)/([\d.]+)", output)
        if rtt:
            result["rtt_ms"] = {"min": float(rtt.group(1)), "avg": float(rtt.group(2)), "max": float(rtt.group(3))}
    else:
        result["measurement"] = "unavailable"
    result["host"] = host
    result["output"] = output
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
