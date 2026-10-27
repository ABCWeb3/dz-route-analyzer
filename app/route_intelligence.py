"""Route intelligence primitives for DZ Route Analyzer."""
from __future__ import annotations
import hashlib
import ipaddress
import re
import shutil
import subprocess
from typing import Any

ALLOWED_TARGETS = {"1.1.1.1", "8.8.8.8"}

def route_fingerprint(hops: list[dict[str, Any]]) -> str:
    path = ">".join(str(hop.get("ip") or "*") for hop in hops)
    return hashlib.sha256(path.encode("utf-8")).hexdigest()

def trace_route(target: str) -> dict[str, Any]:
    if target not in ALLOWED_TARGETS:
        raise ValueError("Target is not in the allowed target list")
    binary = shutil.which("traceroute")
    if not binary:
        raise RuntimeError("traceroute is not installed")
    result = subprocess.run(
        [binary, "-n", "-4", "-m", "20", "-q", "1", "-w", "1", target],
        capture_output=True, text=True, timeout=35, check=False,
    )
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    hops: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not match:
            continue
        number, rest = int(match.group(1)), match.group(2).strip()
        ip_match = re.search(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])", rest)
        rtt_match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*ms", rest)
        address = ip_match.group(1) if ip_match else None
        if address:
            try:
                ipaddress.ip_address(address)
            except ValueError:
                address = None
        hops.append({
            "hop_number": number, "ip": address,
            "rtt_ms": float(rtt_match.group(1)) if rtt_match else None,
            "responded": bool(address or rtt_match),
        })
    return {
        "target": target, "hops": hops,
        "fingerprint": route_fingerprint(hops), "hop_count": len(hops),
        "reached": any(hop["ip"] == target for hop in hops),
        "raw_error": "" if any(hop["ip"] for hop in hops) else output.strip()[-1000:],
    }
