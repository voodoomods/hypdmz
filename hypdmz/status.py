"""`hypdmz status` — a fast snapshot: pod and container states, lockdown, endpoints."""
from __future__ import annotations

import json
import urllib.request

from hypdmz.env import Config
from hypdmz.platforms.base import run_capture
from hypdmz.runner import CONTAINERS, CONTROLLER, POD_NAME


def _pod_state() -> str:
    rc, out, _ = run_capture(["podman", "pod", "ps", "--filter", f"name=^{POD_NAME}$", "--format", "{{.Status}}"])
    return out.strip() or "absent" if rc == 0 else "unknown"


def _container(name: str) -> str:
    rc, out, _ = run_capture(["podman", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Status}}"])
    return out.strip() or "absent" if rc == 0 else "unknown"


def _lockdown() -> str:
    rc, out, _ = run_capture(["podman", "exec", CONTROLLER, "cat", "/run/hypdmz/lockdown.state"])
    return out.strip() if rc == 0 and out.strip() else "UNKNOWN"


def _http(url: str) -> dict | str:
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            body = r.read(4096)
            try:
                return json.loads(body)
            except Exception:
                return f"HTTP {r.status}"
    except Exception as e:
        return f"unreachable ({type(e).__name__})"


def cmd_status(cfg: Config, platform, *, json_output: bool = False) -> int:
    snap = {
        "pod": _pod_state(),
        "containers": {c: _container(c) for c in CONTAINERS},
        "lockdown": _lockdown(),
        "console": _http(f"http://127.0.0.1:{cfg.console_port}/api/status"),
        "record_ui": _http(f"http://127.0.0.1:{cfg.ui_port}/"),
    }
    if json_output:
        print(json.dumps(snap, indent=2))
    else:
        print(f"[hypdmz] pod: {snap['pod']}")
        for c, st in snap["containers"].items():
            print(f"  {c:20s} {st}")
        print(f"  lockdown: {snap['lockdown']}")
        con = snap["console"]
        if isinstance(con, dict):
            pol = con.get("policy", {})
            print(f"  console:  TLS interception {'on' if con.get('tls_interception') else 'OFF'} · "
                  f"{pol.get('enabled')}/{pol.get('rules')} rules · vault {con.get('vault', {}).get('credentials')} "
                  f"credential(s) · DLP {con.get('dlp_mode')}"
                  + (f" · POLICY ERROR: {pol['error']}" if pol.get("error") else ""))
        else:
            print(f"  console:  {con}")
        print(f"  record UI: {snap['record_ui'] if isinstance(snap['record_ui'], str) else 'up'}"
              f"  → http://127.0.0.1:{cfg.ui_port}")
    ok = snap["lockdown"].startswith("LOCKED") and isinstance(snap["console"], dict)
    return 0 if ok else 1
