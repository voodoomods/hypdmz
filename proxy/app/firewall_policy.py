"""
Firewall policy source — one JSON file, hot-reloaded.

HypDMZ keeps the egress allowlist where it belongs: under version control, in
`firewall.json`, mounted read-only into the proxy. No database, no editing UI.
Change the file and the next request sees it (the file's size + mtime are
checked at most once a second).

A file that is missing or does not parse fails closed: an empty rule set, so
every request is denied until the file is fixed. The error is reported once
on the console and in `GET /api/policy`.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

CONFIG_PATH = os.getenv("FIREWALL_CONFIG", "/app/config/firewall.json")
CHECK_EVERY_S = 1.0

_EMPTY = {"rules": [], "cidr_blocklist": [], "default_policy": "deny"}

_lock = threading.Lock()
_policy: dict | None = None
_signature: tuple[int, int] | None = None   # (size, mtime_ns)
_checked_at = 0.0
_error = ""
_loaded_at = ""


def _read() -> tuple[dict, str]:
    p = Path(CONFIG_PATH)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return dict(_EMPTY), f"{CONFIG_PATH} not found — denying everything"
    except Exception as e:  # malformed JSON, encoding, permissions
        return dict(_EMPTY), f"{CONFIG_PATH} unreadable ({type(e).__name__}: {e}) — denying everything"
    if not isinstance(data, dict) or not isinstance(data.get("rules", []), list):
        return dict(_EMPTY), f"{CONFIG_PATH} has no 'rules' list — denying everything"
    rules = [r for r in data.get("rules", []) if isinstance(r, dict) and r.get("name")]
    return {
        "rules": rules,
        "cidr_blocklist": [c for c in data.get("cidr_blocklist", []) if isinstance(c, dict)],
        "default_policy": "deny",            # the only policy HypDMZ has
    }, ""


def get_policy() -> dict:
    """The current policy; re-read when the file changed (checked ≤ once a second)."""
    global _policy, _signature, _checked_at, _error, _loaded_at
    now = time.monotonic()
    with _lock:
        if _policy is not None and now - _checked_at < CHECK_EVERY_S:
            return _policy
        _checked_at = now
        try:
            st = os.stat(CONFIG_PATH)
            sig: tuple[int, int] | None = (st.st_size, st.st_mtime_ns)
        except OSError:
            sig = None
        if _policy is not None and sig == _signature and sig is not None:
            return _policy
        policy, err = _read()
        if err and err != _error:
            print(f"[firewall] {err}")
        _policy, _signature, _error = policy, sig, err
        _loaded_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return _policy


def status() -> dict:
    """What the control API reports: counts and the file's state, never the rules' secrets (there are none)."""
    pol = get_policy()
    return {
        "path": CONFIG_PATH,
        "rules": len(pol["rules"]),
        "enabled": sum(1 for r in pol["rules"] if r.get("enabled", True)),
        "cidr_blocks": len(pol["cidr_blocklist"]),
        "loaded_at": _loaded_at,
        "error": _error,
    }
