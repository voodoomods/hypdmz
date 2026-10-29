"""
Caps on what leaves, per hour, over every rule: calls and request bytes.

HypSwarm enforces its own budget on itself; this is the pod's cap on the swarm's *process*, for the case where
that process is not the HypSwarm you started. The numbers live in firewall.json under "limits" and hot-reload
with it:

    "limits": {"calls_per_hour": 1200, "megabytes_per_hour": 300}

A missing key means no cap on that axis. A request over a cap is refused with 429 and audited as a denial
(`limit:calls_per_hour`). The window is sliding (the last 3,600 s), kept in memory: a proxy restart resets it,
which is the conservative direction for a cap on the swarm but not a guarantee against one.
"""

from __future__ import annotations

import threading
import time
from collections import deque

WINDOW_S = 3600.0

_lock = threading.Lock()
_calls: deque[float] = deque()                 # monotonic times of forwarded calls
_bytes: deque[tuple[float, int]] = deque()     # (time, request bytes) of forwarded calls
_bytes_total = 0


def _prune(now: float) -> None:
    global _bytes_total
    while _calls and now - _calls[0] > WINDOW_S:
        _calls.popleft()
    while _bytes and now - _bytes[0][0] > WINDOW_S:
        _bytes_total -= _bytes.popleft()[1]


def check_and_count(limits: dict, request_bytes: int) -> str:
    """Count this call unless it crosses a cap. Returns "" (counted) or the cap it would cross."""
    global _bytes_total
    cph = int(limits.get("calls_per_hour") or 0)
    mbph = float(limits.get("megabytes_per_hour") or 0)
    now = time.monotonic()
    with _lock:
        _prune(now)
        if cph and len(_calls) >= cph:
            return "calls_per_hour"
        if mbph and _bytes_total + request_bytes > mbph * 1_000_000:
            return "megabytes_per_hour"
        _calls.append(now)
        _bytes.append((now, request_bytes))
        _bytes_total += request_bytes
    return ""


def status(limits: dict) -> dict:
    now = time.monotonic()
    with _lock:
        _prune(now)
        return {
            "calls_per_hour": int(limits.get("calls_per_hour") or 0) or None,
            "megabytes_per_hour": float(limits.get("megabytes_per_hour") or 0) or None,
            "last_hour": {"calls": len(_calls), "megabytes": round(_bytes_total / 1_000_000, 3)},
        }
