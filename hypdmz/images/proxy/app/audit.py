"""
Proxy-side audit log: one JSONL file with a SHA-256 hash chain.

Every proxied request — allowed or denied — becomes one line. Each line's
`hash` covers the line's content and the previous line's hash, so a deleted or
edited line breaks the chain at the next event (`verify()` finds where).

Writes go through one ordered writer thread, never on the event loop (the
file sits on a host mount, where an append can take milliseconds). The last
2,000 events stay in memory for the control API. Optional remote sink:
AUDIT_SINK_URL (+ AUDIT_SINK_TOKEN) receives every event as JSON.

Bodies and headers are not written — the summary carries decision, rule,
host, method, path, status, sizes, latency, the DLP findings and which vaulted
credentials were injected (names only).
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

AUDIT_PATH      = os.getenv("PROXY_AUDIT_PATH", "/app/data/audit/proxy_events.jsonl")
CHAIN_HEAD_PATH = os.getenv("PROXY_AUDIT_HEAD_PATH", "/app/data/audit/.chain_head")
SINK_URL        = os.getenv("AUDIT_SINK_URL", "").strip()
SINK_TOKEN      = os.getenv("AUDIT_SINK_TOKEN", "").strip()
RING = 2000

_lock = threading.Lock()
_head: str | None = None
_ring: deque[dict] = deque(maxlen=RING)
_seq = 0
_q: "queue.Queue[Callable[[], None]]" = queue.Queue()
_writer: threading.Thread | None = None


def _load_head() -> str:
    global _head
    if _head is not None:
        return _head
    p = Path(CHAIN_HEAD_PATH)
    if p.exists():
        try:
            _head = p.read_text().strip() or "GENESIS"
        except Exception:
            _head = "GENESIS"
    else:
        _head = "GENESIS"
    return _head


def _hash_event(event: dict) -> str:
    canon = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _ensure_writer() -> None:
    global _writer
    if _writer is not None:
        return

    def _loop() -> None:
        while True:
            fn = _q.get()
            try:
                fn()
            except Exception as e:
                print(f"[proxy-audit] writer error: {e}")

    _writer = threading.Thread(target=_loop, name="audit-writer", daemon=True)
    _writer.start()


def _post_remote(event: dict) -> None:
    if not SINK_URL:
        return

    def _go() -> None:
        try:
            import httpx
            headers = {"content-type": "application/json"}
            if SINK_TOKEN:
                headers["authorization"] = f"Bearer {SINK_TOKEN}"
            httpx.post(SINK_URL, json=event, headers=headers, timeout=5)
        except Exception as e:
            print(f"[proxy-audit] remote forward error: {e}")

    threading.Thread(target=_go, daemon=True).start()


def log_request(
    client_host: str,
    method: str,
    url: str,
    host: str,
    port: int,
    decision: str,
    matched_rule: str,
    status_code: int = 0,
    bytes_out: int = 0,
    dlp_finding: str = "",
    *,
    scheme: str = "",
    path: str = "",
    latency_ms: int = 0,
    injected: list[str] | None = None,
    req_headers: dict | None = None,   # accepted for call-site parity; never written
    req_body: bytes | None = None,
    resp_headers: dict | None = None,
    resp_body: bytes | None = None,
    dlp_out: str = "",
) -> str:
    """Chain and queue one event. Returns the new chain head."""
    global _head, _seq
    event = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "client_host":  client_host,
        "method":       method,
        "url":          url,
        "host":         host,
        "port":         port,
        "scheme":       scheme,
        "path":         path,
        "decision":     decision,
        "matched_rule": matched_rule,
        "status_code":  status_code,
        "bytes_in":     len(req_body or b""),
        "bytes_out":    bytes_out,
        "latency_ms":   latency_ms,
        "injected":     injected or [],
        "dlp_finding":  dlp_finding,
        "dlp_out":      dlp_out,
    }
    with _lock:
        event["prev_hash"] = _load_head()
        event["hash"] = _hash_event(event)
        _head = event["hash"]
        _seq += 1
        event["id"] = _seq
        _ring.append(event)
        line = json.dumps(event) + "\n"
        head = event["hash"]

        def _append() -> None:
            p = Path(AUDIT_PATH)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                f.write(line)
            Path(CHAIN_HEAD_PATH).write_text(head)

        _ensure_writer()
        _q.put(_append)
    _post_remote(event)
    return head


def recent_events(n: int = 200) -> list[dict]:
    """Newest first: from memory, else the file's tail (after a restart)."""
    with _lock:
        if _ring:
            return list(reversed(list(_ring)))[:n]
    p = Path(AUDIT_PATH)
    if not p.exists():
        return []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return list(reversed(out))


def verify(path: str | None = None) -> dict:
    """Walk the file: every line's hash must cover its content and the previous hash."""
    p = Path(path or AUDIT_PATH)
    if not p.exists():
        return {"ok": True, "events": 0, "note": "no audit file yet"}
    prev = "GENESIS"
    n = 0
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except Exception:
            return {"ok": False, "events": n, "broken_at": lineno, "why": "not JSON"}
        if ev.get("prev_hash") != prev:
            return {"ok": False, "events": n, "broken_at": lineno, "why": "prev_hash does not match"}
        expect = _hash_event({k: v for k, v in ev.items() if k not in ("hash", "id")})
        if ev.get("hash") != expect:
            return {"ok": False, "events": n, "broken_at": lineno, "why": "hash does not match content"}
        prev = ev["hash"]
        n += 1
    return {"ok": True, "events": n, "head": prev}
