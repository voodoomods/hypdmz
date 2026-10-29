"""
HypDMZ egress proxy.

Two listeners in one process, run as the proxy UID (the only UID the pod's
egress floor lets dial out):

  :8080  forward proxy — the swarm's HTTP_PROXY / HTTPS_PROXY. CONNECT is
         answered with a leaf certificate minted under the HypDMZ CA, so every
         HTTPS request is decrypted, checked against firewall.json (host, port,
         method, path, request shape), scanned for secrets (DLP), given its
         vaulted credential, forwarded, and written to the audit chain.
  :8002  control API — status, the policy as loaded, the audit tail, the
         vault (names only). Loopback only; the egress floor keeps the swarm
         UID off this port, and a non-loopback Host header is refused.

Everything the swarm sends out passes through here. Nothing else can.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import audit, dlp, firewall_policy, injection, tls_mitm, vault
from .firewall import evaluate

PROXY_PORT = int(os.getenv("PROXY_PORT", "8080"))
PLACEHOLDER = "__hypdmz_inject__"       # the swarm's OPENAI_API_KEY; the vault supplies the real one
PREVIEW_CAP = 64 * 1024                 # response bytes kept for inbound DLP

app = FastAPI(title="HypDMZ control", docs_url=None, redoc_url=None)


# ── control API (:8002) ────────────────────────────────────────────────

@app.middleware("http")
async def _loopback_only(request: Request, call_next):
    """DNS rebinding and cross-site defence: the console answers to loopback names only, and
    state changes must come from the console's own origin (or no origin: curl)."""
    host = (request.headers.get("host") or "").split(":")[0].strip("[]").lower()
    if host not in ("127.0.0.1", "localhost", "::1"):
        return PlainTextResponse("console is loopback-only", status_code=421)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        site = (request.headers.get("sec-fetch-site") or "").lower()
        origin = (request.headers.get("origin") or "").lower()
        if site in ("cross-site", "same-site") or (origin and urlparse(origin).hostname not in
                                                   ("127.0.0.1", "localhost", "::1")):
            return PlainTextResponse("cross-origin state change refused", status_code=403)
    return await call_next(request)


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "hypdmz-proxy", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/status")
def api_status():
    return {
        "proxy_port": PROXY_PORT,
        "tls_interception": tls_mitm.is_available(),
        "ca_fingerprint_sha256": tls_mitm.ca_fingerprint() if tls_mitm.is_available() else "",
        "dlp_mode": dlp.DLP_MODE,
        "policy": firewall_policy.status(),
        "vault": {"credentials": len(vault.list_credentials())},
        "audit": {"path": audit.AUDIT_PATH, "in_memory": len(audit.recent_events(audit.RING)),
                  "remote_sink": bool(audit.SINK_URL)},
    }


@app.get("/api/policy")
def api_policy():
    """The rules as loaded. Rules carry no secrets — credentials are vault names."""
    pol = firewall_policy.get_policy()
    return {"status": firewall_policy.status(), "rules": pol["rules"], "cidr_blocklist": pol["cidr_blocklist"]}


@app.get("/api/audit")
def api_audit(n: int = 200):
    return {"events": audit.recent_events(max(1, min(n, audit.RING)))}


@app.get("/api/audit/verify")
def api_audit_verify():
    return audit.verify()


@app.get("/api/vault")
def api_vault_list():
    return {"credentials": vault.list_credentials()}


@app.post("/api/vault")
async def api_vault_create(request: Request):
    """Store a credential: {name, value, type: bearer|header|query, injection_spec?, scope_host?, scope_path?}."""
    payload = await request.json()
    if not isinstance(payload, dict) or not payload.get("name") or not payload.get("value"):
        raise HTTPException(400, "name and value are required")
    try:
        return vault.create_credential(payload, actor="operator")
    except Exception as e:
        raise HTTPException(400, str(e))


@app.delete("/api/vault/{name}")
def api_vault_delete(name: str):
    for c in vault.list_credentials():
        if c["name"] == name:
            vault.delete_credential(c["id"], actor="operator")
            return {"deleted": name}
    raise HTTPException(404, "no such credential")


# ── upstream client ────────────────────────────────────────────────────

_UPSTREAM_CLIENT: httpx.AsyncClient | None = None


def _upstream_client() -> httpx.AsyncClient:
    global _UPSTREAM_CLIENT
    if _UPSTREAM_CLIENT is not None:
        return _UPSTREAM_CLIENT
    timeout = httpx.Timeout(
        connect=float(os.getenv("PROXY_UPSTREAM_CONNECT_TIMEOUT", "15")),
        read=float(os.getenv("PROXY_UPSTREAM_READ_TIMEOUT", "300")),
        write=float(os.getenv("PROXY_UPSTREAM_WRITE_TIMEOUT", "60")),
        pool=float(os.getenv("PROXY_UPSTREAM_POOL_TIMEOUT", "10")),
    )
    limits = httpx.Limits(
        max_connections=int(os.getenv("PROXY_UPSTREAM_MAX_CONNECTIONS", "100")),
        max_keepalive_connections=int(os.getenv("PROXY_UPSTREAM_MAX_KEEPALIVE", "20")),
        keepalive_expiry=float(os.getenv("PROXY_UPSTREAM_KEEPALIVE_EXPIRY", "30")),
    )
    transport = httpx.AsyncHTTPTransport(
        retries=int(os.getenv("PROXY_UPSTREAM_TRANSPORT_RETRIES", "2")),
        verify=True, http2=False, limits=limits,
    )
    _UPSTREAM_CLIENT = httpx.AsyncClient(timeout=timeout, transport=transport, follow_redirects=False)
    return _UPSTREAM_CLIENT


# Errors safe to retry IF no response bytes have been sent to the client yet.
_RETRYABLE_PRE_HEADER = (
    httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.PoolTimeout,
    httpx.WriteError, httpx.ReadError, ConnectionResetError, ConnectionAbortedError, ssl.SSLError,
)


# ── forward proxy (:8080) ──────────────────────────────────────────────

def _parse_request(raw: bytes) -> tuple[str, str, dict, bytes]:
    """Parse the first HTTP request out of `raw`. Returns (method, target, headers, body)."""
    head_blob, _, body_bytes = raw.partition(b'\r\n\r\n')
    lines = head_blob.split(b'\r\n')
    if not lines:
        return "", "", {}, b""
    first = lines[0].decode('utf-8', errors='replace')
    parts = first.split()
    if len(parts) < 3:
        return "", "", {}, b""
    method, target = parts[0], parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b':' in line:
            k, v = line.split(b':', 1)
            headers[k.decode().strip()] = v.decode().strip()
    return method, target, headers, body_bytes


async def _read_full_request(reader: asyncio.StreamReader, timeout: float = 30.0) -> bytes:
    """Read one HTTP/1.1 request (headers + Content-Length body if present)."""
    head = b""
    while b"\r\n\r\n" not in head:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError:
            return head
        if not chunk:
            return head
        head += chunk
        if len(head) > 1024 * 1024:  # 1 MB header cap
            return head

    head_blob, _, tail = head.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in head_blob.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode().strip().lower()] = v.decode().strip()
    body = tail
    cl = headers.get("content-length")
    if cl:
        try:
            need = int(cl) - len(body)
        except ValueError:
            need = 0
        while need > 0:
            try:
                chunk = await asyncio.wait_for(reader.read(min(65536, need)), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            body += chunk
            need -= len(chunk)
        return head_blob + b"\r\n\r\n" + body
    return head_blob + b"\r\n\r\n" + body


def _deny(writer: asyncio.StreamWriter, rule: str, reason: str) -> None:
    body = reason.encode()
    writer.write(
        b"HTTP/1.1 403 Forbidden\r\n"
        b"X-Proxy-Decision: deny\r\n"
        b"X-Proxy-Rule: " + rule.encode() + b"\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


HOP_REQ = {"connection", "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer",
           "transfer-encoding", "upgrade", "content-length", "host"}
HOP_RESP = {"transfer-encoding", "content-encoding", "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "trailer", "upgrade", "content-length"}


async def _proxy_one_exchange(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *,
                              scheme: str, host: str, port: int, client_ip: str, raw: bytes) -> bool:
    """Forward one request from `raw` and write the response back. Returns True to keep the connection."""
    t_start = time.monotonic()
    method, target, headers, body_bytes = _parse_request(raw)
    if not method:
        return False
    headers.pop('Proxy-Connection', None)

    # In MITM'd HTTPS the request line is path-only; in plain HTTP it's a full URL.
    if target.startswith('/'):
        parsed = urlparse(target)
        path = parsed.path or '/'
        host_header = headers.get('Host') or f"{host}:{port}"
        target_str = f"{scheme}://{host_header.split(':')[0]}:{port}{target}"
    else:
        parsed = urlparse(target)
        path = parsed.path or '/'
        target_str = target
    query = parsed.query or ""

    # ── firewall, now that method + path are known ──
    verdict = evaluate(scheme, host, port, method, path, client_ip, query=query)
    if verdict.decision == "deny":
        _deny(writer, verdict.matched_rule, verdict.reason)
        await writer.drain()
        audit.log_request(client_host=client_ip, method=method, url=target_str, host=host, port=port,
                          decision="deny", matched_rule=verdict.matched_rule, scheme=scheme, path=path,
                          req_body=body_bytes, latency_ms=int((time.monotonic() - t_start) * 1000))
        return False

    # ── DLP over the body and the sensitive headers ──
    dlp_finding = ""
    scan_payload = body_bytes + b"\n" + (headers.get("Authorization", "") + "\n" +
                                         headers.get("Cookie", "")).encode("utf-8", errors="replace")
    result = dlp.scan(scan_payload)
    if result.finding:
        dlp_finding = f"{result.finding}:{result.snippet}"
        if dlp.is_blocking():
            _deny(writer, "dlp:" + result.finding, f"DLP block: {result.finding}")
            await writer.drain()
            audit.log_request(client_host=client_ip, method=method, url=target_str, host=host, port=port,
                              decision="deny", matched_rule="dlp:" + result.finding, scheme=scheme, path=path,
                              dlp_finding=dlp_finding, req_body=body_bytes,
                              latency_ms=int((time.monotonic() - t_start) * 1000))
            return False

    # ── vaulted credentials (off the loop: the vault lives on a host mount) ──
    forward_headers, forward_url, applied = await asyncio.to_thread(
        injection.apply, cred_names=verdict.injects, host=host, path=path, headers=headers, url=target_str)
    if forward_headers.get("Authorization") == f"Bearer {PLACEHOLDER}":
        del forward_headers["Authorization"]          # the placeholder never leaves the pod
    forward_headers = {k: v for k, v in forward_headers.items() if k.lower() not in HOP_REQ}

    # ── forward upstream: streaming, retried only before any byte reached the client ──
    client = _upstream_client()
    max_retries = int(os.getenv("PROXY_UPSTREAM_RETRIES", "2"))
    backoff_ms = int(os.getenv("PROXY_UPSTREAM_RETRY_BACKOFF_MS", "300"))
    attempt = 0
    last_err: Exception | None = None
    status_written = False

    while True:
        try:
            async with client.stream(method=method, url=forward_url, headers=forward_headers,
                                     content=body_bytes if body_bytes else None) as resp:
                resp_headers_out = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_RESP}
                resp_headers_out["Connection"] = "close"     # no Content-Length → no pipelining
                status_line = f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n"
                blob = ''.join(f"{k}: {v}\r\n" for k, v in resp_headers_out.items())
                writer.write((status_line + blob + "\r\n").encode())
                status_written = True
                await writer.drain()

                preview = bytearray()
                body_size = 0
                # SSE clients hang up as soon as they read `data: [DONE]` — a finished exchange, not a failure.
                client_gone = False
                async for chunk in resp.aiter_bytes():
                    if not client_gone and writer.is_closing():
                        client_gone = True
                    if not client_gone:
                        writer.write(chunk)
                    body_size += len(chunk)
                    if len(preview) < PREVIEW_CAP:
                        preview.extend(chunk[:PREVIEW_CAP - len(preview)])
                if not client_gone:
                    try:
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                        client_gone = True

            dlp_out = ""
            try:
                resp_dlp = dlp.scan(bytes(preview))
                if resp_dlp.finding:
                    dlp_out = f"{resp_dlp.finding}:{resp_dlp.snippet}"
            except Exception:
                pass
            rule_label = verdict.matched_rule
            if attempt:
                rule_label = f"{rule_label} (retry={attempt})"
            if client_gone:
                rule_label = f"{rule_label} (client-closed)"
            audit.log_request(client_host=client_ip, method=method, url=target_str, host=host, port=port,
                              decision="allow", matched_rule=rule_label, scheme=scheme, path=path,
                              status_code=resp.status_code, bytes_out=body_size,
                              latency_ms=int((time.monotonic() - t_start) * 1000),
                              dlp_finding=dlp_finding, dlp_out=dlp_out, injected=applied or None,
                              req_body=body_bytes)
            return False
        except _RETRYABLE_PRE_HEADER as e:
            last_err = e
            if status_written or attempt >= max_retries:
                break
            attempt += 1
            delay = min(3.0, (backoff_ms / 1000.0) * (2 ** (attempt - 1)))
            print(f"[proxy] upstream {host}:{port} {type(e).__name__} attempt {attempt}/{max_retries}: "
                  f"{str(e)[:120]} — retrying in {delay:.2f}s")
            await asyncio.sleep(delay)
            continue
        except Exception as e:
            last_err = e
            break

    err = last_err if last_err is not None else RuntimeError("upstream failed")
    print(f"[proxy] upstream {host}:{port} failed after {attempt} retry(ies): {type(err).__name__}: {str(err)[:120]}")
    if not status_written:
        try:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
    audit.log_request(client_host=client_ip, method=method, url=target_str, host=host, port=port,
                      decision="allow", matched_rule=f"{verdict.matched_rule} (upstream-fail:{type(err).__name__})",
                      scheme=scheme, path=path, status_code=502,
                      latency_ms=int((time.monotonic() - t_start) * 1000), dlp_finding=dlp_finding,
                      req_body=body_bytes)
    return False


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    client_addr = writer.get_extra_info('peername')
    client_ip = client_addr[0] if client_addr else "unknown"
    t_start = time.monotonic()
    try:
        raw = await asyncio.wait_for(reader.read(65536), timeout=10)
        if not raw:
            return
        first_line = raw.split(b'\r\n')[0].decode('utf-8', errors='replace')
        parts = first_line.split()
        if len(parts) < 3:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return
        method, target = parts[0], parts[1]

        if method == 'CONNECT':
            host, port_str = target.rsplit(':', 1)
            port = int(port_str)

            # Host-only check; the path is unknowable until the tunnel is decrypted.
            verdict = evaluate("https", host, port, "CONNECT", "/", client_ip)
            if verdict.decision == "allow" and not tls_mitm.is_available():
                # No CA → nothing inside the tunnel could be checked. Refuse rather than pass bytes blind.
                verdict = type(verdict)("deny", f"{verdict.matched_rule}:no-tls-interception",
                                        "TLS interception is unavailable; opaque tunnels are not allowed")
            if verdict.decision == "deny":
                _deny(writer, verdict.matched_rule, verdict.reason)
                await writer.drain()
                audit.log_request(client_host=client_ip, method=method, url=target, host=host, port=port,
                                  decision="deny", matched_rule=verdict.matched_rule, scheme="https", path="/",
                                  latency_ms=int((time.monotonic() - t_start) * 1000))
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\nX-Proxy-Decision: allow\r\n\r\n")
            await writer.drain()

            # StreamWriter.start_tls() infers server_side from the protocol; passing it is a TypeError.
            try:
                leaf_ctx = tls_mitm.get_leaf_context(host)
                await writer.start_tls(leaf_ctx, ssl_handshake_timeout=10)
            except Exception as e:
                print(f"[proxy] TLS handshake with {client_ip} for {host} failed: {type(e).__name__}: {e}")
                audit.log_request(client_host=client_ip, method=method, url=target, host=host, port=port,
                                  decision="allow", matched_rule=f"{verdict.matched_rule} (tls-fail:{type(e).__name__})",
                                  scheme="https", path="/", status_code=525,
                                  latency_ms=int((time.monotonic() - t_start) * 1000))
                return

            while True:
                req = await _read_full_request(reader, timeout=60.0)
                if not req or b"\r\n\r\n" not in req:
                    return
                keep_alive = await _proxy_one_exchange(reader, writer, scheme="https", host=host, port=port,
                                                       client_ip=client_ip, raw=req)
                if not keep_alive:
                    return
        else:
            parsed = urlparse(target)
            host = parsed.hostname or ''
            port = parsed.port or 80
            await _proxy_one_exchange(reader, writer, scheme=parsed.scheme or "http", host=host, port=port,
                                      client_ip=client_ip, raw=raw)
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_proxy_server():
    server = await asyncio.start_server(handle_client, '0.0.0.0', PROXY_PORT)
    print(f"[proxy] listening on :{PROXY_PORT}")
    async with server:
        await server.serve_forever()


@app.on_event("startup")
async def startup():
    try:
        vault.init_db()
        print("[proxy] vault initialized")
    except Exception as e:
        print(f"[proxy] vault init error: {e}")
    if tls_mitm.is_available():
        print(f"[proxy] TLS interception on; CA {tls_mitm.ca_fingerprint()[:16]}…")
    else:
        print("[proxy] WARNING: no CA at HYPDMZ_CA_PEM — every HTTPS CONNECT will be refused")
    print(f"[proxy] policy: {firewall_policy.status()}")
    asyncio.create_task(start_proxy_server())
