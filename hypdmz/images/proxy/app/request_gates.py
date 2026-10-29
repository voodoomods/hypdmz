"""
Request-shape gates — checked before any allow rule.

Two layers:

  * Global gates (every request, every rule): oversized URLs and secrets in
    the URL itself (DLP over path + query). A credential has no business in a
    URL; vaulted credentials are injected as headers by the proxy.

  * The "public_web" guard (rules with guard="public_web", e.g. the
    time-boxed research window). Broad host access is only tolerable when the
    request shape is narrow, so these rules also require:
      - read-only methods (GET/HEAD; CONNECT only when the tunnel is MITM'd
        so the inner requests are re-checked);
      - a DNS hostname on port 443/80 — no IP literals;
      - the hostname resolves only to public addresses (no private, loopback,
        link-local, or metadata ranges);
      - no long opaque blobs (base64/hex runs) in path or query, and bounded
        query size — the usual shape of data being smuggled out in a URL.

Gates return a short reason string when a request should be denied, else "".
They never raise: a gate failure denies (fail closed).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time

from . import dlp

MAX_URL_LEN = 4096
MAX_QUERY_LEN = 1024
MAX_QUERY_PARAMS = 30
OPAQUE_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{160,}")
READ_ONLY = {"GET", "HEAD"}
WEB_PORTS = {80, 443}


def global_gate(path: str, query: str) -> str:
    try:
        if len(path) + len(query) > MAX_URL_LEN:
            return "url-too-long"
        hit = dlp.scan((path + "?" + query).encode())
        if hit.finding:
            return f"secret-in-url:{hit.finding}"
        return ""
    except Exception as e:
        return f"gate-error:{type(e).__name__}"


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


_DNS_TTL_S = 60.0
_dns_cache: dict[str, tuple[float, bool]] = {}


def _resolves_public(host: str) -> bool:
    """True if every address the host resolves to is public. Cached briefly so a
    name can't pass once and later rebind to a private address for long."""
    now = time.monotonic()
    hit = _dns_cache.get(host)
    if hit and now - hit[0] < _DNS_TTL_S:
        return hit[1]
    try:
        infos = socket.getaddrinfo(host, None)
        ok = bool(infos)
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                    or addr.is_reserved or addr.is_unspecified):
                ok = False
                break
    except (OSError, ValueError):
        ok = False
    if len(_dns_cache) > 2048:
        _dns_cache.clear()
    _dns_cache[host] = (now, ok)
    return ok


def public_web_gate(*, method: str, host: str, port: int, path: str, query: str,
                    is_connect: bool) -> str:
    try:
        if _is_ip_literal(host):
            return "guard:ip-literal-host"
        if port not in WEB_PORTS:
            return "guard:non-web-port"
        if not _resolves_public(host.lower()):
            return "guard:non-public-address"
        if is_connect:
            return ""   # inner requests are re-evaluated after TLS interception
        if method.upper() not in READ_ONLY:
            return "guard:read-only"
        if len(query) > MAX_QUERY_LEN:
            return "guard:query-too-long"
        if query and query.count("&") + 1 > MAX_QUERY_PARAMS:
            return "guard:too-many-params"
        if OPAQUE_RUN.search(path) or OPAQUE_RUN.search(query):
            return "guard:opaque-blob-in-url"
        return ""
    except Exception as e:
        return f"guard-error:{type(e).__name__}"
