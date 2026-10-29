"""
Outbound DLP scanner — proxy-side copy.

Same regex set as agent-image/app/dlp.py. Lives here so the proxy can
inspect plain-HTTP request bodies before forwarding them upstream. For
HTTPS CONNECT tunnels the bytes are TLS-encrypted at this layer; until
TLS-MITM (M4) lands, those flows must be DLP-scanned at the call site.

Modes (env DLP_MODE):
  - off    : disabled
  - audit  : log finding, allow request
  - block  : log finding, refuse request (caller returns 403)
"""

import os
import re
from dataclasses import dataclass


DLP_MODE = (os.getenv("DLP_MODE", "block") or "block").lower()


_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Key-shaped tokens must start at a token boundary: GPT-5 reasoning payloads
    # (encrypted_content) are long base64url blobs that contain "sk-<20 chars>"
    # by chance, and matching inside them blocked legitimate model traffic.
    # Anthropic first so "sk-ant-" isn't reported as an OpenAI key.
    ("anthropic_key",  re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key",     re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"
                                  r"|[A-Za-z0-9]{32,})")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat",     re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    ("github_token",   re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack_token",    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key",    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt",            re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("password_kv",    re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}")),
]


@dataclass
class DLPResult:
    finding: str
    snippet: str


def scan(content) -> DLPResult:
    if content is None or DLP_MODE == "off":
        return DLPResult("", "")
    try:
        text = content.decode("utf-8", errors="replace") if isinstance(content, (bytes, bytearray)) else str(content)
    except Exception:
        return DLPResult("", "")
    if not text:
        return DLPResult("", "")
    for name, pat in _PATTERNS:
        m = pat.search(text)
        if m:
            raw = m.group(0)
            snippet = (raw[:6] + "…" + raw[-4:]) if len(raw) > 12 else "***"
            return DLPResult(name, snippet)
    return DLPResult("", "")


def is_blocking() -> bool:
    return DLP_MODE == "block"
