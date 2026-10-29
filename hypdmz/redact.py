"""Secret redaction. Used by `hypdmz diagnose` and any code that writes
operator-visible bundles. The contract is one-way: redact wraps any string
that *looks* like a secret with `***SCRUBBED***`. False positives are
preferred over false negatives — a noisy log is fine, a leaked key is not."""
from __future__ import annotations

import re
from typing import Iterable

REDACTION = "***SCRUBBED***"

# Patterns are evaluated in order. Each replaces the matched group(s) with
# REDACTION while preserving surrounding context (so log lines stay readable).
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # OpenAI-style keys: sk-proj-, sk-, plus base58/base62 tail. Matches the
    # whole token including the prefix so we don't leave "sk-" dangling.
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"), REDACTION),
    # NVIDIA NIM keys.
    (re.compile(r"\bnvapi-[A-Za-z0-9_\-]{20,}\b"), REDACTION),
    # Generic bearer tokens. "Bearer <token>" or "Authorization: Bearer ..."
    (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9_\-\.]{20,})"), r"\1" + REDACTION),
    # `Authorization: <anything>` — covers Basic, Token, Bot, etc.
    (re.compile(r"(?i)(authorization:\s*)\S+"), r"\1" + REDACTION),
    # JSON / env-style key=value where the key looks secret-y.
    (re.compile(
        r"(?i)((?:api[_-]?key|access[_-]?token|secret|password|broker[_-]?token|"
        r"master[_-]?key|bot[_-]?token|private[_-]?key|client[_-]?secret)\s*[=:]\s*)"
        r"['\"]?([^\s'\",}]{6,})['\"]?"
    ), r"\1" + REDACTION),
    # URL-embedded credentials: https://user:pass@host
    (re.compile(r"(https?://)([^:/\s]+):([^@/\s]+)@"), r"\1\2:" + REDACTION + "@"),
    # Cookies: Set-Cookie or Cookie header values past the name.
    (re.compile(r"(?i)(set-cookie:|cookie:)\s*[^;\n\r]+"), r"\1 " + REDACTION),
    # Long base64url tokens (broker tokens are 64 chars). Heuristic: 32+
    # base64url chars surrounded by non-word boundaries.
    (re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_\-])"),
     REDACTION),
]

# Env var names whose VALUE we always replace, regardless of pattern.
# Used by redact_env_dict — covers cases where the value happens to be short
# (shouldn't trigger pattern matching) but is still secret.
ALWAYS_REDACT_KEYS: frozenset[str] = frozenset({
    "OPENAI_API_KEY",
    "NIM_API_KEY",
    "HYPDMZ_API_TOKEN",
    "PROXY_UI_TOKEN",
    "HYPDMZ_BROKER_TOKEN",
    "VAULT_BOOTSTRAP_OPENAI",
    "VAULT_BOOTSTRAP_NIM",
    "DEEPINFRA_API_KEY",
    "VAULT_BOOTSTRAP_DEEPINFRA",
    "VAULT_MASTER_KEY",
    "AUDIT_SINK_TOKEN",
})


def redact_text(text: str) -> str:
    """Apply every pattern in sequence to a chunk of text."""
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def redact_env_dict(env: dict[str, str]) -> dict[str, str]:
    """Sanitise a process-env-style dict for inclusion in a support bundle."""
    out: dict[str, str] = {}
    for k, v in env.items():
        if k in ALWAYS_REDACT_KEYS:
            out[k] = REDACTION if v else ""
            continue
        out[k] = redact_text(v)
    return out


def redact_lines(lines: Iterable[str]) -> list[str]:
    return [redact_text(line) for line in lines]
