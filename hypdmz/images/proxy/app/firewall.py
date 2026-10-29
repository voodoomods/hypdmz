"""
Firewall policy engine.

Loads rules from firewall.json (firewall_policy — hot-reloaded, fails closed). Evaluates:
  scheme → host → port → method → path_prefix → cidr_blocklist.
Default policy: DENY.

Host matching supports four mechanisms (any one matching is sufficient):
  - host          : exact hostname OR a glob pattern with '*' (e.g. '*.openai.com')
  - host_suffixes : list of suffixes; matches if hostname endswith any of them.
                    A leading '.' anchors the match at a label boundary.
                    e.g. ['.openai.com'] matches 'api.openai.com' but NOT 'evilopenai.com'.
  - host_regex    : full regex (re.fullmatch) — for advanced cases only.
  - hosts         : list of exact hostnames (sugar for OR-of-exacts).

If a rule defines multiple of these, ANY match is sufficient (logical OR).
If a rule defines NONE, the host check is treated as wildcard-allow for that field
(other rule fields still apply).
"""

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import firewall_policy
from . import request_gates


@dataclass
class FirewallVerdict:
    decision: str          # "allow" | "deny"
    matched_rule: str      # rule name or "default-deny" / "cidr-block" / "gate:*"
    reason: str
    injects: list[str] | None = None   # credential names to apply on allow
    guard: str = ""                    # e.g. "public_web" — inner requests must be inspectable


def _expired(expires_at: Optional[str]) -> bool:
    """Time-boxed rules stop matching once expired (fail closed on bad values)."""
    if not expires_at:
        return False
    try:
        ts = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= ts
    except ValueError:
        return True


def _load_policy() -> dict:
    try:
        return firewall_policy.get_policy()
    except Exception:
        # Fail closed — empty policy means default-deny everything.
        return {"rules": [], "cidr_blocklist": [], "default_policy": "deny",
                "error": "policy store unavailable — failing closed"}


def _in_cidr(ip_str: str, cidr_list: list[dict]) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in cidr_list:
        for cidr in entry.get("cidrs", []):
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass
    return False


def _suffix_match(host: str, suffix: str) -> bool:
    """Match `host` against a suffix.

    A leading '.' anchors the match at a DNS label boundary so that
    '.openai.com' matches 'api.openai.com' but not 'evilopenai.com'.
    Without a leading '.' the rule is permissive: 'openai.com' would
    match 'evilopenai.com' too — operators should prefer '.openai.com'
    for safety. We log this as a warning at evaluation time? Keep silent
    here; the pattern is the operator's call.
    """
    host = host.lower()
    suffix = suffix.lower()
    if not suffix:
        return False
    if suffix.startswith("."):
        return host == suffix[1:] or host.endswith(suffix)
    return host.endswith(suffix)


def _host_matches(rule: dict, host: str) -> bool:
    """Decide whether `host` satisfies the rule's host-matching predicates.

    Returns True if any of the configured host predicates match. If the
    rule defines none of host/hosts/host_suffixes/host_regex, returns
    True (wildcard for the host axis — other axes still apply).
    """
    host = (host or "").lower()
    have_predicate = False

    r_host = rule.get("host")
    if r_host:
        have_predicate = True
        rh = r_host.lower()
        if "*" in rh or "?" in rh or "[" in rh:
            if fnmatch.fnmatch(host, rh):
                return True
        elif rh == host:
            return True

    r_hosts = rule.get("hosts") or []
    if r_hosts:
        have_predicate = True
        if any(host == h.lower() for h in r_hosts):
            return True

    r_suffixes = rule.get("host_suffixes") or []
    if r_suffixes:
        have_predicate = True
        if any(_suffix_match(host, s) for s in r_suffixes):
            return True

    r_regex = rule.get("host_regex")
    if r_regex:
        have_predicate = True
        try:
            if re.fullmatch(r_regex, host, re.IGNORECASE):
                return True
        except re.error:
            # broken regex — fail closed for this predicate
            pass

    return not have_predicate


def evaluate(
    scheme: str,
    host: str,
    port: int,
    method: str,
    path: str,
    client_ip: Optional[str] = None,
    query: str = "",
) -> FirewallVerdict:
    policy = _load_policy()
    is_connect = method.upper() == "CONNECT"

    # 0. Request-shape gates that apply to every request.
    if not is_connect:
        why = request_gates.global_gate(path, query)
        if why:
            return FirewallVerdict("deny", f"gate:{why}", f"Request gate: {why}")

    # 1. CIDR blocklist — checked before allowlist
    cidr_list = policy.get("cidr_blocklist", [])
    if _in_cidr(host, cidr_list):
        return FirewallVerdict("deny", "cidr-block", f"Host IP {host} is in CIDR blocklist")
    if client_ip and _in_cidr(client_ip, cidr_list):
        return FirewallVerdict("deny", "cidr-block", f"Client IP {client_ip} is in CIDR blocklist")

    # 2. Allowlist rules
    for rule in policy.get("rules", []):
        if not rule.get("enabled", True):
            continue
        if _expired(rule.get("expires_at")):
            continue

        # scheme
        r_scheme = rule.get("scheme")
        if r_scheme and r_scheme != scheme:
            continue

        # host (exact | glob | suffix list | regex)
        if not _host_matches(rule, host):
            continue

        # port
        r_ports = rule.get("ports", [])
        if r_ports and port not in r_ports:
            continue

        # CONNECT tunnels: method/path checks don't apply here — the real
        # method and path are inside the TLS stream and re-evaluated after MITM.

        # method
        r_methods = rule.get("methods", [])
        if not is_connect and r_methods and method.upper() not in [m.upper() for m in r_methods]:
            continue

        # path prefix
        r_prefixes = rule.get("path_prefixes", [])
        if not is_connect and r_prefixes and not any(path.startswith(p) for p in r_prefixes):
            continue

        # Guarded rules (broad host access) also require a narrow request shape.
        guard = rule.get("guard") or ""
        if guard == "public_web":
            why = request_gates.public_web_gate(
                method=method, host=host, port=port, path=path, query=query,
                is_connect=is_connect)
            if why:
                return FirewallVerdict("deny", f"{rule['name']}:{why}",
                                       f"Rule '{rule['name']}' guard: {why}")

        # all checks passed
        return FirewallVerdict(
            "allow", rule["name"], f"Matched rule '{rule['name']}'",
            injects=rule.get("injects") or None, guard=guard,
        )

    # 3. Default deny — the audit log carries the denial; nothing else records it.
    return FirewallVerdict("deny", "default-deny", "No allowlist rule matched")
