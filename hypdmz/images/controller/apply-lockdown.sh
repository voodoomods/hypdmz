#!/bin/bash
# apply-lockdown.sh
# Applies the pod-level OUTPUT firewall (IPv4 + IPv6).
# Only the controller container has NET_ADMIN so only it can modify these rules.
#
# Threat model: every container in the pod shares ONE network namespace, so a
# port-based allowlist applies to every process in it — including the agent,
# which could simply ignore HTTP_PROXY and dial out directly. The floor is
# therefore keyed on socket owner UID:
#
#   PROXY_UID (mitm-proxy)  → may reach the outside world on the ports below.
#                             It is the only process that does; it enforces
#                             firewall.json for HTTP(S) and audits the broker.
#   everyone else           → loopback only. No DNS, no direct TCP/UDP/ICMP.
#   any UID except 0/proxy  → may NOT reach the proxy control API (:8002).
#                             Stops the agent rewriting its own firewall rules,
#                             reading the vault, or approving its own requests.
#
# Rejects (not drops) so blocked tools fail fast with "connection refused"
# instead of hanging until their timeout.
#
# Exits non-zero on any failure; entrypoint.sh treats that as fatal and the
# agent container refuses to start (it waits on the lockdown gate).

set -euo pipefail

PROXY_UID="${HYPDMZ_PROXY_UID:-1001}"
CONTROL_PORT="${HYPDMZ_CONTROL_PORT:-8002}"

# TCP ports the proxy process may dial upstream.
#   443/80        HTTP(S) egress, filtered by firewall.json
#   587 465 25    SMTP            993 143   IMAP        995 110  POP3
#   22            SSH/SFTP        21 20 + 10000:10100  FTP (+ passive range)
#   5432 3306 6379  Postgres / MySQL / Redis           389 636  LDAP
# (iptables multiport takes at most 15 ports per rule, hence two groups.)
PROXY_TCP_PORTS_WEB_MAIL="443,80,587,465,25,993,143,995,110"
PROXY_TCP_PORTS_INFRA="22,21,20,5432,3306,6379,389,636"
PROXY_TCP_RANGES="10000:10100"

apply_family() {
    local ipt="$1"

    # Policy DROP *before* flushing so there is no open window mid-apply.
    "$ipt" -P OUTPUT DROP
    "$ipt" -F OUTPUT

    # Replies to inbound connections (host → :8000 / :8002) and to the
    # proxy's own upstream sockets.
    "$ipt" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Proxy control API: only root (controller probes, rootless port
    # forwarder) and the proxy itself. Not interface-scoped — the pod's own
    # eth0 address also routes via lo.
    "$ipt" -A OUTPUT -p tcp --dport "$CONTROL_PORT" -m owner --uid-owner 0 -j ACCEPT
    "$ipt" -A OUTPUT -p tcp --dport "$CONTROL_PORT" -m owner --uid-owner "$PROXY_UID" -j ACCEPT
    "$ipt" -A OUTPUT -p tcp --dport "$CONTROL_PORT" -j REJECT --reject-with tcp-reset

    # Intra-pod traffic: proxy :8080, broker :8003, agent UI :8000, etc.
    "$ipt" -A OUTPUT -o lo -j ACCEPT

    # Upstream egress — proxy UID only.
    "$ipt" -A OUTPUT -m owner --uid-owner "$PROXY_UID" -p udp --dport 53 -j ACCEPT
    "$ipt" -A OUTPUT -m owner --uid-owner "$PROXY_UID" -p tcp --dport 53 -j ACCEPT
    "$ipt" -A OUTPUT -m owner --uid-owner "$PROXY_UID" -p tcp \
        -m multiport --dports "$PROXY_TCP_PORTS_WEB_MAIL" -j ACCEPT
    "$ipt" -A OUTPUT -m owner --uid-owner "$PROXY_UID" -p tcp \
        -m multiport --dports "$PROXY_TCP_PORTS_INFRA" -j ACCEPT
    "$ipt" -A OUTPUT -m owner --uid-owner "$PROXY_UID" -p tcp \
        --dport "$PROXY_TCP_RANGES" -j ACCEPT

    # Everything else: fail fast. Packet counters on these two rules are the
    # "blocked egress attempts" figure surfaced by `hypdmz status`.
    "$ipt" -A OUTPUT -p tcp -j REJECT --reject-with tcp-reset
    "$ipt" -A OUTPUT -j REJECT
}

echo "[lockdown] applying IPv4 floor (proxy uid=${PROXY_UID})..."
apply_family iptables

if ip6tables -L OUTPUT -n >/dev/null 2>&1; then
    echo "[lockdown] applying IPv6 floor..."
    apply_family ip6tables
elif [ -s /proc/net/if_inet6 ]; then
    # IPv6 is live but we can't filter it — that's an open side door.
    echo "[lockdown] FATAL: IPv6 is enabled but ip6tables is unusable." >&2
    exit 1
else
    echo "[lockdown] IPv6 disabled in this namespace; skipping."
fi

echo "[lockdown] final IPv4 OUTPUT chain:"
iptables -S OUTPUT
echo "[lockdown] final IPv6 OUTPUT chain:"
ip6tables -S OUTPUT 2>/dev/null || true

echo "[lockdown] complete."
