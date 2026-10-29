#!/bin/bash
# inspect-network.sh — dump pod network state for debugging

echo "=== iptables OUTPUT chain ==="
iptables -L OUTPUT -n -v 2>/dev/null || echo "(iptables unavailable)"

echo ""
echo "=== ip6tables OUTPUT chain ==="
ip6tables -L OUTPUT -n -v 2>/dev/null || echo "(ip6tables unavailable)"

echo ""
echo "=== lockdown state ==="
cat /run/hypdmz/lockdown.state 2>/dev/null || echo "(no state file — lockdown not applied)"

echo ""
echo "=== routing table ==="
ip route show 2>/dev/null || route -n

echo ""
echo "=== listening ports ==="
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "(ss/netstat unavailable)"

echo ""
echo "=== pod env (proxy) ==="
echo "HTTP_PROXY=${HTTP_PROXY}"
echo "HTTPS_PROXY=${HTTPS_PROXY}"
echo "NO_PROXY=${NO_PROXY}"
