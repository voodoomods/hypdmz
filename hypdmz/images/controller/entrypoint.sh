#!/bin/bash
# pod-controller entrypoint.
#
# 1. Apply the egress floor immediately — the rules don't depend on the proxy
#    being up, so there is no reason to leave a window open waiting for it.
# 2. Publish lockdown state on 127.0.0.1:${STATUS_PORT}. The agent container's
#    entrypoint blocks on this gate before starting uvicorn, so the agent
#    never runs without the floor in place (fail closed).
# 3. Every HEARTBEAT_S seconds, re-verify the rule set against the applied
#    fingerprint. On drift, log loudly and re-apply.
set -euo pipefail

STATUS_PORT="${HYPDMZ_LOCKDOWN_STATUS_PORT:-8009}"
HEARTBEAT_S="${HYPDMZ_LOCKDOWN_HEARTBEAT_S:-30}"
STATE_DIR=/run/hypdmz
STATE_FILE="$STATE_DIR/lockdown.state"
mkdir -p "$STATE_DIR"

echo "[controller] starting pod-controller..."
echo "[controller] capabilities: $(grep CapEff /proc/self/status)"

fingerprint() {
    { iptables -S OUTPUT; ip6tables -S OUTPUT 2>/dev/null || true; } | sha256sum | cut -c1-16
}

# Packets rejected by the two catch-all rules at the end of OUTPUT.
denied_count() {
    local ipt="$1"
    "$ipt" -L OUTPUT -n -v -x 2>/dev/null | tail -n 2 | awk '{s+=$1} END {print s+0}'
}

write_state() {
    local status="$1"
    # Atomic replace so the status listener never serves a half-written file.
    printf '%s fingerprint=%s applied_at=%s checked_at=%s denied_v4=%s denied_v6=%s\n' \
        "$status" "$FP" "$APPLIED_AT" "$(date -u +%FT%TZ)" \
        "$(denied_count iptables)" "$(denied_count ip6tables)" > "$STATE_FILE.tmp"
    mv "$STATE_FILE.tmp" "$STATE_FILE"
}

echo "[controller] applying iptables lockdown..."
if ! /controller/apply-lockdown.sh; then
    echo "[controller] FATAL: lockdown failed — refusing to signal ready." >&2
    echo "[controller] the agent container will not start." >&2
    exit 1
fi
FP="$(fingerprint)"
APPLIED_AT="$(date -u +%FT%TZ)"
write_state LOCKED
echo "[controller] lockdown applied (fingerprint $FP)."

# Lockdown gate / status endpoint. Plain TCP, one line, loopback only.
socat "TCP-LISTEN:${STATUS_PORT},bind=127.0.0.1,reuseaddr,fork" \
      "SYSTEM:cat $STATE_FILE" &
echo "[controller] lockdown status on 127.0.0.1:${STATUS_PORT}"

echo "[controller] entering verify loop (every ${HEARTBEAT_S}s)."
while true; do
    sleep "$HEARTBEAT_S"
    now="$(fingerprint)"
    if [ "$now" != "$FP" ]; then
        echo "[controller] WARNING: OUTPUT rules drifted ($FP -> $now); re-applying." >&2
        write_state DRIFT
        if /controller/apply-lockdown.sh >/dev/null; then
            FP="$(fingerprint)"
            APPLIED_AT="$(date -u +%FT%TZ)"
            echo "[controller] re-applied (fingerprint $FP)."
        else
            echo "[controller] FATAL: re-apply failed." >&2
            write_state BROKEN
            exit 1
        fi
    fi
    write_state LOCKED
done
