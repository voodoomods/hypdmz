#!/bin/sh
# hypdmz-proxy entrypoint: fix data-dir ownership as root, then drop to the
# dedicated proxy UID. The pod's egress floor (controller/apply-lockdown.sh)
# grants upstream access to THIS UID only, so the proxy must never run as root
# or as the swarm's UID.
set -eu

PROXY_UID="${HYPDMZ_PROXY_UID:-1001}"

if [ "$(id -u)" = "0" ]; then
    # The control API's bearer token: a host-owned file mounted read-only. Read it here, as root, and hand it to
    # the dropped process through its environment (the proxy UID can't read a 0600 host file on Linux).
    TOKEN_FILE="${PROXY_CONSOLE_TOKEN_FILE:-/app/tokens/console.token}"
    if [ -r "$TOKEN_FILE" ]; then
        PROXY_CONSOLE_TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
        export PROXY_CONSOLE_TOKEN
        echo "[proxy] control API requires the bearer token from $TOKEN_FILE"
    else
        echo "[proxy] WARNING: no console token at $TOKEN_FILE — the control API is open on loopback"
    fi
    mkdir -p /app/data/audit /app/data/leaf-certs
    # Best-effort: bind mounts on Windows/macOS hosts ignore chown (and are
    # already world-writable); on Linux rootless podman this hands the data
    # directory to the proxy UID.
    chown -R "$PROXY_UID:$PROXY_UID" /app/data 2>/dev/null || true
    exec setpriv --reuid="$PROXY_UID" --regid="$PROXY_UID" --clear-groups \
        --inh-caps=-all --bounding-set=-all -- "$@"
fi
exec "$@"
