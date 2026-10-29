#!/bin/sh
# hypdmz-swarm entrypoint. Fail closed, then serve the record.
set -e

echo "[swarm] starting HypDMZ swarm container as $(id)"

# 1. Lockdown gate. hypdmz-controller publishes its state on 127.0.0.1:8009 only
#    after the UID-scoped egress floor is in place. Until it says LOCKED nothing
#    starts: no window in which the swarm could dial out directly.
#    HYPDMZ_LOCKDOWN_GATE=off only for image debugging outside the pod.
if [ "${HYPDMZ_LOCKDOWN_GATE:-on}" != "off" ]; then
    GATE_PORT="${HYPDMZ_LOCKDOWN_STATUS_PORT:-8009}"
    GATE_TIMEOUT="${HYPDMZ_LOCKDOWN_TIMEOUT_S:-60}"
    echo "[swarm] waiting for egress lockdown on 127.0.0.1:${GATE_PORT}..."
    i=0
    state=""
    while [ "$i" -lt "$GATE_TIMEOUT" ]; do
        state="$(curl -s --max-time 2 "telnet://127.0.0.1:${GATE_PORT}" </dev/null 2>/dev/null || true)"
        case "$state" in
            LOCKED*) break ;;
        esac
        i=$((i + 1))
        sleep 1
    done
    case "$state" in
        LOCKED*) echo "[swarm] lockdown confirmed: ${state}" ;;
        *)
            echo "[swarm] FATAL: egress lockdown not confirmed after ${GATE_TIMEOUT}s (got: '${state:-nothing}')." >&2
            echo "[swarm] refusing to start. Check: podman logs hypdmz-controller" >&2
            exit 1
            ;;
    esac
fi

# 2. The code the swarm runs is not the swarm's to change. Checked as the swarm
#    user with access(2), so read-only mounts that show as 777 on Windows pass.
CODE="/usr/local/lib/python3.12 /usr/local/bin /usr/local/lib/hypdmz /entrypoint.sh"
# shellcheck disable=SC2086
find $CODE ! -type l \( -perm -g+w -o -perm -o+w \) -exec chmod go-w {} + 2>/dev/null || true
# shellcheck disable=SC2086
writable="$(gosu swarm find $CODE ! -type l -writable -print 2>/dev/null | head -3)"
if [ -n "$writable" ]; then
    echo "[swarm] FATAL: the swarm user can write its own code; refusing to start:" >&2
    echo "$writable" | sed 's/^/[swarm]   /' >&2
    exit 1
fi

# 3. Trust the HypDMZ egress CA (the public certificate only — the key is the proxy's). The root filesystem is
#    read-only, so the bundle goes to /tmp (a size-capped tmpfs); the launcher points SSL_CERT_FILE,
#    REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE at the same path for `hypdmz run`'s exec'd processes.
CA_CERT=/etc/hypdmz-certs/hypdmz-ca-cert.pem
BUNDLE="${HYPDMZ_CA_BUNDLE:-/tmp/hypdmz-ca-bundle.crt}"
if [ -f "$CA_CERT" ]; then
    cat /etc/ssl/certs/ca-certificates.crt "$CA_CERT" > "$BUNDLE" && chmod 644 "$BUNDLE"
    export SSL_CERT_FILE="$BUNDLE" REQUESTS_CA_BUNDLE="$BUNDLE" CURL_CA_BUNDLE="$BUNDLE"
    echo "[swarm] trusting the HypDMZ egress CA via $BUNDLE"
else
    echo "[swarm] WARNING: no CA certificate at $CA_CERT — HTTPS through the proxy will fail"
fi
if awk '$2 == "/" && $4 ~ /(^|,)ro(,|$)/ { found = 1 } END { exit !found }' /proc/mounts; then
    echo "[swarm] root filesystem is read-only; writable: /records /work /tmp /home/swarm"
else
    echo "[swarm] WARNING: root filesystem is writable (started without --read-only?)"
fi

# 4. The swarm's own directories (best effort; Windows/macOS mounts ignore chown). /home/swarm is a tmpfs the
#    launcher mounts 0700; it arrives root-owned.
chown swarm:swarm /records /work /home/swarm 2>/dev/null || true
chown -R swarm:swarm /work 2>/dev/null || true

RECORD="${HYPDMZ_RECORD:-/records/swarm.hypgraph}"
echo "[swarm] proxy: HTTPS_PROXY=${HTTPS_PROXY}  model endpoint: ${OPENAI_BASE_URL}"
if [ ! -f "$RECORD" ]; then
    echo "[swarm] creating an empty record at ${RECORD}"
    gosu swarm python -c "from hypgraph import Graph; Graph('$RECORD')"
fi
echo "[swarm] serving ${RECORD} on :8000 (read-only UI; runs write the file directly)"
exec gosu swarm python -m hypgraph --db "$RECORD" serve --host 0.0.0.0 --port 8000 --no-browser
