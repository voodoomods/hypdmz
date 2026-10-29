# HypDMZ

Run a [HypSwarm](https://hypswarm.com) research swarm inside a governed-egress pod. The swarm's models, tools
and code run in a container that can reach exactly one thing: a proxy that allows the model API and nothing
else, holds the API key the swarm never sees, decrypts every request to check it, and writes a tamper-evident
log of all of it. The record the swarm builds is served live in the [HypGraph](https://hypgraph.com) UI.

Three containers in one Podman pod, sharing a network namespace:

```
hypdmz-pod
├── hypdmz-controller   NET_ADMIN · applies the UID-scoped iptables/ip6tables egress floor · lockdown gate on :8009
├── hypdmz-proxy        :8080 allowlisting TLS-intercepting forward proxy · :8002 control API · vault · audit chain
└── hypdmz-swarm        :8000 HypGraph UI on the record · `hypswarm` runs here as UID 1000 with loopback only
```

**The egress floor is keyed on socket owner UID, not port.** Only the proxy's UID (1001) may dial out. Every
other UID — the swarm, anything it spawns — gets loopback only, over IPv4 and IPv6, and cannot reach the
proxy's control port. The controller applies the rules before anything else starts, publishes `LOCKED` on
`127.0.0.1:8009`, and re-verifies the rule fingerprint every 30 s. The swarm container refuses to start until
the gate says `LOCKED`. `hypdmz up` ends by running `egress-check` from the swarm's own seat and stops the
swarm if any escape probe succeeds.

## Quick start

Needs Podman (Podman Desktop on Windows/macOS, `podman` on Linux) and Python 3.9+ on the host; nothing else.

```bash
pip install -e .                       # or: python -m hypdmz …
hypdmz doctor                          # prints the state dir; copy .env.example there as .env and set MODEL_API_KEY
hypdmz build                           # three images
hypdmz up                              # creates the CA, starts the pod, verifies the egress floor
hypdmz run examples/first-swarm --python --budget-usd 0.20
```

Then open http://127.0.0.1:8000 — the record, live, with the swarm's lanes. `hypdmz status`, `hypdmz logs`,
`hypdmz egress-check`, `hypdmz down`.

`hypdmz run <folder>` copies the folder (a `task.toml`, optional `seats.toml`, data files) into the pod and
runs `hypswarm run` there as the swarm user. `--python` gives the seats a Python tool that runs in the same
locked-down container. `--profile scientific|software|trading|knowledge|optimization` uses HypSwarm's rosters
instead of `seats.toml`. Every run is an investigation in the served record (`records/swarm.hypgraph` in the
state dir); `--record NAME` writes a separate file instead.

## What the swarm can and cannot do

| | |
|---|---|
| Reach the model API | yes — through the proxy, `MODEL_BASE_URL` only, inference paths only (`proxy/config/firewall.json`) |
| See the API key | no — it sends a placeholder; the proxy's vault (AES-256-GCM, master key in `proxy-data/`) adds the real one, scoped to the model host |
| Reach any other host, by name, by IP, over IPv6, via DNS | no — iptables owner match, verified by `egress-check` |
| Reach the proxy's control API | no — `:8002` is open to root and the proxy UID only |
| Read the TLS interception CA's private key | no — the swarm mounts the certificate alone |
| Rewrite its own code | no — root-owned, `go-w`, checked with `access(2)` as the swarm user at start |
| Send a secret out in a request | no — DLP over bodies and auth headers blocks it (`DLP_MODE=block`) |
| Do anything unlogged | no — every request, allowed or denied, is a line in a SHA-256 hash chain (`proxy-data/audit/`); optional remote sink |

The allowlist is a JSON file under version control, hot-reloaded (size + mtime, checked once a second). A
missing or malformed file denies everything. Rules carry host, ports, methods, path prefixes, an optional
`guard: "public_web"` request-shape gate, `expires_at`, and the vault credential names to inject.

## Layout

```
hypdmz/            host launcher (stdlib only): doctor · build · up · down · status · logs · debug · egress-check · run
controller/        egress floor (alpine + iptables): apply-lockdown.sh, lockdown gate, drift re-apply
proxy/             the proxy: app/{main,firewall,firewall_policy,request_gates,dlp,injection,vault,tls_mitm,audit}.py
proxy/config/      firewall.json — the policy
swarm/             the swarm image: hypswarm + hypgraph from PyPI, entrypoint with the gate + code check
examples/          first-swarm — a two-seat t-test with the python instrument
docs/DESIGN.md     what was taken from PegasusDMZ, what was left out, and why
```

State (secrets, records) lives outside the repo: `%USERPROFILE%\.hypdmz` on Windows,
`~/.local/state/hypdmz` on Linux, `~/Library/Application Support/HypDMZ` on macOS (`HYPDMZ_STATE_DIR` overrides).

## Control API (`:8002`, loopback only)

`GET /healthz` · `GET /api/status` · `GET /api/policy` · `GET /api/audit?n=` · `GET /api/audit/verify` ·
`GET /api/vault` · `POST /api/vault` `{name, value, type, injection_spec?, scope_host?}` · `DELETE /api/vault/{name}`.
A `Host` header that is not loopback, or a cross-origin state change, is refused.

## Using the pod's proxy from the host

The proxy is published on `127.0.0.1:8080` (`HYPDMZ_PROXY_PORT`). Host tools get the same governance:

```
HTTPS_PROXY=http://127.0.0.1:8080  SSL_CERT_FILE=<state dir>/certs/public/hypdmz-ca-cert.pem  OPENAI_API_KEY=__hypdmz_inject__
```
