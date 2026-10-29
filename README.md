# HypDMZ

Run a [HypSwarm](https://hypswarm.com) research swarm inside a governed-egress pod. The swarm's models, tools
and code run in a container that can reach exactly one thing: a proxy that allows the model API and nothing
else, holds the API key the swarm never sees, decrypts every request to check it, caps what leaves per hour,
and writes a tamper-evident log of all of it. The record the swarm builds is served live in the
[HypGraph](https://hypgraph.com) UI. Every start ends with the swarm trying to escape, from its own seat, and the
pod refusing to run if it can. [hypdmz.com](https://hypdmz.com) shows the measures and the proof.

```
hypdmz-pod  (one Podman pod, one network namespace)
├── hypdmz-controller   NET_ADMIN · applies the UID-scoped iptables/ip6tables egress floor · lockdown gate on :8009
├── hypdmz-proxy        :8080 allowlisting TLS-intercepting forward proxy · :8002 control API · vault · audit chain · hourly caps
└── hypdmz-swarm        :8000 HypGraph UI on the record · `hypswarm` runs here as UID 1000: loopback only, read-only root, capped
```

**The egress floor is keyed on socket owner UID, not port.** Only the proxy's UID (1001) may dial out. Every
other UID — the swarm, anything it spawns — gets loopback only, over IPv4 and IPv6, and cannot reach the
proxy's control port. The controller applies the rules before anything else starts, publishes `LOCKED` on
`127.0.0.1:8009`, and re-verifies the rule fingerprint every 30 s. The swarm container refuses to start until
the gate says `LOCKED`. `hypdmz up` ends by running `egress-check` from the swarm's own seat and stops the
swarm if any escape probe succeeds.

## Quick start

Needs Podman on the host (Podman Desktop on Windows and macOS, `podman` on Linux) and Python 3.9+. The launcher
has no dependencies; the three image build contexts, the default policy and an example ride inside the package.

```bash
pip install hypdmz
hypdmz init                                  # the state dir and its .env; prints what comes next
podman secret create hypdmz_llm_api_key -    # paste the model API key; it reaches the proxy only, as a file
hypdmz doctor
hypdmz build                                 # three images, from the package's own contexts
hypdmz up                                    # creates the CA, starts the pod, vaults the key, verifies the egress floor
hypdmz run first-swarm --python --budget-usd 0.20
```

Then open http://127.0.0.1:8000 — the record, live, with the swarm's lanes. `hypdmz status`, `hypdmz logs`,
`hypdmz egress-check`, `hypdmz down`.

`hypdmz run <folder>` copies a folder (a `task.toml`, optional `seats.toml`, data files) into the pod and runs
`hypswarm run` there as the swarm user; a bundled example's name works too (`hypdmz example` lists them,
`hypdmz example first-swarm ./mine` copies one out to edit). `--python` gives the seats a Python tool inside the
locked container. `--profile scientific|software|trading|knowledge|optimization` uses HypSwarm's rosters instead
of `seats.toml`. Every run is an investigation in the served record (`records/swarm.hypgraph` in the state dir);
`--record NAME` writes a separate file instead.

## What the swarm can and cannot do

| | |
|---|---|
| Reach the model API | yes — through the proxy, `MODEL_BASE_URL`'s host only, inference paths only (`hypdmz policy`) |
| See the API key | no — it sends a placeholder; the proxy's vault (AES-256-GCM, master key in `proxy-data/`) adds the real one, scoped to the model host. The key arrives as a podman secret mounted into the proxy alone (mode 0400, proxy UID), never in an environment |
| Reach any other host, by name, by IP, over IPv6, via DNS | no — iptables owner match, verified by `egress-check` |
| Reach the proxy's control API | no — `:8002` is open to root and the proxy UID only; from the host it needs a bearer token |
| Read the TLS interception CA's private key | no — the swarm mounts the certificate alone |
| Rewrite its own code | no — root-owned, `go-w`, checked with `access(2)` as the swarm user at start |
| Send a secret out in a request | no — DLP over bodies and auth headers blocks it (`DLP_MODE=block`) |
| Call the model without limit | no — the proxy caps forwarded calls and request megabytes per sliding hour (`limits` in the policy; 429 past the cap, audited) |
| Exhaust the machine | no — read-only root filesystem, size-capped `/tmp` and home, memory, CPU and process-count limits on the container; only `/records` and `/work` persist |
| Do anything unlogged | no — every request, allowed or denied, is a line in a SHA-256 hash chain (`proxy-data/audit/`); optional remote sink |

## The policy is a file

`hypdmz up` seeds `<state dir>/policy/firewall.json` from the package's default on the first run; after that it is
yours. The proxy hot-reloads it (size + mtime, checked once a second). A missing or malformed file denies
everything. Rules carry host, ports, methods, path prefixes, an optional `guard: "public_web"` request-shape gate,
`expires_at`, and the vault credential names to inject; `limits` holds the hourly caps. `hypdmz policy` shows it,
`hypdmz policy path` says where it is, `hypdmz policy reset` restores the default (keeping a `.bak`).

## Layout

```
hypdmz/                the launcher (stdlib only): init · doctor · build · up · down · status · logs · debug · egress-check · run · policy · example
hypdmz/images/         the three build contexts, shipped in the wheel: controller (egress floor), proxy, swarm
hypdmz/images/proxy/config/firewall.json   the default policy
hypdmz/examples/       first-swarm — a two-seat t-test with the python instrument
hypdmz/env.example     the .env template `hypdmz init` writes
tests/                 the launcher without podman (configuration, payload, policy seed, the command lines it would run)
docs/DESIGN.md         what was taken from PegasusDMZ, what was left out, the blast radius, the limits
```

State (secrets, policy, records) lives outside the package and outside any repository: `%USERPROFILE%\.hypdmz` on
Windows, `~/.local/state/hypdmz` on Linux, `~/Library/Application Support/HypDMZ` on macOS (`HYPDMZ_STATE_DIR`
overrides). `.env` keys: `MODEL_BASE_URL`, `MODEL`, `HYPDMZ_UI_PORT` / `HYPDMZ_CONSOLE_PORT` / `HYPDMZ_PROXY_PORT`,
`HYPDMZ_SWARM_MEMORY` / `_CPUS` / `_PIDS` / `_TMP`, `HYPDMZ_KEY_SECRET`, `HYPDMZ_RECORDS_DIR`, `DLP_MODE`,
`AUDIT_SINK_URL` / `AUDIT_SINK_TOKEN`.

## Control API (`:8002`, loopback only, bearer token)

`GET /healthz` · `GET /api/status` · `GET /api/policy` · `GET /api/audit?n=` · `GET /api/audit/verify` ·
`GET /api/vault` · `POST /api/vault` `{name, value, type, injection_spec?, scope_host?}` · `DELETE /api/vault/{name}`.
Everything but `/healthz` needs `Authorization: Bearer <token>`; the token is generated once into
`<state dir>/tokens/console.token` (0600) and mounted read-only into the proxy. `hypdmz status` prints the
`curl` line. A `Host` header that is not loopback, or a cross-origin state change, is refused as well.

## Using the pod's proxy from the host

The proxy is published on `127.0.0.1:8080` (`HYPDMZ_PROXY_PORT`). Host tools get the same governance:

```
HTTPS_PROXY=http://127.0.0.1:8080  SSL_CERT_FILE=<state dir>/certs/public/hypdmz-ca-cert.pem  OPENAI_API_KEY=__hypdmz_inject__
```

## Status

Alpha, private beta. Verified on Windows 11 (Podman Desktop, WSL2); the Linux and macOS paths are written and
untested. Known limits are on [hypdmz.com](https://hypdmz.com#limits) and in `docs/DESIGN.md`.
