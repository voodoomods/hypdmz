# HypDMZ design

HypDMZ is the protection layer of PegasusDMZ, cut down to what a research swarm needs. PegasusDMZ grew into a
whole company of agents — broker, kanban, office, gym, research graph, lab, ledger. HypDMZ keeps the part that
makes an agent safe to run and drops the rest. One job: run `hypswarm` on a record, with the model API the
only thing it can reach, and prove it.

## What was taken, verbatim or nearly

| Piece | From | Change |
|---|---|---|
| Egress floor (`controller/`) | `controller-image/` | env prefix `HYPDMZ_`; state at `/run/hypdmz`. Rules unchanged: owner-UID match on OUTPUT, v4 + v6, DNS + upstream for the proxy UID only, loopback for the rest, `:8002` for root/proxy only, fingerprint re-verified every 30 s |
| Lockdown gate | agent entrypoint | the swarm entrypoint waits for `LOCKED` on `127.0.0.1:8009`, 60 s, then refuses |
| Forward proxy | `proxy-image/app/main.py` lines 5031–5513 | the ledger (metering, attribution headers) removed; everything else kept: CONNECT → leaf cert → per-request firewall → DLP → injection → streamed forward with pre-header retries → inbound DLP → audit; SSE client hang-up is a finished exchange |
| TLS interception (`tls_mitm.py`) | same | plus `init_ca()`: the launcher creates the CA with the proxy image's code on the first `up` instead of relying on a mitmproxy-made one |
| Firewall engine (`firewall.py`) | same | policy comes from `firewall_policy.py` (JSON file, hot-reloaded, fail-closed) instead of `firewall_db` |
| Request-shape gates, DLP, injection | same | unchanged |
| Vault (`vault.py`) | same | one bootstrap recipe (`model_api_key` from `VAULT_BOOTSTRAP_MODEL`, scoped to the model host); rule links live in `firewall.json`; no policy overrides |
| Audit chain (`audit.py`) | same shape | JSONL + hash chain + remote sink, with its own writer thread; no SQLite twin, no header/body previews on disk; `verify()` walks the chain |
| Code-is-not-the-agent's | agent entrypoint | the swarm entrypoint checks site-packages, `/usr/local/bin`, the probe helper and itself with `access(2)` as the swarm user |
| Privilege drops | both images | proxy: `setpriv` to 1001 with an empty bounding set; swarm: `gosu` to 1000, `--cap-drop ALL`, `SETUID`/`SETGID` only, `no-new-privileges` |
| Launcher | `pegasus/` | platforms and redaction copied; `env.py`, `runner.py`, `egress.py`, `status.py`, `doctor.py` rewritten small. Stdlib only |
| egress-check | `pegasus/egress.py` | the same probe shape; Pegasus-specific probes (broker, graph authors, policy API) replaced by: CA private key unreadable, own code unwritable, relay-to-console refused |

## What was left out, and why

- **Protocol broker, HITL gates, operator policy, locks** — they govern a general agent with shell, mail, SSH
  and databases. The swarm has one tool surface (HypSwarm's record tools and, with `--python`, a subprocess
  in the locked container). Governance of *what the swarm concludes* is the record's job (HypGraph refuses
  overclaims); governance of *where bytes go* is this pod's job. Nothing in between is needed.
- **Firewall database and editing UI** — the policy is a file in git. Reviewing a diff beats an admin page.
- **Ledger / pricing** — HypSwarm meters its own calls (`--budget-usd`, `--pricing`); the proxy's audit log
  has every call with sizes and latency if a second count is wanted.
- **Audit SQLite with request/response previews** — one chained file is simpler to verify and to ship to a
  sink; previews of model prompts on disk were a liability, not a feature.
- **Lab container, GPU, research graph in the proxy** — the record *is* the research graph (hypgraph), and it
  lives in the swarm container's `/records` mount, served by the same library.
- **Bridge, office, gym, meetings, company layer** — Pegasus's organisation; not protection.

## Layout: the launcher carries the pod

`pip install hypdmz` is the whole thing. The package `hypdmz/` holds the launcher and, as package data, the three
image build contexts (`hypdmz/images/{controller,proxy,swarm}`), the default policy
(`hypdmz/images/proxy/config/firewall.json`), the `.env` template and the bundled examples. `hypdmz build` builds
the images from those contexts; `hypdmz up` seeds the operator's policy into `<state dir>/policy/firewall.json` on
the first run and mounts that directory read-only into the proxy — after that the policy is the operator's
(`hypdmz policy show|path|reset`). Nothing is read from a repository checkout.

## Trust boundaries

```
host (operator)            pod network namespace                                      internet
──────────────             ───────────────────────────────────────────────────         ────────
hypdmz run ──podman exec──▶ hypdmz-swarm (UID 1000, loopback only)
                             │ HTTPS_PROXY=127.0.0.1:8080, OPENAI_API_KEY=placeholder
                             ▼
                            hypdmz-proxy (UID 1001, the only UID with egress) ───────▶ MODEL_BASE_URL host only
                             firewall.json · DLP · vault (key added here) · audit chain
                            hypdmz-controller (root, NET_ADMIN): iptables owner match; gate :8009
:8000 record UI ◀── published, loopback
:8002 control   ◀── published, loopback; refused from the swarm UID by the floor
```

The swarm container holds: hypswarm, hypgraph, the records mount, the work mount, the CA *certificate*. It
does not hold: the API key, the CA key, the vault, the audit log, the policy.

## The blast radius (added after the first live run)

Three things a hostile or runaway swarm process could still have done, each now a refusal with a probe:

- **Exhaust the machine.** The swarm container runs with `--read-only` (the CA bundle goes to a tmpfs `/tmp`),
  size-capped tmpfs for `/tmp` and `/home/swarm`, `--memory` (+ swap = same), `--cpus` and `--pids-limit`
  (`HYPDMZ_SWARM_*`). Probes `swarm-rootfs-readonly`, `swarm-memory-capped`, `swarm-pids-capped`,
  `swarm-cpu-capped` read the cgroup and `/proc/mounts` from inside. `/records` and `/work` are host bind
  mounts and cannot be size-capped by podman; that stays a limit.
- **Reach the other containers through shared kernel objects.** The pod shares only the network namespace (the
  egress floor works on it) and the hostname: `podman pod create --share net,uts`. Podman's default also shares
  IPC, which would put the swarm and the proxy in one SysV shared-memory and message-queue space; nothing used it,
  and now it isn't there. Probe `ipc-namespace-shared` compares the two containers' `/proc/self/ns/ipc` from the
  host. The pod never shared the PID namespace, so the swarm sees only its own processes.
- **Find something under `/run/secrets`.** Podman can add default mounts there (on Fedora-based podman machines,
  Red Hat subscription files: public CA certificates and a config file). The swarm is given no secrets, so it gets
  an empty read-only tmpfs at `/run/secrets` instead; the proxy keeps its own, where the model key's podman secret
  lands. Probe `run-secrets-empty` checks it from the swarm's seat.
- **Call the model without limit.** `proxy/app/limits.py`: sliding-hour caps on forwarded calls and request
  megabytes, over every rule, from `firewall.json → limits` (hot-reloaded). Past a cap: 429, audited as
  `limit:<cap>`. In memory, so a proxy restart resets the window. HypSwarm's own budget is the finer control;
  this one holds when the process is not the HypSwarm you started.
- **Read or change the proxy's state from the host.** The control API requires a bearer token (`hmac.compare_digest`)
  on everything but `/healthz`. The launcher generates it once into `<state dir>/tokens/console.token` (0600),
  mounts the dir read-only, and the proxy entrypoint reads it as root before dropping privileges. Probes
  `console-requires-token` (401 without) and `console-with-token` (200 with) run from the host.

## Known limits (honest)

- The API key's first mile is a podman secret (`hypdmz_llm_api_key`, `HYPDMZ_KEY_SECRET`), mounted into the
  proxy container as `/run/secrets/<name>` with mode 0400 for the proxy UID and read once into the vault; it is
  in no container's environment and not in `podman inspect`. The `.env` fallback (`MODEL_API_KEY`) still passes
  through `--env` and is visible in `inspect` until removed; the launcher says so and prefers the secret.
- On Windows and macOS the state dir is a 9p/virtiofs mount: file ownership is not enforced there, so the
  "swarm cannot read the CA key" guarantee rests on the swarm container mounting `certs/public/` only — which
  `egress-check` verifies — not on file modes.
- The record UI (`:8000`) is read-only (`hypgraph serve` without `--writable`); runs write the SQLite file
  directly from the same container. Anyone on the host loopback can read the record.
- One proxy identity: every run shares the same egress rules and key. Per-run keys would need per-run
  vault scopes; not built.
