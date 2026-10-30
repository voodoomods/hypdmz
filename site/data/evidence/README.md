# The evidence behind hypdmz.com

What the pod printed on 2026-10-29, captured as files. `dev/site_record.py` builds the page's HypGraph record from
these at every deploy: the measurements come from here, the reviewer re-measures them another way from the same
files, and the page's text is checked against the record (`hypgraph check`). Nothing on the page is typed in.

| file | what it is | how it was captured |
|---|---|---|
| `egress-check.json` | the 27 probes, lockdown state and the proxy's caps | `hypdmz egress-check --json` (20 probes run as the swarm user inside the swarm container, 7 from the host) |
| `status.json` | the proxy's status: TLS interception, policy, caps, vault count | `GET :8002/api/status` with the console token |
| `audit-verify.json` | the proxy's own walk of its audit chain | `GET :8002/api/audit/verify` |
| `proxy_events.jsonl` | the audit chain itself: one line per request, hash-chained | copied from `<state dir>/proxy-data/audit/` |
| `swarm-hostconfig.json` | the swarm container's limits as podman configured them | `podman inspect hypdmz-swarm`, `.HostConfig` (selected keys) |
| `swarm-env.json` | the swarm container's environment | `podman inspect hypdmz-swarm`, `.Config.Env` |
| `proxy-env.json` | the proxy's environment, the vault and token entries | `podman inspect hypdmz-proxy`, `.Config.Env` (selected keys) |
| `swarm.bundle.json` | the record the swarms wrote inside the pod, with their telemetry | `hypgraph export --telemetry` on `<state dir>/records/swarm.hypgraph` |

The audit lines carry hosts, methods, paths, status codes, sizes and the injected credential's *name*; no bodies, no
headers, no key. The environments carry a placeholder (`OPENAI_API_KEY=__hypdmz_inject__`) and the *path* to the
secret file, not its value.

To rebuild: `python dev/site_record.py` (add `--live` to have the reviewer re-run `egress-check` against a running
pod). The bundle lands in `site/data/site-record.bundle.json`, the figures in `site/assets/site-data.js`, and the page
as the check read it in `site/data/page-checked.md`.
