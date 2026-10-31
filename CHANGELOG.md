# Changelog

## Unreleased

- **hypgraph 0.7.12** in the swarm image (was 0.7.7) and in the site build (was 0.7.10), and a test keeps the two
  equal. 0.7.8–0.7.12 bring pinned references between records, blind work orders and their seal, and the
  pre-launch trust-boundary fixes (same-origin writes, reviewer names need a named token, `verify --head`).
  Checked on this machine: the pod comes up on the new image with all 27 `egress-check` probes passing, the
  existing record (323 events) verifies with the same head, scripted swarms settle inside the image with no
  network, and the site record builds with 0 copy errors.
- **The proxy is hardened like the swarm.** `--cap-drop ALL` plus only SETUID, SETGID, SETPCAP and CHOWN (the entrypoint
  drops to the proxy UID and empties the bounding set), `no-new-privileges`, a read-only root with `/tmp` as the only
  scratch space. Four `egress-check` probes read the proxy's process from the host: UID 1001, no capabilities,
  NoNewPrivs, read-only root.
- **Pinned supply chain.** The three images pin their base by the digest of its multi-arch index, and the proxy's
  Python packages are pinned to exact versions with the sha256 of every published file (`--require-hashes`). A hash
  that doesn't match fails the build.
- **No shared IPC namespace** (`--share net,uts`), and the swarm gets an empty read-only `/run/secrets`, hiding podman's
  default mounts there. Probes `ipc-namespace-shared` and `run-secrets-empty`.
- **`egress-check` reads "missing" honestly:** a probe that never reported fails the check but is not called a
  bypass. 27 probes in all.

## 0.1.0a3 — 2026-10-30

- **Licensed.** 0.1.0a1 and 0.1.0a2 went to PyPI without a licence file or field, so they carried no licence grant
  and no warranty disclaimer. This release ships `LICENSE` (Apache-2.0, like HypGraph, HypSwarm and HypMesh) and
  `NOTICE` (VoodooMods LLC), and the wheel declares `License-Expression: Apache-2.0`.
- **A disclaimer** (`DISCLAIMER.md`, a section on hypdmz.com and its own page at hypdmz.com/disclaimer/): provided as
  is; HypDMZ reduces what an agent can reach and does not make running untrusted code safe; a passing egress check
  shows its probes were blocked, not that no bypass exists; tested where the site says, unverified elsewhere; alpha,
  not independently audited.
- **`egress-check` says what it showed.** Its success line read "the swarm cannot bypass the proxy". It now says
  every bypass the check tries was blocked, and that a route it does not try is not tested. `hypdmz up` ends with
  one line on what the pod does and does not promise.

## 0.1.0a2 — 2026-10-29

- **The record UI answers browsers.** The swarm image now pins hypgraph 0.7.7, whose `serve` bound to `0.0.0.0`
  accepts the loopback names. With 0.7.6 every request through the published port (`Host: 127.0.0.1:<port>`)
  got a 421, so `http://127.0.0.1:8000` refused browsers while the egress probes still passed. A test keeps the
  pin at 0.7.7 or later.
- **Python 3.10 is the floor** (`requires-python >=3.10`; 3.9 is end of life). 0.1.0a1 declared `>=3.9`.

## 0.1.0a1 — 2026-10-29

First alpha. `pip install hypdmz` carries the pod: the controller, proxy and swarm build contexts, the default
policy and an example ride in the wheel. `init`, `doctor`, `build`, `up`, `down`, `status`, `logs`, `debug`,
`egress-check` (21 probes from the swarm's seat), `run`, `policy`, `example`. The model key is a podman secret;
the swarm runs read-only with capped memory, CPU and processes; the proxy caps calls and bytes per hour; the
control API needs a bearer token.
