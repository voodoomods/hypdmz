# Changelog

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
