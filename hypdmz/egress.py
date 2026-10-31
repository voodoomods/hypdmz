"""`hypdmz egress-check` — prove the egress floor holds, from the swarm's seat.

Runs a fixed battery of escape attempts *as the swarm user inside the swarm container*
and asserts each one is blocked, plus a few positive controls so the check can't pass
because networking is simply dead.

  blocked  — must fail. A success here means the swarm can bypass the proxy.
  control  — must succeed. A failure means the pod is broken (or the host is offline).

Exit codes: 0 all probes passed · 1 at least one failed · 2 pod not running.
`hypdmz up` runs this automatically and stops the swarm container on a bypass.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Optional

from hypdmz.env import Config
from hypdmz.platforms.base import run_capture

SWARM_CONTAINER = "hypdmz-swarm"
CONTROLLER_CONTAINER = "hypdmz-controller"
SWARM_USER = "swarm"

_CURL = "curl -s -o /dev/null --max-time 5 -w '%{http_code}'"


@dataclass(frozen=True)
class Probe:
    name: str
    kind: str          # "blocked" | "control"
    command: str       # sh snippet; prints an HTTP code or ok/fail
    description: str
    # For "blocked" probes against a server that legitimately answers (the proxy): an HTTP
    # error code counts as blocked; only a 2xx/3xx is a breach.
    http_error_is_blocked: bool = False


def probes(cfg: Config) -> tuple[Probe, ...]:
    return (
        Probe("direct-https-by-name", "blocked", f"{_CURL} --noproxy '*' https://example.com",
              "HTTPS to a public hostname, ignoring HTTPS_PROXY"),
        Probe("direct-https-by-ip", "blocked", f"{_CURL} --noproxy '*' -k https://1.1.1.1",
              "HTTPS straight to an IP (no DNS needed)"),
        Probe("direct-http-by-ip", "blocked", f"{_CURL} --noproxy '*' http://1.1.1.1",
              "Plain HTTP straight to an IP"),
        Probe("direct-ipv6", "blocked", f"{_CURL} -6 --noproxy '*' -k 'https://[2606:4700:4700::1111]'",
              "HTTPS over IPv6"),
        Probe("direct-dns-public", "blocked", "python /usr/local/lib/hypdmz/probe_dns.py 1.1.1.1",
              "DNS query to a public resolver (an exfiltration channel)"),
        Probe("pod-resolver-dns", "blocked",
              "getent hosts example.com >/dev/null 2>&1 && echo ok || echo fail",
              "DNS via the pod's configured resolver"),
        Probe("proxy-control-api", "blocked", f"{_CURL} --noproxy '*' http://127.0.0.1:8002/healthz",
              "The proxy's control API on :8002 (policy, vault, audit)"),
        Probe("proxy-denies-unlisted", "blocked", f"{_CURL} -x http://127.0.0.1:8080 https://example.com",
              "A host not in firewall.json, through the proxy", http_error_is_blocked=True),
        Probe("proxy-relay-to-console", "blocked",
              f"NO_PROXY= no_proxy= {_CURL} --noproxy '' -x http://127.0.0.1:8080 http://127.0.0.1:8002/healthz",
              "Reach the control API by relaying through the proxy", http_error_is_blocked=True),
        Probe("ca-private-key", "blocked",
              "[ -r /etc/hypdmz-certs/hypdmz-ca.pem ] && echo ok || echo fail",
              "Read the egress CA's private key (only the proxy holds it)"),
        Probe("run-secrets-empty", "blocked",
              "[ -n \"$(ls -A /run/secrets 2>/dev/null)\" ] && echo ok || echo fail",
              "Find anything under /run/secrets (podman's default mounts land there; the swarm is given none)"),
        Probe("swarm-code-write", "blocked",
              "d=\"$(python -c 'import hypswarm,os;print(os.path.dirname(hypswarm.__file__))')\"; "
              "[ -w \"$d/run.py\" ] || [ -w \"$d\" ] || [ -w /entrypoint.sh ] && echo ok || echo fail",
              "Write its own code (hypswarm, the entrypoint)"),
        # ── the blast radius: what the swarm's process is allowed to consume and change ──
        Probe("swarm-rootfs-readonly", "control",
              "awk '$2 == \"/\" && $4 ~ /(^|,)ro(,|$)/ { f = 1 } END { exit !f }' /proc/mounts && echo ok || echo fail",
              "The container's root filesystem is mounted read-only"),
        Probe("swarm-memory-capped", "control",
              "v=$(cat /sys/fs/cgroup/memory.max 2>/dev/null); [ -n \"$v\" ] && [ \"$v\" != max ] && echo ok || echo fail",
              "A memory limit is set on the container's cgroup"),
        Probe("swarm-pids-capped", "control",
              "v=$(cat /sys/fs/cgroup/pids.max 2>/dev/null); [ -n \"$v\" ] && [ \"$v\" != max ] && echo ok || echo fail",
              "A process-count limit is set on the container's cgroup"),
        Probe("swarm-cpu-capped", "control",
              "v=$(cut -d' ' -f1 /sys/fs/cgroup/cpu.max 2>/dev/null); [ -n \"$v\" ] && [ \"$v\" != max ] && echo ok || echo fail",
              "A CPU quota is set on the container's cgroup"),
        Probe("lockdown-gate", "control",
              "curl -s --max-time 2 telnet://127.0.0.1:8009 </dev/null 2>/dev/null | grep -q '^LOCKED' && echo ok || echo fail",
              "The controller reports LOCKED on the gate"),
        Probe("record-ui", "control", f"{_CURL} --noproxy '*' http://127.0.0.1:8000/",
              "The record UI answers on :8000"),
        Probe("proxy-listener", "control", f"{_CURL} --noproxy '*' http://127.0.0.1:8080/",
              "The proxy answers on :8080"),
        Probe("proxy-upstream", "control", f"{_CURL} -x http://127.0.0.1:8080 {cfg.model_base_url}/models",
              f"The model host through the proxy ({cfg.model_host}; the proxy UID has egress)"),
    )


@dataclass
class ProbeResult:
    name: str
    kind: str
    passed: bool
    observed: str
    description: str


@dataclass
class EgressReport:
    lockdown_state: str
    results: list[ProbeResult]
    error: Optional[str] = None
    caps: Optional[dict] = None     # the proxy's hourly caps and the last hour's use

    @property
    def ok(self) -> bool:
        return self.error is None and self.lockdown_state.startswith("LOCKED") and all(r.passed for r in self.results)

    @property
    def bypass_found(self) -> bool:
        # a probe that never reported ("missing") fails the check but proves no bypass
        return any(not r.passed and r.observed != "missing" for r in self.results if r.kind == "blocked")


def lockdown_state() -> str:
    rc, out, _ = run_capture(["podman", "exec", CONTROLLER_CONTAINER, "cat", "/run/hypdmz/lockdown.state"])
    if rc != 0:
        return "UNKNOWN (controller not running or lockdown never applied)"
    return out.strip() or "UNKNOWN (empty state file)"


def _wait_for_ui(*, deadline_s: int) -> None:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        rc, out, _ = run_capture(["podman", "exec", "-u", SWARM_USER, SWARM_CONTAINER, "sh", "-c",
                                  f"{_CURL} --noproxy '*' http://127.0.0.1:8000/"])
        if out.strip() not in ("", "000"):
            return
        time.sleep(1)


def _succeeded(observed: str) -> bool:
    if observed == "ok":
        return True
    if observed.isdigit():
        return observed != "000"
    return False


def _passed(probe: Probe, observed: str) -> bool:
    if observed == "missing":          # a probe that never reported proved nothing
        return False
    if probe.kind == "control":
        return _succeeded(observed)
    if probe.http_error_is_blocked:
        return not (observed.isdigit() and 200 <= int(observed) < 400)
    return not _succeeded(observed)


def run_check(cfg: Config, *, wait_for_lock_s: int = 20) -> EgressReport:
    state = lockdown_state()
    deadline = time.monotonic() + wait_for_lock_s
    while not state.startswith("LOCKED") and time.monotonic() < deadline:
        time.sleep(1)
        state = lockdown_state()
    _wait_for_ui(deadline_s=wait_for_lock_s + 30)

    ps = probes(cfg)
    script = "\n".join(f"printf '%s|%s\\n' {p.name} \"$({p.command} 2>/dev/null || true)\"" for p in ps)
    rc, out, err = run_capture(["podman", "exec", "-u", SWARM_USER, SWARM_CONTAINER, "sh", "-c", script])
    if rc != 0 and not out.strip():
        return EgressReport(state, [], error=(err.strip() or f"podman exec exit {rc}"))
    observed: dict[str, str] = {}
    for line in out.splitlines():
        name, _, value = line.partition("|")
        observed[name.strip()] = value.strip() or "000"
    results = [ProbeResult(p.name, p.kind, _passed(p, observed.get(p.name, "missing")),
                           observed.get(p.name, "missing"), p.description) for p in ps]
    results += console_checks(cfg)
    results += namespace_checks()
    results += proxy_checks()
    return EgressReport(state, results, caps=console_caps(cfg))


def _console_get(cfg: Config, path: str, token: str | None) -> int:
    """HTTP status of GET <console>/path from the host, with or without the bearer token (0 = unreachable)."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(f"http://127.0.0.1:{cfg.console_port}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def console_checks(cfg: Config) -> list[ProbeResult]:
    """Run from the host: the control API must refuse a request without the token and answer one with it."""
    tok = cfg.console_token()
    without = _console_get(cfg, "/api/status", None)
    with_tok = _console_get(cfg, "/api/status", tok) if tok else 0
    return [
        ProbeResult("console-requires-token", "blocked", without == 401, "missing" if without == 0 else str(without),
                    "Control API without the bearer token (from the host)"),
        ProbeResult("console-with-token", "control", with_tok == 200, "missing" if with_tok == 0 else str(with_tok),
                    f"Control API with the token from {cfg.console_token_path.name}"),
    ]


def _ns(container: str, kind: str) -> str:
    rc, out, _ = run_capture(["podman", "exec", container, "readlink", f"/proc/self/ns/{kind}"])
    return out.strip() if rc == 0 else ""


def namespace_checks() -> list[ProbeResult]:
    """Run from the host: the swarm and the proxy must not share an IPC namespace (SysV shared memory, semaphores and
    message queues would be a channel between them). They do share the network namespace, on purpose."""
    swarm, proxy = _ns(SWARM_CONTAINER, "ipc"), _ns("hypdmz-proxy", "ipc")
    shared = bool(swarm) and swarm == proxy
    observed = "shared" if shared else ("separate" if swarm and proxy else "missing")
    return [ProbeResult("ipc-namespace-shared", "blocked", observed == "separate", observed,
                        "The swarm and the proxy in one IPC namespace (from the host)")]


PROXY_UID = 1001


def proxy_checks() -> list[ProbeResult]:
    """Run from the host, read inside the proxy: its main process must run as the proxy UID with no capabilities
    and no way to gain any, on a read-only root filesystem. The proxy holds the key; this is its blast radius."""
    script = ("awk '/^Uid:/{print \"uid|\"$2} /^CapEff:/{print \"caps|\"$2} /^NoNewPrivs:/{print \"nnp|\"$2}' /proc/1/status; "
              "awk '$2 == \"/\" && $4 ~ /(^|,)ro(,|$)/ { f = 1 } END { print \"rootfs|\" (f ? \"ro\" : \"rw\") }' /proc/mounts")
    rc, out, _ = run_capture(["podman", "exec", "hypdmz-proxy", "sh", "-c", script])
    seen = dict(line.split("|", 1) for line in out.splitlines() if "|" in line) if rc == 0 else {}
    uid, caps, nnp, rootfs = seen.get("uid", ""), seen.get("caps", ""), seen.get("nnp", ""), seen.get("rootfs", "")
    return [
        ProbeResult("proxy-not-root", "control", uid == str(PROXY_UID), uid or "missing",
                    f"The proxy's main process runs as UID {PROXY_UID}, not root (from the host)"),
        ProbeResult("proxy-no-capabilities", "control", bool(caps) and set(caps) == {"0"}, caps or "missing",
                    "The proxy's process holds no capabilities (CapEff is zero)"),
        ProbeResult("proxy-no-new-privileges", "control", nnp == "1", nnp or "missing",
                    "The proxy's process cannot gain privileges (NoNewPrivs)"),
        ProbeResult("proxy-rootfs-readonly", "control", rootfs == "ro", rootfs or "missing",
                    "The proxy container's root filesystem is mounted read-only"),
    ]


def console_caps(cfg: Config) -> dict:
    """The proxy's hourly caps and the last hour's use, for the report header."""
    import urllib.request
    tok = cfg.console_token()
    if not tok:
        return {}
    req = urllib.request.Request(f"http://127.0.0.1:{cfg.console_port}/api/status",
                                 headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.load(r).get("limits") or {}
    except Exception:
        return {}


def report_dict(report: EgressReport) -> dict:
    return {"ok": report.ok, "bypass_found": report.bypass_found, "lockdown_state": report.lockdown_state,
            "caps": report.caps or {}, "error": report.error, "results": [asdict(r) for r in report.results]}


def print_report(report: EgressReport) -> None:
    print(f"── lockdown ──\n  {report.lockdown_state}")
    if report.caps:
        used = report.caps.get("last_hour") or {}
        print(f"  caps: {report.caps.get('calls_per_hour') or '∞'} calls/h · "
              f"{report.caps.get('megabytes_per_hour') or '∞'} MB/h · last hour: {used.get('calls', 0)} calls, "
              f"{used.get('megabytes', 0)} MB")
    print()
    if report.error:
        print(f"[ERROR] could not run probes: {report.error}")
        return
    print("── probes (run as the swarm user; the console, IPC namespace and proxy-process probes from the host) ──")
    for r in report.results:
        glyph = "PASS" if r.passed else "FAIL"
        expect = "blocked" if r.kind == "blocked" else "reachable"
        print(f"  [{glyph}] {r.name:24s} expect {expect:9s} got {r.observed:5s}  {r.description}")
    print()
    if report.ok:
        print("[hypdmz] egress floor verified: every bypass this check tries was blocked.")
        print("         A route the check does not try is not tested — https://hypdmz.com/#disclaimer")
    elif report.bypass_found:
        print("[hypdmz] EGRESS BYPASS: the swarm can reach the network without the proxy.")
    else:
        print("[hypdmz] the lockdown holds, but a control probe failed — the pod is degraded (or the host is offline).")


def cmd_egress_check(cfg: Config, platform, *, json_output: bool = False) -> int:
    rc, _, _ = run_capture(["podman", "container", "exists", SWARM_CONTAINER])
    if rc != 0:
        msg = "the swarm container is not running — start the pod with `hypdmz up`."
        print(json.dumps({"ok": False, "error": msg}) if json_output else f"[ERROR] {msg}")
        return 2
    report = run_check(cfg)
    if json_output:
        print(json.dumps(report_dict(report), indent=2))
    else:
        print_report(report)
    return 0 if report.ok else 1
