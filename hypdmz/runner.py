"""Pod lifecycle: `build`, `up`, `down`, `logs`, `debug`, `run`. One source of truth for every
podman command; the platform backend handles only OS-specific glue."""
from __future__ import annotations

import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from hypdmz.env import Config
from hypdmz.platforms.base import Platform, run, run_capture

POD_NAME = "hypdmz-pod"
CONTROLLER, PROXY, SWARM = "hypdmz-controller", "hypdmz-proxy", "hypdmz-swarm"
CONTAINERS = (CONTROLLER, PROXY, SWARM)
SWARM_USER = "swarm"
PROXY_UID = 1001

IMAGES = [
    ("hypdmz-controller:latest", "controller/"),
    ("hypdmz-proxy:latest", "proxy/"),
    ("hypdmz-swarm:latest", "swarm/"),
]

PLACEHOLDER = "__hypdmz_inject__"
RECORD_IN_POD = "/records/swarm.hypgraph"


# ── build ─────────────────────────────────────────────────────────────

def cmd_build(cfg: Config, platform: Platform, *, dry_run: bool = False) -> int:
    print("[hypdmz] building pod images...")
    for i, (tag, ctx) in enumerate(IMAGES, 1):
        print(f"\n[{i}/{len(IMAGES)}] building {tag}")
        args = ["podman", "build", "-t", tag, platform.host_path(cfg.repo_root / ctx)]
        if dry_run:
            print(f"  $ {' '.join(args)}")
            continue
        run(args)
    print("\n[hypdmz] build complete.")
    return 0


# ── up ────────────────────────────────────────────────────────────────

def _ensure_ca(cfg: Config, platform: Platform, *, dry_run: bool) -> None:
    """Create the egress CA once, with the proxy image's own code. The key lands in certs/ (the proxy's
    mount) and the certificate in certs/public/ (the swarm's). Runs as root in the container so the key
    can be handed to the proxy UID on Linux hosts."""
    if cfg.ca_cert_path.exists() and (cfg.cert_dir / "hypdmz-ca.pem").exists():
        return
    args = ["podman", "run", "--rm", "--entrypoint", "python",
            *_volume(platform, cfg.cert_dir, "/certs"),
            "--env", f"HYPDMZ_PROXY_UID={PROXY_UID}",
            "hypdmz-proxy:latest", "-m", "app.tls_mitm", "init", "/certs"]
    if dry_run:
        _print_cmd(args)
        return
    print("[hypdmz] creating the egress CA (first run)...")
    run(args)
    if not cfg.ca_cert_path.exists():
        raise RuntimeError(f"CA creation failed: {cfg.ca_cert_path} missing")


def cmd_up(cfg: Config, platform: Platform, *, dry_run: bool = False, skip_egress_check: bool = False) -> int:
    print("[hypdmz] starting pod...")
    if not dry_run:
        platform.ensure_runtime()
        for d in (cfg.proxy_data_dir / "audit", cfg.cert_dir, cfg.public_cert_dir, cfg.records_dir, cfg.work_dir):
            d.mkdir(parents=True, exist_ok=True)
    print(f"[hypdmz] state:   {cfg.state_dir}")
    print(f"[hypdmz] records: {cfg.records_dir}")
    print(f"[hypdmz] model:   {cfg.model} via {cfg.model_base_url}")
    secret = cfg.key_secret if (dry_run or secret_exists(cfg.key_secret)) else ""
    if secret:
        print(f"[hypdmz] key:     podman secret '{secret}' (mounted into the proxy as a file; never in an environment)")
        if cfg.model_api_key:
            print(f"[hypdmz] note: MODEL_API_KEY in {cfg.env_file} is ignored while the secret exists — remove it")
    elif cfg.model_api_key:
        print(f"[hypdmz] key:     MODEL_API_KEY from .env — prefer a podman secret: "
              f"podman secret create {cfg.key_secret} -")
    else:
        print("[hypdmz] note: no key in a podman secret or .env — fine if the vault already holds it "
              "(hypdmz status shows the count)")

    if not dry_run:
        _teardown(quiet=True)
    _ensure_ca(cfg, platform, dry_run=dry_run)

    pod_args = ["podman", "pod", "create", "--name", POD_NAME]
    for host_port, pod_port in cfg.publish_ports:
        pod_args += ["--publish", f"127.0.0.1:{host_port}:{pod_port}"]
    _do(pod_args, dry_run)

    _do(["podman", "run", "-d", "--pod", POD_NAME, "--name", CONTROLLER,
         "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
         *_envs({"HYPDMZ_PROXY_UID": str(PROXY_UID), "HYPDMZ_CONTROL_PORT": "8002"}),
         "hypdmz-controller:latest"], dry_run)

    proxy_env = {
        "HYPDMZ_PROXY_UID": str(PROXY_UID),
        "FIREWALL_CONFIG": "/app/config/firewall.json",
        "PROXY_AUDIT_PATH": "/app/data/audit/proxy_events.jsonl",
        "PROXY_AUDIT_HEAD_PATH": "/app/data/audit/.chain_head",
        "HYPDMZ_CA_PEM": "/etc/hypdmz-certs/hypdmz-ca.pem",
        "HYPDMZ_LEAF_CACHE": "/app/data/leaf-certs",
        "VAULT_DB_PATH": "/app/data/vault.db",
        "VAULT_MASTER_KEY": "/app/data/.master.key",
        "VAULT_BOOTSTRAP_MODEL_HOST": cfg.model_host,
        **{k: v for k, v in cfg.hardening_env().items() if v},
    }
    secret_args: list[str] = []
    if secret:
        # The key arrives as a file the proxy UID alone can read, and the proxy vaults it on first start.
        secret_args = ["--secret", f"{secret},type=mount,uid={PROXY_UID},gid={PROXY_UID},mode=0400"]
        proxy_env["VAULT_BOOTSTRAP_MODEL_FILE"] = f"/run/secrets/{secret}"
    elif cfg.model_api_key:
        proxy_env["VAULT_BOOTSTRAP_MODEL"] = cfg.model_api_key
    _do(["podman", "run", "-d", "--pod", POD_NAME, "--name", PROXY,
         *_volume(platform, cfg.repo_root / "proxy" / "config", "/app/config", readonly=True),
         *_volume(platform, cfg.proxy_data_dir, "/app/data"),
         *_volume(platform, cfg.cert_dir, "/etc/hypdmz-certs", readonly=True),
         *secret_args,
         *_envs(proxy_env), "hypdmz-proxy:latest"], dry_run, redact=("VAULT_BOOTSTRAP_MODEL",))

    swarm_env = {
        "OPENAI_BASE_URL": cfg.model_base_url,
        "OPENAI_API_KEY": PLACEHOLDER,                 # the vault supplies the real key, per host rule
        "HYPSWARM_MODEL": cfg.model,
        "HTTP_PROXY": "http://127.0.0.1:8080",
        "HTTPS_PROXY": "http://127.0.0.1:8080",
        "NO_PROXY": "localhost,127.0.0.1",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
        "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/ca-certificates.crt",
        "HYPDMZ_RECORD": RECORD_IN_POD,
    }
    _do(["podman", "run", "-d", "--pod", POD_NAME, "--name", SWARM,
         "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
         "--security-opt", "no-new-privileges",
         *_volume(platform, cfg.records_dir, "/records"),
         *_volume(platform, cfg.work_dir, "/work"),
         *_volume(platform, cfg.public_cert_dir, "/etc/hypdmz-certs", readonly=True),
         *_envs(swarm_env), "hypdmz-swarm:latest"], dry_run)

    if dry_run:
        return 0
    platform.add_port_forwards([p for p, _ in cfg.publish_ports])
    print(f"\n[hypdmz] pod is up.\n  record UI  → http://127.0.0.1:{cfg.ui_port}\n"
          f"  console    → http://127.0.0.1:{cfg.console_port}\n"
          f"  proxy      → http://127.0.0.1:{cfg.proxy_port}  (host tools: trust {cfg.ca_cert_path})")
    if cfg.model_api_key and not secret:
        print(f"[hypdmz] MODEL_API_KEY was handed to the vault — remove it from {cfg.env_file} now.")
    if skip_egress_check:
        print("[hypdmz] egress check skipped (--skip-egress-check).")
        return 0
    return _verify_egress_floor(cfg)


def _verify_egress_floor(cfg: Config) -> int:
    from hypdmz.egress import print_report, run_check

    print("\n[hypdmz] verifying the egress floor...")
    report = run_check(cfg, wait_for_lock_s=30)
    print_report(report)
    if report.bypass_found or not report.lockdown_state.startswith("LOCKED"):
        print(f"[hypdmz] stopping {SWARM} — fix the lockdown, then `hypdmz up` again.")
        run_capture(["podman", "stop", SWARM])
        return 3
    if not report.ok:
        print("[hypdmz] continuing: the lockdown holds but a control probe failed (pod degraded, or host offline).")
    return 0


# ── run ───────────────────────────────────────────────────────────────

def cmd_run(cfg: Config, platform: Platform, folder: Path, *, task: str = "task.toml", seats: str = "",
            profile: str = "", model: str = "", budget_usd: float = 0.0, budget_calls: int = 150,
            pricing: str = "", python: bool = False, record: str = "", name: str = "") -> int:
    """Copy `folder` into the pod's work area and run hypswarm there, as the swarm user."""
    folder = folder.resolve()
    if not (folder / task).is_file():
        print(f"[hypdmz] no {task} in {folder}")
        return 2
    rc, _, _ = run_capture(["podman", "container", "exists", SWARM])
    if rc != 0:
        print("[hypdmz] the swarm container is not running — `hypdmz up` first.")
        return 2
    stamp = name or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + folder.name
    stamp = "".join(c if c.isalnum() or c in "-_." else "-" for c in stamp)
    dst = cfg.work_dir / stamp
    if dst.exists():
        print(f"[hypdmz] {dst} exists — pick another --name")
        return 2
    shutil.copytree(folder, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.hypgraph*"))
    pod_dir = f"/work/{stamp}"
    run_capture(["podman", "exec", "-u", "0", SWARM, "chown", "-R", f"{SWARM_USER}:{SWARM_USER}", pod_dir])

    rec = f"/records/{record}" if record else RECORD_IN_POD
    if rec.endswith("/") or ".." in rec:
        print("[hypdmz] bad --record name")
        return 2
    if record and not rec.endswith(".hypgraph"):
        rec += ".hypgraph"
    cmd = ["hypswarm", "run", "--task", f"{pod_dir}/{task}", "--folder", pod_dir, "--record", rec,
           "--budget-calls", str(budget_calls), "--budget-usd", str(budget_usd)]
    seats_file = seats or ("seats.toml" if (folder / "seats.toml").is_file() else "")
    if seats_file:
        cmd += ["--seats", f"{pod_dir}/{seats_file}"]
    if profile:
        cmd += ["--profile", profile]
    if model:
        cmd += ["--model", model]
    if pricing:
        cmd += ["--pricing", pricing]
    if python:
        cmd += ["--python"]
    print(f"[hypdmz] run {stamp}: {' '.join(cmd)}")
    print(f"[hypdmz] watch it at http://127.0.0.1:{cfg.ui_port}\n")
    proc = subprocess.run(["podman", "exec", "-i", "-u", SWARM_USER, "-w", pod_dir, SWARM, *cmd])
    rec_host = cfg.records_dir / Path(rec).name
    print(f"\n[hypdmz] run {stamp} finished (exit {proc.returncode}). Record: {rec_host}  Work: {dst}")
    return proc.returncode


# ── down / logs / debug ───────────────────────────────────────────────

def cmd_down(cfg: Config, platform: Platform) -> int:
    print("[hypdmz] stopping pod...")
    _teardown(quiet=False)
    platform.remove_port_forwards([p for p, _ in cfg.publish_ports])
    print("[hypdmz] pod stopped and removed.")
    return 0


def cmd_logs(cfg: Config, platform: Platform, *, follow: bool = True) -> int:
    if not follow:
        for c in CONTAINERS:
            print(f"\n──── {c} ────")
            run(["podman", "logs", "--tail", "200", c], check=False)
        return 0
    if platform.name == "windows":
        for c in CONTAINERS:
            platform.open_log_window(c)
        print("[hypdmz] tailing the three containers in separate windows.")
        return 0
    return _stream_logs_inline(CONTAINERS)


def cmd_debug(cfg: Config, platform: Platform) -> int:
    print("[hypdmz] diagnostic report\n\n── pod ──")
    run(["podman", "ps", "-a", "--pod", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"], check=False)
    print("\n── lockdown ──")
    run(["podman", "exec", CONTROLLER, "cat", "/run/hypdmz/lockdown.state"], check=False)
    print("\n── swarm user ──")
    run(["podman", "exec", SWARM, "id", SWARM_USER], check=False)
    print("\n── network ──")
    run(["podman", "exec", CONTROLLER, "/controller/inspect-network.sh"], check=False)
    return 0


# ── helpers ───────────────────────────────────────────────────────────

def secret_exists(name: str) -> bool:
    rc, _, _ = run_capture(["podman", "secret", "exists", name])
    return rc == 0


def _do(args: list[str], dry_run: bool, *, redact: tuple[str, ...] = ()) -> None:
    if dry_run:
        _print_cmd(args, redact=redact)
    else:
        run(args)


def _print_cmd(args: list[str], *, redact: tuple[str, ...] = ()) -> None:
    out = []
    for a in args:
        k, sep, _ = a.partition("=")
        out.append(f"{k}=***" if sep and k in redact else a)
    print("  $ " + " ".join(out))


def _envs(mapping: dict[str, str]) -> list[str]:
    out: list[str] = []
    for k, v in mapping.items():
        out += ["--env", f"{k}={v}"]
    return out


def _volume(platform: Platform, host: Path, container: str, *, readonly: bool = False) -> list[str]:
    suffix = ":ro" if readonly else ""
    selinux = _selinux_suffix() if platform.name == "linux" else ""
    return ["--volume", f"{platform.host_path(host)}:{container}{suffix}{selinux}"]


def _selinux_suffix() -> str:
    if not shutil.which("getenforce"):
        return ""
    rc, out, _ = run_capture(["getenforce"])
    return ":Z" if rc == 0 and out.strip().lower() == "enforcing" else ""


def _teardown(*, quiet: bool) -> None:
    for c in CONTAINERS:
        run_capture(["podman", "rm", "-f", "--ignore", c])
    rc, _, err = run_capture(["podman", "pod", "rm", "-f", "--ignore", POD_NAME])
    if rc != 0 and not quiet:
        print(f"[hypdmz] pod rm: {err.strip()}")


def _stream_logs_inline(containers: tuple[str, ...]) -> int:
    procs = []
    for c in containers:
        p = subprocess.Popen(["podman", "logs", "-f", "--tail", "50", c], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        procs.append(p)

        def pump(proc=p, name=c):
            for line in proc.stdout:
                print(f"[{name}] {line.rstrip()}")

        threading.Thread(target=pump, daemon=True).start()
    try:
        while any(p.poll() is None for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
    return 0
