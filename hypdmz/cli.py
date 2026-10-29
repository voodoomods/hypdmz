from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from hypdmz import __version__
from hypdmz.doctor import cmd_doctor
from hypdmz.egress import cmd_egress_check
from hypdmz.env import Config, load
from hypdmz.platforms import detect
from hypdmz.runner import bundled_examples, cmd_build, cmd_debug, cmd_down, cmd_logs, cmd_run, cmd_up, ensure_policy
from hypdmz.status import cmd_status


def cmd_init(cfg: Config) -> int:
    """Create the state directory and its .env from the package's template; say what comes next."""
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    if cfg.env_file.exists():
        print(f"[hypdmz] .env already there: {cfg.env_file}")
    else:
        shutil.copyfile(cfg.env_example, cfg.env_file)
        print(f"[hypdmz] wrote {cfg.env_file}")
    created = ensure_policy(cfg)
    if not created:
        print(f"[hypdmz] policy already there: {cfg.policy_path}")
    print(f"""
[hypdmz] next:
  1. edit {cfg.env_file}: MODEL_BASE_URL and MODEL (DeepInfra is the default)
  2. put the model API key in a podman secret:   podman secret create {cfg.key_secret} -
     (paste the key, Enter, then Ctrl-D on Linux/macOS or Ctrl-Z Enter on Windows)
  3. hypdmz doctor · hypdmz build · hypdmz up · hypdmz run first-swarm --python --budget-usd 0.20
  the allowlist is {cfg.policy_path} (hot-reloaded; `hypdmz policy reset` restores the default)""")
    return 0


def cmd_policy(cfg: Config, action: str) -> int:
    if action == "path":
        print(cfg.policy_path)
        return 0
    if action == "reset":
        cfg.policy_dir.mkdir(parents=True, exist_ok=True)
        if cfg.policy_path.exists():
            backup = cfg.policy_path.with_suffix(".json.bak")
            shutil.copyfile(cfg.policy_path, backup)
            print(f"[hypdmz] previous policy kept at {backup}")
        shutil.copyfile(cfg.default_policy, cfg.policy_path)
        print(f"[hypdmz] policy reset to the package default → {cfg.policy_path} (the proxy picks it up within a second)")
        return 0
    # show
    src = cfg.policy_path if cfg.policy_path.exists() else cfg.default_policy
    try:
        pol = json.loads(src.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[hypdmz] {src} does not parse ({e}) — the proxy denies everything until it does")
        return 1
    print(f"[hypdmz] {src}{'' if src == cfg.policy_path else '  (package default; no operator policy yet)'}")
    lim = pol.get("limits") or {}
    print(f"  limits: {lim.get('calls_per_hour') or '∞'} calls/h · {lim.get('megabytes_per_hour') or '∞'} MB/h")
    for c in pol.get("cidr_blocklist") or []:
        print(f"  block   {c.get('name')}: {', '.join(c.get('cidrs') or [])}")
    for r in pol.get("rules") or []:
        hosts = r.get("host") or ", ".join(r.get("hosts") or r.get("host_suffixes") or []) or r.get("host_regex") or "*"
        flag = "" if r.get("enabled", True) else "  (disabled)"
        guard = f"  guard={r['guard']}" if r.get("guard") else ""
        exp = f"  until {r['expires_at']}" if r.get("expires_at") else ""
        print(f"  rule    {r.get('name')}: {r.get('scheme', 'https')}://{hosts} {r.get('ports') or ''} "
              f"{'/'.join(r.get('methods') or ['*'])} {' '.join(r.get('path_prefixes') or ['/'])}"
              f"{'  injects ' + ','.join(r['injects']) if r.get('injects') else ''}{guard}{exp}{flag}")
    return 0


def cmd_examples(cfg: Config, name: str, dest: Path | None) -> int:
    names = bundled_examples(cfg)
    if not name:
        for n in names:
            print(n)
        return 0
    if name not in names:
        print(f"[hypdmz] no bundled example '{name}' (have: {', '.join(names)})")
        return 2
    target = (dest or Path(name)).resolve()
    if target.exists():
        print(f"[hypdmz] {target} exists")
        return 2
    shutil.copytree(cfg.examples_dir / name, target)
    print(f"[hypdmz] copied {name} → {target}  (edit task.toml and seats.toml, then: hypdmz run {target})")
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows consoles default to cp1252
    p = argparse.ArgumentParser(prog="hypdmz", description="Run a HypSwarm research swarm inside a governed-egress pod.")
    p.add_argument("--version", action="version", version=f"hypdmz {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the state dir and .env; print what comes next")
    s = sub.add_parser("doctor", help="preflight checks"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("build", help="build the three images from the package's contexts"); s.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("up", help="create the pod, start the containers, verify the egress floor")
    s.add_argument("--dry-run", action="store_true"); s.add_argument("--skip-egress-check", action="store_true")
    sub.add_parser("down", help="stop and remove the pod")
    s = sub.add_parser("status", help="pod, lockdown and endpoint snapshot"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("logs", help="tail the containers"); s.add_argument("--no-follow", action="store_true")
    sub.add_parser("debug", help="pod, lockdown state and iptables view")
    s = sub.add_parser("egress-check", help="escape attempts as the swarm user; exit 1 on any bypass")
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("run", help="run a swarm: a folder with task.toml (and seats.toml or --profile), or a bundled example's name")
    s.add_argument("folder", type=Path)
    s.add_argument("--task", default="task.toml"); s.add_argument("--seats", default="")
    s.add_argument("--profile", default="", help="scientific | software | trading | knowledge | optimization")
    s.add_argument("--model", default="", help="default model id (else MODEL from .env)")
    s.add_argument("--budget-usd", type=float, default=0.0); s.add_argument("--budget-calls", type=int, default=150)
    s.add_argument("--pricing", default="", help="input,cached,output $ per million tokens")
    s.add_argument("--python", action="store_true", help="give the seats a python tool in the work folder (in the pod)")
    s.add_argument("--record", default="", help="record file name under records/ (default: the served swarm.hypgraph)")
    s.add_argument("--name", default="", help="name for this run's work folder")
    s = sub.add_parser("policy", help="the egress allowlist: show, path, reset")
    s.add_argument("action", nargs="?", default="show", choices=["show", "path", "reset"])
    s = sub.add_parser("example", help="list the bundled examples, or copy one out to edit")
    s.add_argument("name", nargs="?", default=""); s.add_argument("dest", nargs="?", type=Path, default=None)

    a = p.parse_args(argv)
    cfg = load()
    try:
        if a.cmd == "init":
            return cmd_init(cfg)
        if a.cmd == "policy":
            return cmd_policy(cfg, a.action)
        if a.cmd == "example":
            return cmd_examples(cfg, a.name, a.dest)
        platform = detect()
        if a.cmd == "doctor":
            return cmd_doctor(cfg, platform, json_output=a.json)
        if a.cmd == "build":
            return cmd_build(cfg, platform, dry_run=a.dry_run)
        if a.cmd == "up":
            return cmd_up(cfg, platform, dry_run=a.dry_run, skip_egress_check=a.skip_egress_check)
        if a.cmd == "down":
            return cmd_down(cfg, platform)
        if a.cmd == "status":
            return cmd_status(cfg, platform, json_output=a.json)
        if a.cmd == "logs":
            return cmd_logs(cfg, platform, follow=not a.no_follow)
        if a.cmd == "debug":
            return cmd_debug(cfg, platform)
        if a.cmd == "egress-check":
            return cmd_egress_check(cfg, platform, json_output=a.json)
        if a.cmd == "run":
            return cmd_run(cfg, platform, a.folder, task=a.task, seats=a.seats, profile=a.profile, model=a.model,
                           budget_usd=a.budget_usd, budget_calls=a.budget_calls, pricing=a.pricing,
                           python=a.python, record=a.record, name=a.name)
    except KeyboardInterrupt:
        return 130
    except RuntimeError as e:
        print(f"[hypdmz] {e}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
