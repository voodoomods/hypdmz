from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from hypdmz import __version__
from hypdmz.doctor import cmd_doctor
from hypdmz.egress import cmd_egress_check
from hypdmz.env import load
from hypdmz.platforms import detect
from hypdmz.runner import cmd_build, cmd_debug, cmd_down, cmd_logs, cmd_run, cmd_up
from hypdmz.status import cmd_status


def _repo_root() -> Path:
    """HYPDMZ_REPO_ROOT, else walk up from this file, then from cwd, for proxy/config/firewall.json."""
    env = os.environ.get("HYPDMZ_REPO_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    sentinel = Path("proxy") / "config" / "firewall.json"
    here = Path(__file__).resolve().parent
    for candidate in (here.parent, *here.parents):
        if (candidate / sentinel).exists():
            return candidate
    cwd = Path.cwd().resolve()
    for candidate in (cwd, *cwd.parents):
        if (candidate / sentinel).exists():
            return candidate
    return cwd


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # Windows consoles default to cp1252
    p = argparse.ArgumentParser(prog="hypdmz", description="Run a HypSwarm research swarm inside a governed-egress pod.")
    p.add_argument("--version", action="version", version=f"hypdmz {__version__}")
    p.add_argument("--repo-root", type=Path, default=None, help="project tree (default: auto-detected)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("doctor", help="preflight checks"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("build", help="build the three images"); s.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("up", help="create the pod, start the containers, verify the egress floor")
    s.add_argument("--dry-run", action="store_true"); s.add_argument("--skip-egress-check", action="store_true")
    sub.add_parser("down", help="stop and remove the pod")
    s = sub.add_parser("status", help="pod, lockdown and endpoint snapshot"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("logs", help="tail the containers"); s.add_argument("--no-follow", action="store_true")
    sub.add_parser("debug", help="pod, lockdown state and iptables view")
    s = sub.add_parser("egress-check", help="escape attempts as the swarm user; exit 1 on any bypass")
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("run", help="run a swarm: a folder with task.toml (and seats.toml or --profile)")
    s.add_argument("folder", type=Path)
    s.add_argument("--task", default="task.toml"); s.add_argument("--seats", default="")
    s.add_argument("--profile", default="", help="scientific | software | trading | knowledge | optimization")
    s.add_argument("--model", default="", help="default model id (else MODEL from .env)")
    s.add_argument("--budget-usd", type=float, default=0.0); s.add_argument("--budget-calls", type=int, default=150)
    s.add_argument("--pricing", default="", help="input,cached,output $ per million tokens")
    s.add_argument("--python", action="store_true", help="give the seats a python tool in the work folder (in the pod)")
    s.add_argument("--record", default="", help="record file name under records/ (default: the served swarm.hypgraph)")
    s.add_argument("--name", default="", help="name for this run's work folder")

    a = p.parse_args(argv)
    root = a.repo_root.resolve() if a.repo_root else _repo_root()
    cfg = load(root)
    platform = detect()
    try:
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
