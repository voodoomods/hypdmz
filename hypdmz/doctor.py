"""`hypdmz doctor` — preflight checks before the first `up`."""
from __future__ import annotations

import json
from dataclasses import asdict

from hypdmz.env import Config, sync_folder_marker
from hypdmz.platforms.base import Platform, PreflightResult


def cmd_doctor(cfg: Config, platform: Platform, *, json_output: bool = False) -> int:
    app_results = [_check_env_file(cfg), _check_state_dir(cfg), _check_model_key(cfg), _check_build_inputs(cfg)]
    plat_results = platform.preflight()
    fail = sum(1 for r in app_results + plat_results if not r.ok)
    if json_output:
        print(json.dumps({"platform": platform.name, "ok": fail == 0, "fail_count": fail,
                          "application": [asdict(r) for r in app_results],
                          "platform_checks": [asdict(r) for r in plat_results]}, indent=2))
        return 0 if fail == 0 else 1
    print(f"[hypdmz] doctor — platform={platform.name}\n")
    for r in app_results:
        print(r.render())
    print("\n── platform checks ──")
    for r in plat_results:
        print(r.render())
    print()
    print("[hypdmz] all checks passed." if fail == 0 else f"[hypdmz] {fail} check(s) failed.")
    return 0 if fail == 0 else 1


def _check_env_file(cfg: Config) -> PreflightResult:
    if cfg.env_file.exists():
        return PreflightResult(".env present", True, str(cfg.env_file))
    return PreflightResult(".env present", False,
                           f"copy .env.example to {cfg.env_file} (MODEL_API_KEY, MODEL_BASE_URL, MODEL)")


def _check_state_dir(cfg: Config) -> PreflightResult:
    marker = sync_folder_marker(cfg.state_dir)
    if marker:
        return PreflightResult("state dir is local", False,
                               f"{cfg.state_dir} is under a cloud-synced folder ({marker}); set HYPDMZ_STATE_DIR")
    return PreflightResult("state dir is local", True, str(cfg.state_dir))


def _check_model_key(cfg: Config) -> PreflightResult:
    from hypdmz.runner import secret_exists

    vault = cfg.proxy_data_dir / "vault.db"
    if secret_exists(cfg.key_secret):
        return PreflightResult("model API key", True, f"podman secret '{cfg.key_secret}' (mounted into the proxy only)")
    if cfg.model_api_key:
        return PreflightResult("model API key", True, "MODEL_API_KEY in .env; vaulted on the next `up` — then delete the "
                               f"line (better: podman secret create {cfg.key_secret} -)")
    if vault.exists():
        return PreflightResult("model API key", True, "no secret, not in .env; the vault exists (hypdmz status shows the count)")
    return PreflightResult("model API key", False,
                           f"no key: `podman secret create {cfg.key_secret} -` (paste it), or MODEL_API_KEY in .env")


def _check_build_inputs(cfg: Config) -> PreflightResult:
    missing = [p for p in ("controller/Dockerfile", "proxy/Dockerfile", "swarm/Dockerfile", "proxy/config/firewall.json")
               if not (cfg.repo_root / p).exists()]
    if missing:
        return PreflightResult("repo layout", False, f"missing under {cfg.repo_root}: {', '.join(missing)}")
    return PreflightResult("repo layout", True, str(cfg.repo_root))
