"""Configuration: the state directory and `.env`.

Secrets and runtime state live in a per-user, machine-local state directory —
never in the repo, which may sit in a cloud-synced folder:

    <state dir>/.env            MODEL_API_KEY etc. (the key is vaulted on first `up`; delete it after)
    <state dir>/proxy-data/     vault.db, .master.key, audit/, leaf-certs/   (the proxy's, UID 1001)
    <state dir>/certs/          hypdmz-ca.pem (CA cert + key: the proxy's secret)
    <state dir>/certs/public/   hypdmz-ca-cert.pem (what the swarm and the host trust)
    <state dir>/records/        swarm.hypgraph + its telemetry sidecar
    <state dir>/work/           one folder per `hypdmz run`

Defaults: Windows %USERPROFILE%\\.hypdmz, Linux ${XDG_STATE_HOME:-~/.local/state}/hypdmz,
macOS ~/Library/Application Support/HypDMZ. Override with HYPDMZ_STATE_DIR (process env only).
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


def parse_env_file(path: Path) -> dict[str, str]:
    """Minimal .env parser: skip blanks and comments, split on the first '=', strip matching quotes."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


def wsl_linux_path(path: Path | str) -> str | None:
    """\\\\wsl.localhost\\<distro>\\a\\b (or \\\\wsl$\\…) → /a/b; None for any other path."""
    s = str(path).replace("/", "\\")
    for prefix in ("\\\\wsl.localhost\\", "\\\\wsl$\\"):
        if s.lower().startswith(prefix):
            tail = s[len(prefix):].partition("\\")[2]
            return "/" + tail.replace("\\", "/")
    return None


_SYNC_MARKERS = ("onedrive", "dropbox", "google drive", "googledrive",
                 "icloud drive", "icloud", "mobile documents", "box sync", "box")


def default_state_dir() -> Path:
    home = Path.home()
    if sys.platform == "win32":
        # Not under AppData: Microsoft Store Python redirects AppData writes into its sandbox.
        return home / ".hypdmz"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "HypDMZ"
    base = Path(os.environ.get("XDG_STATE_HOME") or home / ".local" / "state")
    return base / "hypdmz"


def resolve_state_dir() -> tuple[Path, str]:
    explicit = os.environ.get("HYPDMZ_STATE_DIR")
    if explicit:
        return Path(explicit).expanduser(), "env"
    return default_state_dir(), "default"


def sync_folder_marker(path: Path) -> str | None:
    """Name of the cloud-sync folder `path` sits under, or None."""
    for env_key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        root = os.environ.get(env_key)
        if root:
            try:
                path.resolve().relative_to(Path(root).resolve())
                return env_key
            except ValueError:
                pass
    for part in path.resolve().parts:
        low = part.lower()
        if any(low == m or low.startswith(m + " ") or low.startswith(m + "-") for m in _SYNC_MARKERS):
            return part
    return None


DEFAULT_MODEL_BASE_URL = "https://api.deepinfra.com/v1/openai"
DEFAULT_MODEL = "deepseek-ai/DeepSeek-V4.1-Flash"


@dataclass
class Config:
    repo_root: Path
    env: dict[str, str] = field(default_factory=dict)
    state_dir: Path = None  # type: ignore[assignment]
    state_source: str = "default"

    def __post_init__(self) -> None:
        if self.state_dir is None:
            self.state_dir, self.state_source = resolve_state_dir()

    # ── paths ──
    @property
    def env_file(self) -> Path:
        return self.state_dir / ".env"

    @property
    def proxy_data_dir(self) -> Path:
        return self.state_dir / "proxy-data"

    @property
    def cert_dir(self) -> Path:
        return self.state_dir / "certs"

    @property
    def public_cert_dir(self) -> Path:
        return self.cert_dir / "public"

    @property
    def ca_cert_path(self) -> Path:
        return self.public_cert_dir / "hypdmz-ca-cert.pem"

    @property
    def records_dir(self) -> Path:
        explicit = self.env.get("HYPDMZ_RECORDS_DIR")
        return Path(explicit).expanduser() if explicit else self.state_dir / "records"

    @property
    def work_dir(self) -> Path:
        return self.state_dir / "work"

    # ── model access ──
    @property
    def model_base_url(self) -> str:
        return (self.env.get("MODEL_BASE_URL") or DEFAULT_MODEL_BASE_URL).rstrip("/")

    @property
    def model_host(self) -> str:
        return urlparse(self.model_base_url).hostname or ""

    @property
    def model(self) -> str:
        return self.env.get("MODEL") or DEFAULT_MODEL

    @property
    def model_api_key(self) -> str:
        return self.env.get("MODEL_API_KEY", "")

    @property
    def key_secret(self) -> str:
        """The podman secret holding the model API key (preferred over MODEL_API_KEY in .env):
        `podman secret create hypdmz_llm_api_key -` then paste the key. Mounted as a file into the proxy
        container only; never in any container's environment or `podman inspect`."""
        return self.env.get("HYPDMZ_KEY_SECRET") or "hypdmz_llm_api_key"

    # ── host ports (the pod's own ports never change: 8000 UI, 8002 console, 8080 proxy) ──
    def _port(self, key: str, default: int) -> int:
        try:
            return int(self.env.get(key) or default)
        except ValueError:
            return default

    @property
    def ui_port(self) -> int:
        return self._port("HYPDMZ_UI_PORT", 8000)

    @property
    def console_port(self) -> int:
        return self._port("HYPDMZ_CONSOLE_PORT", 8002)

    @property
    def proxy_port(self) -> int:
        return self._port("HYPDMZ_PROXY_PORT", 8080)

    # ── the swarm container's resource limits (podman flags; cgroups v2) ──
    @property
    def swarm_memory(self) -> str:
        return self.env.get("HYPDMZ_SWARM_MEMORY") or "4g"

    @property
    def swarm_cpus(self) -> str:
        return self.env.get("HYPDMZ_SWARM_CPUS") or "2"

    @property
    def swarm_pids(self) -> str:
        return self.env.get("HYPDMZ_SWARM_PIDS") or "512"

    @property
    def swarm_tmp(self) -> str:
        return self.env.get("HYPDMZ_SWARM_TMP") or "2g"

    # ── the control API's bearer token: generated once, host-owned, mounted ro into the proxy ──
    @property
    def tokens_dir(self) -> Path:
        return self.state_dir / "tokens"

    @property
    def console_token_path(self) -> Path:
        return self.tokens_dir / "console.token"

    def console_token(self) -> str:
        try:
            return self.console_token_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    @property
    def publish_ports(self) -> tuple[tuple[int, int], ...]:
        """(host port, container port) pairs published on 127.0.0.1."""
        return ((self.ui_port, 8000), (self.console_port, 8002), (self.proxy_port, 8080))

    def hardening_env(self) -> dict[str, str]:
        return {k: self.env.get(k, "") for k in ("DLP_MODE", "AUDIT_SINK_URL", "AUDIT_SINK_TOKEN")}


_PASSTHROUGH = {"MODEL_API_KEY", "MODEL_BASE_URL", "MODEL", "DLP_MODE", "AUDIT_SINK_URL", "AUDIT_SINK_TOKEN"}


def load(repo_root: Path, env_file: Path | None = None) -> Config:
    """Load <state dir>/.env, then let the process environment override it."""
    state_dir, source = resolve_state_dir()
    env: dict[str, str] = {}
    env.update(parse_env_file(env_file or (state_dir / ".env")))
    for k, v in os.environ.items():
        if k in env or k.startswith("HYPDMZ_") or k in _PASSTHROUGH:
            env[k] = v
    return Config(repo_root=repo_root, env=env, state_dir=state_dir, state_source=source)
