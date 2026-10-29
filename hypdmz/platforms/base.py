from __future__ import annotations

import abc
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence


@dataclass
class PreflightResult:
    name: str
    ok: bool
    detail: str = ""

    def render(self) -> str:
        glyph = "OK " if self.ok else "FAIL"
        line = f"  [{glyph}] {self.name}"
        if self.detail:
            line += f"\n        {self.detail}"
        return line


@dataclass
class Platform(abc.ABC):
    name: str = field(init=False)

    @abc.abstractmethod
    def ensure_runtime(self) -> None:
        """Make sure podman is reachable. Start a VM if the OS needs one."""

    @abc.abstractmethod
    def preflight(self) -> list[PreflightResult]:
        """Cheap, read-only checks. Used by `hypdmz doctor`."""

    def host_path(self, path: Path) -> str:
        """Format a host path the way `podman run --volume` expects."""
        return str(path)

    def add_port_forwards(self, ports: Sequence[int]) -> None:
        """Bridge host loopback to the container ports. No-op on native Linux."""
        return None

    def remove_port_forwards(self, ports: Sequence[int]) -> None:
        return None

    def open_log_window(self, container: str) -> None:
        """Tail one container's logs. Default streams in the current terminal."""
        run(["podman", "logs", "-f", container], check=False)

    def supports_admin_check(self) -> bool:
        return False

    def is_admin(self) -> bool:
        return False


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run(
    args: Sequence[str],
    *,
    check: bool = True,
    capture: bool = False,
    env: dict | None = None,
    quiet: bool = False,
) -> subprocess.CompletedProcess:
    """Thin subprocess.run wrapper. Streams stdout/stderr by default.

    The echoed command line is always redacted — `hypdmz up` passes API keys
    and the broker token as `--env KEY=VALUE` and terminals get logged."""
    if not quiet:
        print(f"  $ {redact_args(args)}", flush=True)
    return subprocess.run(
        list(args),
        check=check,
        text=True,
        capture_output=capture,
        env=env,
    )


def redact_args(args: Sequence[str]) -> str:
    """Render an argv for display with secret env values and token-shaped strings scrubbed."""
    from hypdmz.redact import ALWAYS_REDACT_KEYS, REDACTION, redact_text

    out: list[str] = []
    for a in args:
        key, sep, _ = a.partition("=")
        if sep and key in ALWAYS_REDACT_KEYS:
            out.append(f"{key}={REDACTION}")
        else:
            out.append(redact_text(a))
    return " ".join(out)


def run_capture(args: Sequence[str], *, check: bool = False) -> tuple[int, str, str]:
    proc = subprocess.run(list(args), text=True, capture_output=True, check=check)
    return proc.returncode, proc.stdout, proc.stderr


def podman_exists() -> bool:
    return which("podman") is not None
