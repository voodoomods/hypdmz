from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from hypdmz.env import wsl_linux_path
from hypdmz.platforms.base import (
    Platform,
    PreflightResult,
    podman_exists,
    run,
    run_capture,
)


class WindowsPlatform(Platform):
    name = "windows"

    def ensure_runtime(self) -> None:
        if not podman_exists():
            raise RuntimeError(
                "podman not found. Install Podman Desktop from "
                "https://podman-desktop.io/ and run `podman machine init`."
            )
        # `podman machine start` exits non-zero if already running on some
        # versions — that's harmless, only `podman info` is authoritative.
        run_capture(["podman", "machine", "start"])
        rc, _, err = run_capture(["podman", "info"])
        if rc != 0:
            raise RuntimeError(
                "podman is not reachable. Make sure Podman Desktop is installed,\n"
                "then run: podman machine init && podman machine start\n"
                f"stderr:\n{err}"
            )

    def preflight(self) -> list[PreflightResult]:
        results: list[PreflightResult] = []
        results.append(_check_binary("podman"))
        results.append(_check_binary("powershell", optional=False))
        results.append(_check_binary("netsh", optional=True))

        rc, out, _ = run_capture(["podman", "machine", "list", "--format", "{{.Name}}\t{{.Running}}"])
        if rc == 0:
            running_any = any("true" in line.lower() for line in out.splitlines())
            results.append(PreflightResult(
                "podman machine running",
                ok=running_any,
                detail=out.strip() or "no machines",
            ))
        else:
            results.append(PreflightResult("podman machine list", ok=False, detail="failed"))

        admin = self.is_admin()
        results.append(PreflightResult(
            "administrator",
            ok=True,  # not required if gvproxy passes ports through cleanly
            detail=(
                "yes" if admin else
                "no — only needed if 127.0.0.1 ports are unreachable; "
                "rerun in an admin shell or use bat\\podman-expose.bat"
            ),
        ))
        return results

    def supports_admin_check(self) -> bool:
        return True

    def is_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def host_path(self, path: Path) -> str:
        # A path inside the Podman VM (\\wsl.localhost\<machine>\…) mounts as the VM's own path.
        return wsl_linux_path(path) or str(path)

    def add_port_forwards(self, ports: Sequence[int]) -> None:
        if not self.is_admin():
            print("[hypdmz] not admin — skipping netsh portproxy. "
                  "Run `hypdmz expose` from an admin shell if ports are unreachable.")
            return
        ip = self._podman_machine_ip()
        if not ip:
            print("[hypdmz] could not detect Podman machine IP; skipping portproxy.")
            return
        for port in ports:
            run_capture([
                "netsh", "interface", "portproxy", "delete", "v4tov4",
                f"listenaddress=127.0.0.1", f"listenport={port}",
            ])
            run([
                "netsh", "interface", "portproxy", "add", "v4tov4",
                f"listenaddress=127.0.0.1", f"listenport={port}",
                f"connectaddress={ip}", f"connectport={port}",
            ], check=False)

    def remove_port_forwards(self, ports: Sequence[int]) -> None:
        if not self.is_admin():
            return
        for port in ports:
            run_capture([
                "netsh", "interface", "portproxy", "delete", "v4tov4",
                f"listenaddress=127.0.0.1", f"listenport={port}",
            ])

    def open_log_window(self, container: str) -> None:
        # Spawn each in its own cmd window so all three stream in parallel.
        subprocess.Popen(
            ["cmd", "/c", "start", f'"{container} logs"', "cmd", "/k",
             f"podman logs -f {container}"],
            shell=False,
        )

    def _podman_machine_ip(self) -> str | None:
        rc, out, _ = run_capture(["podman", "machine", "ssh", "--", "hostname", "-I"])
        if rc != 0:
            return None
        first = out.strip().split()
        return first[0] if first else None


def _check_binary(name: str, *, optional: bool = False) -> PreflightResult:
    found = shutil.which(name)
    if found:
        return PreflightResult(f"{name} present", ok=True, detail=found)
    return PreflightResult(
        f"{name} present",
        ok=optional,
        detail="not on PATH" + (" (optional)" if optional else ""),
    )
