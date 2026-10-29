from __future__ import annotations

import platform as _platform
import shutil
from pathlib import Path

from hypdmz.platforms.base import (
    Platform,
    PreflightResult,
    podman_exists,
    run_capture,
)


class MacOSPlatform(Platform):
    name = "macos"

    def ensure_runtime(self) -> None:
        if not podman_exists():
            raise RuntimeError(
                "podman not found. Install with one of:\n"
                "  brew install podman                 # via Homebrew\n"
                "  https://podman.io/getting-started   # GUI installer\n"
                "Then run: podman machine init && podman machine start"
            )
        run_capture(["podman", "machine", "start"])
        rc, _, err = run_capture(["podman", "info"])
        if rc != 0:
            raise RuntimeError(
                "podman is not reachable. Run `podman machine start` first.\n"
                f"stderr:\n{err}"
            )

    def preflight(self) -> list[PreflightResult]:
        results: list[PreflightResult] = []

        results.append(_check_binary("podman"))
        results.append(_check_binary("brew", optional=True))

        # Architecture matters because the matching .pkg / Homebrew bottle
        # has to align (Apple Silicon vs Intel). We don't fail on mismatch —
        # Rosetta 2 makes amd64 binaries run on arm64 — but it's worth
        # surfacing.
        arch = _platform.machine()
        results.append(PreflightResult(
            "host architecture",
            ok=True,
            detail=f"{arch} ({'Apple Silicon' if arch == 'arm64' else 'Intel'})",
        ))

        # Podman machine status. On macOS this is mandatory because there's
        # no native container runtime.
        rc, out, _ = run_capture([
            "podman", "machine", "list", "--format", "{{.Name}}\t{{.Running}}",
        ])
        if rc == 0:
            running_any = any("true" in line.lower() for line in out.splitlines())
            results.append(PreflightResult(
                "podman machine running",
                ok=running_any,
                detail=out.strip() or "no machines (run `podman machine init`)",
            ))
        else:
            results.append(PreflightResult(
                "podman machine list",
                ok=False,
                detail="failed",
            ))

        # Apple's Virtualization framework backend is preferred over QEMU.
        # On Podman 5+ it's the default for Apple Silicon. Surfacing it lets
        # operators on older Podman setups know to upgrade for performance.
        rc, info, _ = run_capture([
            "podman", "info", "--format", "{{.Host.OCIRuntime.Name}}",
        ])
        if rc == 0 and info.strip():
            results.append(PreflightResult(
                "podman OCI runtime",
                ok=True,
                detail=info.strip(),
            ))

        # macOS launchd. Only really needs to be present (it always is) —
        # but checking it confirms `hypdmz install-service` will work.
        results.append(_check_binary("launchctl"))

        return results

    def host_path(self, path: Path) -> str:
        return str(path)


def _check_binary(name: str, *, optional: bool = False) -> PreflightResult:
    found = shutil.which(name)
    if found:
        return PreflightResult(f"{name} present", ok=True, detail=found)
    return PreflightResult(
        f"{name} present",
        ok=optional,
        detail="not on PATH" + (" (optional)" if optional else ""),
    )
