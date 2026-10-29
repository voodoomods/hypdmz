from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Sequence

from hypdmz.platforms.base import (
    Platform,
    PreflightResult,
    podman_exists,
    run_capture,
)


class LinuxPlatform(Platform):
    name = "linux"

    def ensure_runtime(self) -> None:
        if not podman_exists():
            raise RuntimeError(
                "podman not found. Install with: sudo apt install podman  "
                "(Ubuntu 22.04+) or your distro's equivalent."
            )
        rc, _, err = run_capture(["podman", "info"])
        if rc != 0:
            raise RuntimeError(
                "podman is installed but `podman info` failed.\n"
                f"stderr:\n{err}"
            )

    def preflight(self) -> list[PreflightResult]:
        results: list[PreflightResult] = []

        results.append(_check_binary("podman"))
        results.append(_check_binary("iptables", optional=True))

        rc, out, _ = run_capture(["podman", "info", "--format", "{{.Host.Security.Rootless}}"])
        if rc == 0:
            rootless = out.strip().lower() == "true"
            results.append(PreflightResult(
                "podman runtime mode",
                ok=True,
                detail=f"rootless={rootless}",
            ))
            if rootless:
                results.append(_check_unprivileged_ports())
                results.append(_check_subuid())
        else:
            results.append(PreflightResult("podman info", ok=False, detail="podman info failed"))

        results.append(_check_selinux())
        results.append(_check_apparmor())
        results.append(_check_kernel_module("ip_tables"))

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


def _check_unprivileged_ports() -> PreflightResult:
    path = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
    try:
        value = int(Path(path).read_text().strip())
    except (FileNotFoundError, ValueError):
        return PreflightResult(
            "unprivileged port start",
            ok=False,
            detail=f"could not read {path}",
        )
    needed = [8000, 8002, 8080]
    ok = all(p >= value for p in needed)
    return PreflightResult(
        "unprivileged port start",
        ok=ok,
        detail=(
            f"value={value} (need <=8000 to publish on 8000/8002/8080 rootless)."
            " Fix: sudo sysctl net.ipv4.ip_unprivileged_port_start=80"
            if not ok else f"value={value}"
        ),
    )


def _check_subuid() -> PreflightResult:
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    for path in ("/etc/subuid", "/etc/subgid"):
        try:
            content = Path(path).read_text()
        except OSError:
            return PreflightResult(f"{path} readable", ok=False, detail="missing")
        if user and user not in content:
            return PreflightResult(
                f"{path} entry",
                ok=False,
                detail=(
                    f"no entry for user {user!r}. "
                    f"Fix: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {user}"
                ),
            )
    return PreflightResult("subuid/subgid", ok=True, detail=f"user={user}")


def _check_selinux() -> PreflightResult:
    if not shutil.which("getenforce"):
        return PreflightResult("SELinux", ok=True, detail="not present (Ubuntu/Debian)")
    rc, out, _ = run_capture(["getenforce"])
    state = out.strip() if rc == 0 else "unknown"
    if state.lower() == "enforcing":
        return PreflightResult(
            "SELinux",
            ok=True,
            detail="enforcing — volume mounts will use :Z",
        )
    return PreflightResult("SELinux", ok=True, detail=state)


def _check_apparmor() -> PreflightResult:
    if not Path("/sys/kernel/security/apparmor").exists():
        return PreflightResult("AppArmor", ok=True, detail="not loaded")
    return PreflightResult("AppArmor", ok=True, detail="loaded (Ubuntu default)")


def _check_kernel_module(name: str) -> PreflightResult:
    try:
        modules = Path("/proc/modules").read_text()
    except OSError:
        return PreflightResult(f"kernel module {name}", ok=True, detail="builtin or unreadable")
    if any(line.startswith(name + " ") for line in modules.splitlines()):
        return PreflightResult(f"kernel module {name}", ok=True, detail="loaded")
    return PreflightResult(
        f"kernel module {name}",
        ok=True,
        detail="not loaded (probably builtin — pod-controller will load if needed)",
    )
