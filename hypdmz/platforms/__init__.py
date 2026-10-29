import sys

from hypdmz.platforms.base import Platform


def detect() -> Platform:
    if sys.platform.startswith("linux"):
        from hypdmz.platforms.linux import LinuxPlatform
        return LinuxPlatform()
    if sys.platform == "win32":
        from hypdmz.platforms.windows import WindowsPlatform
        return WindowsPlatform()
    if sys.platform == "darwin":
        from hypdmz.platforms.macos import MacOSPlatform
        return MacOSPlatform()
    raise RuntimeError(f"unsupported platform: {sys.platform}")
