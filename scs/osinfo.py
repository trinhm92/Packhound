"""Operating-system identification (/etc/os-release) and the matching OSV ecosystem."""
from __future__ import annotations

import os
import platform
from pathlib import Path

OS_RELEASE = Path(os.environ.get("SCS_OS_RELEASE", "/etc/os-release"))


def os_release(path: Path | None = None) -> dict[str, str]:
    p = path or OS_RELEASE
    out: dict[str, str] = {}
    try:
        for line in p.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def deb_ecosystem(info: dict[str, str] | None = None) -> str | None:
    """'Ubuntu:24.04:LTS', 'Ubuntu:24.10', 'Debian:12' — or None if not a Debian-family system."""
    info = info if info is not None else os_release()
    distro = info.get("ID", "").lower()
    like = info.get("ID_LIKE", "").lower().split()
    ver = info.get("VERSION_ID", "")
    if distro == "ubuntu" or ("ubuntu" in like and info.get("UBUNTU_CODENAME")):
        if distro != "ubuntu":  # derivatives (Mint, Pop!_OS…) track an Ubuntu base
            ver = _ubuntu_version_for(info.get("UBUNTU_CODENAME", "")) or ver
        lts = "LTS" in info.get("VERSION", "") or (ver.endswith(".04") and int(ver.split(".")[0]) % 2 == 0)
        return f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"
    if distro == "debian" or "debian" in like:
        return f"Debian:{ver.split('.')[0]}" if ver else None
    return None


_UBUNTU_CODENAMES = {"focal": "20.04", "jammy": "22.04", "noble": "24.04", "oracular": "24.10",
                     "plucky": "25.04", "questing": "25.10", "resolute": "26.04"}


def _ubuntu_version_for(codename: str) -> str | None:
    return _UBUNTU_CODENAMES.get(codename.lower())


def is_linux() -> bool:
    return platform.system() == "Linux"


def is_deb_ecosystem(eco: str) -> bool:
    return eco.startswith(("Ubuntu:", "Debian:"))
