"""Windows inventory: winget, Chocolatey, Scoop and installed programs (registry Uninstall keys).

None of these ecosystems is covered by OSV. Installed programs that map to a
known CPE product are matched against NVD with --nvd (low confidence), and
every source reports pending updates as "outdated".
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
from pathlib import Path

from scs.collectors import Collector, Context
from scs.models import Package
from scs.util import run
from scs.versions import vkey
from scs.windows import Registry, registry

UNINSTALL_KEYS = [("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                  ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                  ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")]

# DisplayName pattern -> (CPE vendor, CPE product) for NVD matching of common tools
CPE_MAP: list[tuple[re.Pattern, tuple[str, str]]] = [(re.compile(p, re.I), v) for p, v in [
    (r"^Git(\s+version|\s*$|\s+\d)", ("git-scm", "git")), (r"^Python 3\.\d+\.\d+", ("python", "python")),
    (r"^Node\.js$", ("nodejs", "node.js")), (r"^7-Zip", ("7-zip", "7-zip")), (r"^PuTTY", ("putty", "putty")),
    (r"^WinSCP", ("winscp", "winscp")), (r"^Wireshark", ("wireshark", "wireshark")),
    (r"^VLC media player", ("videolan", "vlc_media_player")), (r"^FileZilla", ("filezilla-project", "filezilla_client")),
    (r"^Docker Desktop", ("docker", "desktop")), (r"^Google Chrome$", ("google", "chrome")),
    (r"^Mozilla Firefox", ("mozilla", "firefox")), (r"^WinRAR", ("rarlab", "winrar")),
    (r"^Microsoft Visual Studio Code", ("microsoft", "visual_studio_code")), (r"^OpenVPN", ("openvpn", "openvpn")),
    (r"^KeePass", ("keepass", "keepass")), (r"^OpenSSL", ("openssl", "openssl")),
]]


def cpe_for_app(display_name: str) -> tuple[str, str] | None:
    for pat, cpe in CPE_MAP:
        if pat.search(display_name):
            return cpe
    return None


def normalize_app_version(name: str, version: str) -> str:
    """python.org installers report 3.12.4150.0 for 3.12.4 (micro*1000 + release level)."""
    m = re.match(r"^(\d+)\.(\d+)\.(\d{4,})(?:\.0)?$", version)
    if m and name.lower().startswith("python"):
        return f"{m.group(1)}.{m.group(2)}.{int(m.group(3)) // 1000}"
    return version


# ---------------------------------------------------------------- registry programs

def installed_programs(reg: Registry) -> list[Package]:
    pkgs, seen = [], set()
    for hive, path in UNINSTALL_KEYS:
        for sub in reg.subkeys(hive, path):
            v = reg.values(hive, f"{path}\\{sub}")
            name = str(v.get("DisplayName") or "").strip()
            version = str(v.get("DisplayVersion") or "").strip()
            if not name or v.get("SystemComponent") == 1 or v.get("ParentKeyName") \
                    or str(v.get("ReleaseType", "")).lower() in ("update", "hotfix", "security update"):
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            icon = str(v.get("DisplayIcon") or "").split(",")[0].strip('"')
            meta = {"kind": "program", "publisher": v.get("Publisher", ""), "hive": hive, "key": f"{hive}\\{path}\\{sub}",
                    "install_location": v.get("InstallLocation", ""), "exe": icon if icon.lower().endswith(".exe") else "",
                    "uninstall": str(v.get("UninstallString") or "")[:300]}
            cpe = cpe_for_app(name)
            if cpe:
                meta["cpe"] = cpe
            pkgs.append(Package(ecosystem="Windows-app", name=name, version=normalize_app_version(name, version) or "?",
                                source="programs", location=meta["key"], scope="global", direct=True, meta=meta))
    return pkgs


# ---------------------------------------------------------------- winget

def parse_table(text: str) -> list[list[str]]:
    """Fixed-width tables printed by winget (positions come from the header; works for any UI language)."""
    lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    lines = [ln.split("\r")[-1] for ln in lines]  # drop progress-spinner frames
    for i in range(len(lines) - 1):
        if re.match(r"^-{10,}$", lines[i + 1].strip()) and lines[i].strip():
            header, body = lines[i], lines[i + 2:]
            break
    else:
        return []
    starts = [m.start() for m in re.finditer(r"\S+", header)]
    rows = []
    min_len = starts[min(2, len(starts) - 1)]
    for ln in body:
        if len(ln) <= min_len:
            continue  # blank or summary lines ("2 upgrades available.") never reach the Version column
        cells = []
        for j, s in enumerate(starts):
            e = starts[j + 1] if j + 1 < len(starts) else None
            cells.append(ln[s:e].strip() if s < len(ln) else "")
        rows.append(cells)
    return rows


def winget_packages(list_text: str, upgrade_text: str) -> list[Package]:
    upgrades = {}
    for r in parse_table(upgrade_text):
        if len(r) >= 5:
            upgrades[r[1]] = r[3]
    pkgs = []
    for r in parse_table(list_text):
        if len(r) < 4:
            continue
        name, pid, version = r[0], r[1], r[2]
        source = r[-1]
        if source.lower() != "winget" or not pid or "\\" in pid:
            continue  # ARP/MSIX entries without a winget source are covered by the programs collector
        pkgs.append(Package(ecosystem="winget", name=pid, version=version, source="winget", location=f"winget:{pid}",
                            scope="global", direct=True,
                            meta={"kind": "winget", "display": name.rstrip("…"), "latest": upgrades.get(pid),
                                  "outdated": pid in upgrades}))
    return pkgs


def _winget(ctx: Context) -> list[Package]:
    lst = run(["winget", "list", "--disable-interactivity"], timeout=180) or ""
    upg = run(["winget", "upgrade", "--disable-interactivity", "--include-unknown"], timeout=180) or ""
    return winget_packages(lst, upg)


# ---------------------------------------------------------------- chocolatey

def choco_packages(list_text: str, outdated_text: str) -> list[Package]:
    outdated = {}
    for ln in outdated_text.splitlines():
        parts = ln.strip().split("|")
        if len(parts) >= 3:
            outdated[parts[0].lower()] = (parts[2], len(parts) > 3 and parts[3].lower() == "true")
    pkgs = []
    for ln in list_text.splitlines():
        parts = ln.strip().split("|")
        if len(parts) != 2 or not parts[1][:1].isdigit():
            continue
        name, version = parts
        latest, pinned = outdated.get(name.lower(), (None, False))
        pkgs.append(Package(ecosystem="chocolatey", name=name, version=version, source="choco",
                            location=f"choco:{name}", scope="global", direct=True,
                            meta={"kind": "choco", "latest": latest, "outdated": latest is not None, "pinned": pinned}))
    return pkgs


def _choco(ctx: Context) -> list[Package]:
    lst = run(["choco", "list", "--limit-output"], timeout=180) or ""
    out = run(["choco", "outdated", "--limit-output", "--ignore-unfound"], timeout=300) or ""
    return choco_packages(lst, out)


# ---------------------------------------------------------------- scoop (read from disk)

def scoop_roots() -> list[Path]:
    roots = [os.environ.get("SCOOP") or os.path.expanduser("~/scoop"),
             os.environ.get("SCOOP_GLOBAL") or os.path.join(os.environ.get("ProgramData", "C:/ProgramData"), "scoop")]
    return [Path(r) for r in dict.fromkeys(roots) if Path(r, "apps").is_dir()]


def scoop_packages(roots: list[Path]) -> list[Package]:
    pkgs = []
    for root in roots:
        for app_dir in sorted((root / "apps").iterdir()):
            cur = app_dir / "current"
            try:
                manifest = json.loads((cur / "manifest.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            version = manifest.get("version", "")
            bucket = ""
            try:
                bucket = json.loads((cur / "install.json").read_text(encoding="utf-8")).get("bucket", "")
            except (OSError, ValueError):
                pass
            latest = None
            for bm in glob.glob(str(root / "buckets" / (bucket or "*") / "bucket" / f"{app_dir.name}.json")):
                try:
                    latest = json.loads(Path(bm).read_text(encoding="utf-8")).get("version")
                    break
                except (OSError, ValueError):
                    continue
            versions = sorted([d.name for d in app_dir.iterdir() if d.is_dir() and d.name != "current"], key=vkey)
            pkgs.append(Package(ecosystem="scoop", name=app_dir.name, version=version, source="scoop",
                                location=str(app_dir), scope="global", direct=True,
                                meta={"kind": "scoop", "bucket": bucket, "latest": latest,
                                      "outdated": bool(latest and vkey(latest) > vkey(version)),
                                      "installed_versions": versions, "root": str(root)}))
    return pkgs


PROGRAMS = Collector("programs", "Windows installed programs (registry Uninstall keys)", True,
                     lambda ctx: os.name == "nt", lambda ctx: installed_programs(registry()))
WINGET = Collector("winget", "winget packages (with pending upgrades)", True,
                   lambda ctx: shutil.which("winget") is not None, _winget)
CHOCO = Collector("choco", "Chocolatey packages (with outdated)", True,
                  lambda ctx: shutil.which("choco") is not None, _choco)
SCOOP = Collector("scoop", "Scoop apps (read from ~/scoop, with bucket updates)", True,
                  lambda ctx: bool(scoop_roots()), lambda ctx: scoop_packages(scoop_roots()))
