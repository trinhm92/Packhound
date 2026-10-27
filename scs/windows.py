"""Windows helpers: registry access, PowerShell JSON queries, Authenticode, elevation.

Everything Windows-specific goes through `Registry` and `powershell_json` so the
collectors and audits can be tested on any OS with fixture data.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Optional

HIVES = ("HKLM", "HKCU")


class Registry:
    """Minimal read-only registry interface."""

    def subkeys(self, hive: str, path: str) -> list[str]:
        raise NotImplementedError

    def values(self, hive: str, path: str) -> dict[str, Any]:
        raise NotImplementedError


class LiveRegistry(Registry):
    def __init__(self):
        import winreg  # type: ignore[import-not-found]
        self.w = winreg
        self.roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}

    def _open(self, hive: str, path: str):
        return self.w.OpenKey(self.roots[hive], path, 0, self.w.KEY_READ)

    def subkeys(self, hive: str, path: str) -> list[str]:
        out = []
        try:
            with self._open(hive, path) as k:
                i = 0
                while True:
                    try:
                        out.append(self.w.EnumKey(k, i))
                    except OSError:
                        break
                    i += 1
        except OSError:
            pass
        return out

    def values(self, hive: str, path: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        try:
            with self._open(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = self.w.EnumValue(k, i)
                    except OSError:
                        break
                    out[name] = val
                    i += 1
        except OSError:
            pass
        return out


class FakeRegistry(Registry):
    """{"HKLM\\path\\to\\key": {"name": value, ...}}; subkeys are derived from the key paths."""

    def __init__(self, data: dict[str, dict[str, Any]]):
        self.data = {k.lower(): (k, v) for k, v in data.items()}

    def subkeys(self, hive: str, path: str) -> list[str]:
        prefix = f"{hive}\\{path}\\".lower()
        out = []
        for low, (orig, _) in self.data.items():
            if low.startswith(prefix):
                child = orig[len(prefix):].split("\\")[0]
                if child not in out:
                    out.append(child)
        return out

    def values(self, hive: str, path: str) -> dict[str, Any]:
        return dict(self.data.get(f"{hive}\\{path}".lower(), (None, {}))[1])


def registry() -> Optional[Registry]:
    if os.name != "nt":
        return None
    try:
        return LiveRegistry()
    except ImportError:
        return None


def powershell() -> Optional[str]:
    return shutil.which("pwsh") or shutil.which("powershell")


def powershell_json(script: str, timeout: int = 120) -> Any:
    """Run a PowerShell snippet whose output is ConvertTo-Json; returns parsed JSON or None."""
    exe = powershell()
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = r.stdout.strip()
    if not out:
        return None
    try:
        data = json.loads(out)
    except ValueError:
        return None
    return data


def as_list(data: Any) -> list:
    """ConvertTo-Json emits a bare object for one result and an array for several."""
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


AUTHENTICODE_PS = r"""
$paths = Get-Content -LiteralPath '{list}'
$out = foreach ($p in $paths) {{
  try {{
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    [pscustomobject]@{{ Path = $p; Status = [string]$s.Status;
      Subject = if ($s.SignerCertificate) {{ $s.SignerCertificate.Subject }} else {{ '' }};
      Thumbprint = if ($s.SignerCertificate) {{ $s.SignerCertificate.Thumbprint }} else {{ '' }} }}
  }} catch {{ [pscustomobject]@{{ Path = $p; Status = 'Error'; Subject = ''; Thumbprint = '' }} }}
}}
$out | ConvertTo-Json -Compress -Depth 3
"""


def authenticode(paths: list[str]) -> dict[str, dict]:
    """Batch Get-AuthenticodeSignature (one PowerShell start for all files)."""
    paths = [p for p in dict.fromkeys(paths) if p and os.path.isfile(p)]
    if not paths or not powershell():
        return {}
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("\n".join(paths))
    try:
        data = powershell_json(AUTHENTICODE_PS.format(list=f.name.replace("'", "''")), timeout=600)
    finally:
        os.unlink(f.name)
    return {d["Path"]: {"status": d.get("Status", ""), "subject": d.get("Subject", ""),
                        "thumbprint": d.get("Thumbprint", "")} for d in as_list(data) if isinstance(d, dict)}


def signer_name(subject: str) -> str:
    """'CN=Microsoft Corporation, O=Microsoft Corporation, …' -> 'Microsoft Corporation'."""
    for part in subject.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip('"')
    return subject


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def expand(s: str) -> str:
    """Expand %VARS% the way Windows does (also works in tests on other OSes)."""
    return os.path.expandvars(s) if os.name == "nt" else _expand_percent(s)


def _expand_percent(s: str) -> str:
    import re
    return re.sub(r"%([^%]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), s)


def exe_from_command(cmd: str) -> str:
    """Executable path from a Windows command line ('"C:\\a b\\x.exe" -arg', 'C:\\x.exe /s', 'rundll32 a.dll,f')."""
    cmd = expand(cmd.strip())
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    low = cmd.lower()
    for ext in (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".scr"):
        i = low.find(ext)
        if i != -1:
            return cmd[:i + len(ext)]
    return cmd.split(" ")[0]
