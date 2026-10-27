"""Is this copy of scs the one that was built? (`scs self-check`, the Home page, every scheduled run)

  macOS app      codesign --verify --deep --strict: every file is sealed by the app's signature
                 (ad-hoc or Developer ID), so any changed, added or removed file fails
  Windows app    the SHA-256 manifest written at build time (scs-manifest.json), plus the
                 Authenticode signature when the build was signed
  Ubuntu .deb    dpkg --verify scs: files compared with the package's md5sums
  source tree    not checked (git shows your own changes)

Only a real code signature (Developer ID, Authenticode) proves *who* built the app; a manifest
or an ad-hoc seal catches files changed after installation, by malware or by accident.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

MANIFEST = "scs-manifest.json"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(folder: str) -> int:
    """Record the SHA-256 of every file of a built app folder (run by the Windows build script)."""
    root = Path(folder)
    files = {p.relative_to(root).as_posix(): _sha256(p) for p in sorted(root.rglob("*"))
             if p.is_file() and p.name != MANIFEST}
    (root / MANIFEST).write_text(json.dumps({"files": files}, indent=0, sort_keys=True), encoding="utf-8")
    print(f"wrote {root / MANIFEST} ({len(files)} files)")
    return 0


def _check_manifest(root: Path) -> tuple[Optional[bool], str]:
    m = root / MANIFEST
    if not m.is_file():
        return False, f"{MANIFEST} is missing: the app folder was changed or not built by the build script"
    want = json.loads(m.read_text(encoding="utf-8"))["files"]
    changed = [rel for rel, digest in want.items()
               if not (root / rel).is_file() or _sha256(root / rel) != digest]
    extra = [p.relative_to(root).as_posix() for p in root.rglob("*")
             if p.is_file() and p.name != MANIFEST and p.relative_to(root).as_posix() not in want
             and "__pycache__" not in p.parts]
    if changed or extra:
        return False, ("changed or missing: " + ", ".join(changed[:5]) if changed else "") + \
               ("; added: " + ", ".join(extra[:5]) if extra else "")
    return True, f"all {len(want)} files match the build manifest"


def _authenticode(exe: str) -> str:
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"(Get-AuthenticodeSignature -LiteralPath '{exe}').Status"],
                           capture_output=True, text=True, timeout=60)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def verify() -> dict:
    """{"ok": True | False | None, "how": ..., "detail": ...}; None = nothing to check here."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        if sys.platform == "darwin":
            app = next((p for p in exe.parents if p.suffix == ".app"), None)
            if not app:
                return {"ok": None, "how": "codesign", "detail": "not inside an .app bundle"}
            r = subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)],
                               capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                return {"ok": False, "how": "codesign", "detail": (r.stderr or r.stdout).strip()[:400]}
            signer = subprocess.run(["codesign", "-dv", str(app)], capture_output=True, text=True, timeout=60).stderr
            kind = "Developer ID" if "Authority=Developer ID" in signer else "ad-hoc (no publisher identity)"
            return {"ok": True, "how": "codesign", "detail": f"signature intact; {kind}"}
        ok, detail = _check_manifest(exe.parent)
        if sys.platform == "win32":
            status = _authenticode(str(exe))
            if status and status not in ("Valid", "NotSigned"):
                return {"ok": False, "how": "authenticode", "detail": f"Authenticode signature status: {status}"}
            detail += f"; Authenticode: {status or 'unknown'}"
        return {"ok": ok, "how": "manifest", "detail": detail}
    here = Path(__file__).resolve()
    if str(here).startswith("/opt/scs/"):
        try:
            r = subprocess.run(["dpkg", "--verify", "scs"], capture_output=True, text=True, timeout=300)
        except OSError:
            return {"ok": None, "how": "dpkg", "detail": "dpkg not available"}
        bad = [ln for ln in r.stdout.splitlines() if ln.strip()]
        if bad or r.returncode != 0:
            return {"ok": False, "how": "dpkg", "detail": "; ".join(bad[:5]) or r.stderr.strip()[:300]}
        return {"ok": True, "how": "dpkg", "detail": "all files match the package's checksums"}
    return {"ok": None, "how": "source", "detail": f"running from source in {here.parent.parent}"}


def cmd_self_check(args) -> int:
    if getattr(args, "write_manifest", None):
        return write_manifest(args.write_manifest)
    res = verify()
    label = {True: "OK", False: "FAILED", None: "not checked"}[res["ok"]]
    print(f"scs integrity ({res['how']}): {label} — {res['detail']}")
    return 1 if res["ok"] is False else 0


def add_parser(sub) -> None:
    p = sub.add_parser("self-check", help="check that this copy of scs has not been modified since it was built")
    p.add_argument("--write-manifest", metavar="DIR", help=argparse.SUPPRESS)  # used by the Windows build script
    p.set_defaults(func=cmd_self_check)
