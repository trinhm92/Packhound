"""IOC packs: known-bad package versions and file indicators for specific campaigns.

Pack format (JSON):
{
  "id": "npm-chalk-debug-2025-09", "name": "...", "description": "...",
  "severity": "CRITICAL", "references": ["https://..."],
  "packages": [{"ecosystem": "npm", "name": "chalk", "versions": ["5.6.1"]}],
  "files": [".github/workflows/x.yml", "~/absolute/or/home/path"],
  "filenames": ["setup_bun.js"],              # file names inside installed packages
  "sha256": ["<hex digest>"],                 # hashes of install scripts / payloads
  "extensions": [{"ecosystem": "vscode", "id": "publisher.name"}, {"ecosystem": "chrome", "id": "<32-char id>"}]
}
Relative file patterns are checked inside every project/repo found under --root.
filenames / sha256 / extensions are used by `scs malware`.
"""
from __future__ import annotations

import glob
import os
from pathlib import Path

from scs.models import Advisory, Package, normalize_name
from scs.util import log, read_json

BUNDLED = Path(__file__).resolve().parent.parent / "iocs"
USER_DIR = Path("~/.config/scs/iocs").expanduser()


def load_packs(extra_dirs: list[str]) -> list[dict]:
    packs = []
    for d in [BUNDLED, USER_DIR, *(Path(os.path.expanduser(x)) for x in extra_dirs)]:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.json")):
            try:
                data = read_json(f)
            except Exception as e:
                log(f"bad IOC pack {f}: {e}")
                continue
            for pack in data if isinstance(data, list) else [data]:
                pack["_file"] = str(f)
                packs.append(pack)
    return packs


def match_packages(packs: list[dict], pkgs: list[Package]) -> dict:
    index: dict[tuple[str, str, str], list[dict]] = {}
    for pack in packs:
        for entry in pack.get("packages", []):
            eco = entry["ecosystem"]
            for v in entry.get("versions", []):
                index.setdefault((eco, normalize_name(eco, entry["name"]), v), []).append(pack)
    out: dict = {}
    for p in pkgs:
        for pack in index.get(p.key, []):
            out.setdefault(p.key, []).append(Advisory(
                id=f"IOC:{pack['id']}", summary=pack.get("name", pack["id"]), severity="CRITICAL",
                malicious=True, source="ioc", references=pack.get("references", [])[:8],
            ))
    return out


def malware_indicators(packs: list[dict]) -> dict[str, dict[str, str]]:
    """Index filename / sha256 / extension IOCs -> pack id."""
    out: dict[str, dict[str, str]] = {"filenames": {}, "sha256": {}, "extensions": {}}
    for pack in packs:
        for n in pack.get("filenames", []):
            out["filenames"][n] = pack["id"]
        for h in pack.get("sha256", []):
            out["sha256"][h.lower()] = pack["id"]
        for e in pack.get("extensions", []):
            out["extensions"][e["id"].lower() if e.get("ecosystem") == "vscode" else e["id"]] = pack["id"]
    return out


def match_files(packs: list[dict], project_dirs: list[Path]) -> list[dict]:
    hits = []
    for pack in packs:
        for pattern in pack.get("files", []):
            if pattern.startswith(("~", "/")):
                paths = glob.glob(os.path.expanduser(pattern))
            else:
                paths = [m for d in project_dirs for m in glob.glob(str(d / pattern))]
            for path in sorted(set(paths)):
                hits.append({"pack": pack["id"], "name": pack.get("name", ""), "path": path,
                             "references": pack.get("references", [])})
    return hits
