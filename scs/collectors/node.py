"""Globally installed Node packages (npm, nvm, volta, fnm, pnpm, bun).

Walks node_modules trees and reads package.json, keeping the parent chain so
transitive packages show which top-level tool pulled them in.
"""
from __future__ import annotations

import glob
import json
import os
from pathlib import Path

from scs.collectors import Collector, Context
from scs.models import Package

GLOBAL_DIRS = [
    "/opt/homebrew/lib/node_modules",
    "/usr/local/lib/node_modules",
    "/usr/lib/node_modules",
    "~/.nvm/versions/node/*/lib/node_modules",
    "~/.volta/tools/image/node/*/lib/node_modules",
    "~/.local/share/fnm/node-versions/*/installation/lib/node_modules",
    "~/Library/Application Support/fnm/node-versions/*/installation/lib/node_modules",
    "~/.npm-global/lib/node_modules",
    "~/.local/lib/node_modules",
    "~/Library/pnpm/global/*/node_modules",
    "~/.local/share/pnpm/global/*/node_modules",
    "~/.bun/install/global/node_modules",
    "~/AppData/Roaming/npm/node_modules",
    "~/AppData/Roaming/nvm/v*/node_modules",          # nvm-windows
    "C:/Program Files/nodejs/node_modules",
    "~/scoop/persist/nodejs/bin/node_modules",
]

MAX_DEPTH = 40


def _read_pkg(path: Path) -> tuple[str, str] | None:
    try:
        with open(path / "package.json", "r", encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    name, version = d.get("name"), d.get("version")
    if isinstance(name, str) and isinstance(version, str) and name and version:
        return name, version
    return None


def walk_node_modules(nm: Path, root: str, chain: list[str], seen: set[str],
                      out: list[Package], depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        return
    try:
        entries = list(os.scandir(nm))
    except OSError:
        return
    pkg_dirs: list[Path] = []
    for e in entries:
        if e.name == ".pnpm":
            # pnpm virtual store: .pnpm/<name>@<ver>/node_modules/<name>
            for store in glob.glob(str(Path(e.path) / "*" / "node_modules")):
                walk_node_modules(Path(store), root, chain + ["(pnpm store)"], seen, out, depth + 1)
            continue
        if e.name.startswith("."):
            continue
        if e.name.startswith("@"):
            try:
                pkg_dirs.extend(Path(s.path) for s in os.scandir(e.path) if not s.name.startswith("."))
            except OSError:
                pass
        else:
            pkg_dirs.append(Path(e.path))
    for p in pkg_dirs:
        real = os.path.realpath(p)
        if real in seen:
            continue
        seen.add(real)
        nv = _read_pkg(p)
        if not nv:
            continue
        name, version = nv
        out.append(Package(
            ecosystem="npm", name=name, version=version, source="npm-global", location=str(p),
            scope="global", direct=not chain, chain=list(chain), meta={"root": root},
        ))
        nested = p / "node_modules"
        if nested.is_dir():
            walk_node_modules(nested, root, chain + [name], seen, out, depth + 1)


def global_dirs() -> list[Path]:
    seen, out = set(), []
    for g in GLOBAL_DIRS:
        for d in glob.glob(os.path.expanduser(g)):
            real = os.path.realpath(d)
            if real not in seen and os.path.isdir(real):
                seen.add(real)
                out.append(Path(d))
    return out


def _collect(ctx: Context) -> list[Package]:
    out: list[Package] = []
    seen: set[str] = set()
    for d in global_dirs():
        walk_node_modules(d, str(d), [], seen, out)
    return out


COLLECTOR = Collector("npm-global", "Global Node packages (npm, nvm, volta, fnm, pnpm, bun)", True,
                      lambda ctx: bool(global_dirs()), _collect)
