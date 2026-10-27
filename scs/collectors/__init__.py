"""Collector registry. Each collector reads package metadata from disk and
returns Package records; none of them execute the packages they inventory."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from scs.config import Config
from scs.models import Package
from scs.util import log


@dataclass
class Context:
    config: Config
    # Filled by the project walker so the python collector can include venvs under roots.
    venvs: list[Path] = field(default_factory=list)
    lockfiles: list[Path] = field(default_factory=list)
    repos: list[Path] = field(default_factory=list)
    build_files: list[Path] = field(default_factory=list)  # wrappers and CI files (malware buildchain check)
    graphs: dict = field(default_factory=dict)  # graph key -> scs.graph.DepGraph
    errors: list[str] = field(default_factory=list)

    def project_dirs(self) -> list[Path]:
        dirs = {*self.repos, *(lf.parent for lf in self.lockfiles), *(v.parent for v in self.venvs)}
        return sorted(dirs)


@dataclass
class Collector:
    id: str
    description: str
    system: bool  # True = global/system install, skipped with --no-system
    available: Callable[[Context], bool]
    collect: Callable[[Context], list[Package]]


def registry() -> list[Collector]:
    from scs.collectors import brew, cargo, dpkg, java, lockfiles, node, python, runtimes, snap, windows
    # lockfiles first: the runtimes collector reads the go.mod files it found
    return [lockfiles.COLLECTOR, brew.COLLECTOR, dpkg.COLLECTOR, snap.SNAP, snap.FLATPAK, windows.PROGRAMS,
            windows.WINGET, windows.CHOCO, windows.SCOOP, python.COLLECTOR, node.COLLECTOR, cargo.COLLECTOR,
            java.COLLECTOR, runtimes.RUNTIMES, runtimes.DEVTOOLS]


def run_collectors(ctx: Context) -> tuple[list[Package], dict[str, dict]]:
    cfg = ctx.config
    packages: list[Package] = []
    stats: dict[str, dict] = {}
    for c in registry():
        if cfg.collectors and c.id not in cfg.collectors:
            continue
        if c.system and not cfg.system:
            continue
        if not c.available(ctx):
            stats[c.id] = {"status": "unavailable", "count": 0, "seconds": 0}
            continue
        t0 = time.time()
        try:
            found = c.collect(ctx)
        except Exception as e:  # a broken collector must not kill the scan
            ctx.errors.append(f"{c.id}: {e!r}")
            log(f"collector {c.id} failed: {e!r}")
            stats[c.id] = {"status": "error", "count": 0, "seconds": round(time.time() - t0, 1)}
            continue
        packages.extend(found)
        stats[c.id] = {"status": "ok", "count": len(found), "seconds": round(time.time() - t0, 1)}
        log(f"{c.id}: {len(found)} packages")
    return packages, stats
