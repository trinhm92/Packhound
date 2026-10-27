"""Homebrew formulae and casks (macOS and Linuxbrew)."""
from __future__ import annotations

import json
import re
import shutil

from scs.collectors import Collector, Context
from scs.graph import DepGraph, finalize
from scs.models import Package
from scs.util import run

BREW_ENV = {"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ENV_HINTS": "1"}


def _available(ctx: Context) -> bool:
    return shutil.which("brew") is not None


def _collect(ctx: Context) -> list[Package]:
    out = run(["brew", "info", "--json=v2", "--installed"], timeout=300, env_extra=BREW_ENV)
    if not out:
        raise RuntimeError("`brew info --json=v2 --installed` failed")
    data = json.loads(out)
    prefix = (run(["brew", "--prefix"], env_extra=BREW_ENV) or "").strip()

    formulae = data.get("formulae", [])
    used_by: dict[str, list[str]] = {}
    installed_names = {f["name"] for f in formulae}
    for f in formulae:
        for dep in f.get("dependencies", []):
            if dep in installed_names:
                used_by.setdefault(dep, []).append(f["name"])

    pkgs: list[Package] = []
    for f in formulae:
        for inst in f.get("installed", []):
            raw = inst.get("version", "")
            version = re.sub(r"_\d+$", "", raw)  # strip bottle revision suffix
            pkgs.append(Package(
                ecosystem="Homebrew", name=f["name"], version=version, source="brew",
                location=f"{prefix}/Cellar/{f['name']}/{raw}", scope="global",
                direct=bool(inst.get("installed_on_request")),
                meta={
                    "kind": "formula",
                    "latest": (f.get("versions") or {}).get("stable"),
                    "outdated": bool(f.get("outdated")),
                    "pinned": bool(f.get("pinned")),
                    "deps": f.get("dependencies", []),
                    "used_by": sorted(used_by.get(f["name"], [])),
                    "aliases": f.get("aliases", []),
                    "homepage": f.get("homepage"),
                },
            ))
    g = DepGraph()
    for p in pkgs:
        p.meta["node"] = p.name
        g.add_node(p.name, f"{p.name}@{p.version}")
        if p.direct:
            g.add_root(p.name)
    for p in pkgs:
        for dep in p.meta["deps"]:
            if dep in installed_names:
                g.add_edge(p.name, dep)
    finalize(g, pkgs, "brew")
    ctx.graphs["brew"] = g

    for c in data.get("casks", []):
        version = c.get("installed") or ""
        if not version:
            continue
        pkgs.append(Package(
            ecosystem="Homebrew-cask", name=c["token"], version=version, source="brew",
            location=f"{prefix}/Caskroom/{c['token']}/{version}", scope="global", direct=True,
            meta={
                "kind": "cask",
                "latest": c.get("version"),
                "outdated": bool(c.get("outdated")),
                "auto_updates": bool(c.get("auto_updates")),
                "homepage": c.get("homepage"),
            },
        ))
    return pkgs


COLLECTOR = Collector("brew", "Homebrew formulae and casks", True, _available, _collect)
