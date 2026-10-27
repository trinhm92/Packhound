"""Python packages in every interpreter / environment we can find.

Reads *.dist-info/METADATA directly instead of running `pip list`, so no
interpreter starts and no (possibly malicious) .pth file executes.
"""
from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from scs.collectors import Collector, Context
from scs.graph import DepGraph, finalize
from scs.models import Package, normalize_name

SITE_GLOBS = [
    # Windows: python.org per-user / all-users installs, user site, pyenv-win, conda
    "~/AppData/Local/Programs/Python/Python3*/Lib/site-packages",
    "~/AppData/Roaming/Python/Python3*/site-packages",
    "C:/Program Files/Python3*/Lib/site-packages",
    "C:/Python3*/Lib/site-packages",
    "~/.pyenv/pyenv-win/versions/*/Lib/site-packages",
    "~/miniconda3/Lib/site-packages", "~/anaconda3/Lib/site-packages",
    "~/pipx/venvs/*/Lib/site-packages",
    # pyenv / asdf / mise
    "~/.pyenv/versions/*/lib/python3*/site-packages",
    "~/.pyenv/versions/*/envs/*/lib/python3*/site-packages",
    "~/.asdf/installs/python/*/lib/python3*/site-packages",
    "~/.local/share/mise/installs/python/*/lib/python3*/site-packages",
    # Homebrew / python.org / Command Line Tools (macOS)
    "/opt/homebrew/lib/python3*/site-packages",
    "/usr/local/lib/python3*/site-packages",
    "/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/*/lib/python3*/site-packages",
    "~/Library/Python/3*/lib/python/site-packages",
    # Linux user / local installs (apt-managed dist-packages are left to the dpkg collector)
    "~/.local/lib/python3*/site-packages",
    "/usr/local/lib/python3*/dist-packages",
    # conda family
    "~/miniconda3/lib/python3*/site-packages", "~/miniconda3/envs/*/lib/python3*/site-packages",
    "~/anaconda3/lib/python3*/site-packages", "~/anaconda3/envs/*/lib/python3*/site-packages",
    "~/miniforge3/lib/python3*/site-packages", "~/miniforge3/envs/*/lib/python3*/site-packages",
    "~/opt/anaconda3/lib/python3*/site-packages", "~/opt/anaconda3/envs/*/lib/python3*/site-packages",
    # pipx / uv tools
    "~/.local/pipx/venvs/*/lib/python3*/site-packages",
    "~/.local/share/pipx/venvs/*/lib/python3*/site-packages",
    "~/.local/share/uv/tools/*/lib/python3*/site-packages",
    "~/.local/share/uv/python/*/lib/python3*/site-packages",
]


def _read_metadata(path: Path) -> tuple[str, str, list[str]] | None:
    """Name, Version and non-extra Requires-Dist names from the metadata headers."""
    name = version = None
    requires: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    break  # end of headers
                if line.startswith("Name:") and name is None:
                    name = line[5:].strip()
                elif line.startswith("Version:") and version is None:
                    version = line[8:].strip()
                elif line.startswith("Requires-Dist:") and "extra ==" not in line:
                    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line[14:])
                    if m:
                        requires.append(m.group(1))
    except OSError:
        return None
    return (name, version, requires) if name and version else None


def _env_prefix(site: Path) -> Path:
    # .../<prefix>/lib/python3.X/site-packages -> <prefix>
    if site.parent.parent.name == "lib":
        return site.parent.parent.parent
    # Windows: <prefix>\Lib\site-packages -> <prefix>
    if site.parent.name.lower() == "lib":
        return site.parent.parent
    return site.parent


def site_dirs(ctx: Context) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    candidates: list[str] = []
    if ctx.config.system:
        for g in SITE_GLOBS:
            candidates.extend(glob.glob(os.path.expanduser(g)))
    for venv in ctx.venvs:
        candidates.extend(glob.glob(str(venv / "lib" / "python3*" / "site-packages")))
        candidates.extend(glob.glob(str(venv / "Lib" / "site-packages")))  # Windows venv layout
    for c in candidates:
        real = os.path.realpath(c)
        if real not in seen and os.path.isdir(real):
            seen.add(real)
            out.append(Path(c))
    return out


def env_graph(pkgs: list[Package], requires: dict[str, list[str]]) -> DepGraph:
    """Requires-Dist graph; packages nothing else requires are treated as direct installs."""
    g = DepGraph()
    by_name = {}
    for p in pkgs:
        node = normalize_name("PyPI", p.name)
        p.meta["node"] = node
        g.add_node(node, f"{p.name}@{p.version}")
        by_name[node] = p
    for node, reqs in requires.items():
        for r in reqs:
            child = normalize_name("PyPI", r)
            if child in by_name:
                g.add_edge(node, child)
    rev = g.reverse()
    for node in by_name:
        if not rev.get(node):
            g.add_root(node)
    return g


def scan_site(site: Path, scope: str, graphs: dict | None = None) -> list[Package]:
    pkgs: list[Package] = []
    requires: dict[str, list[str]] = {}
    prefix = _env_prefix(site)
    m = re.search(r"python(\d+\.\d+)", str(site)) or \
        re.search(r"[/\\]Python[/\\](\d+\.\d+)[/\\]lib[/\\]python[/\\]site-packages", str(site))  # macOS user site
    if not m:  # Windows layouts: ...\Python312\Lib\site-packages
        w = re.search(r"[Pp]ython(3)(\d{1,2})\b", str(site))
        m = re.match(r"(.*)", f"{w.group(1)}.{w.group(2)}") if w else None
    # the versioned name first: one prefix can hold several Pythons (Homebrew python3.11 and python3.12)
    candidates = [prefix / "bin" / n for n in ([f"python{m.group(1)}"] if m else []) + ["python", "python3"]]
    candidates += [prefix / "python.exe", prefix / "Scripts" / "python.exe"]
    python = next((c for c in candidates if c.exists()), prefix / "bin" / "python")
    try:
        entries = list(os.scandir(site))
    except OSError:
        return pkgs
    for e in entries:
        if e.name.endswith(".dist-info"):
            meta = Path(e.path) / "METADATA"
        elif e.name.endswith(".egg-info"):
            meta = Path(e.path) / "PKG-INFO" if e.is_dir() else Path(e.path)
        else:
            continue
        nv = _read_metadata(meta)
        if not nv:
            continue
        name, version, reqs = nv
        extra = {"env": str(prefix), "python": str(python)}
        if m:
            extra["runtime"] = m.group(1)
        if (Path(e.path) / "direct_url.json").exists():
            extra["direct_url"] = True  # editable / VCS / local install
        requires[normalize_name("PyPI", name)] = reqs
        pkgs.append(Package(
            ecosystem="PyPI", name=name, version=version, source="pip", location=str(site),
            scope=scope, meta=extra,
        ))
    if graphs is not None and pkgs:
        g = env_graph(pkgs, requires)
        finalize(g, pkgs, str(site))
        graphs[str(site)] = g
    return pkgs


def _collect(ctx: Context) -> list[Package]:
    venv_set = {os.path.realpath(v) for v in ctx.venvs}
    pkgs: list[Package] = []
    for site in site_dirs(ctx):
        prefix = os.path.realpath(_env_prefix(site))
        scope = "project" if prefix in venv_set else "global"
        pkgs.extend(scan_site(site, scope, ctx.graphs))
    return pkgs


COLLECTOR = Collector("pip", "Python site-packages (pyenv, brew, conda, pipx, venvs)", False,
                      lambda ctx: True, _collect)
