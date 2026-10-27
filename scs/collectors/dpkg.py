"""Debian/Ubuntu packages from /var/lib/dpkg/status (read directly, nothing executed).

Advisories (USN/DSA via OSV) are keyed by *source* package, so binary packages
are grouped by (source, source version). Each Package keeps its binaries for
the upgrade commands, plus the reverse-dependency graph for chains.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from scs.collectors import Collector, Context
from scs.graph import DepGraph, finalize
from scs.models import Package
from scs.osinfo import deb_ecosystem

DPKG_STATUS = Path(os.environ.get("SCS_DPKG_STATUS", "/var/lib/dpkg/status"))


def parse_status(text: str) -> list[dict]:
    pkgs, cur, last = [], {}, None
    for line in text.splitlines():
        if not line.strip():
            if cur:
                pkgs.append(cur)
            cur, last = {}, None
            continue
        if line[0] in " \t":
            if last:
                cur[last] += "\n" + line.strip()
            continue
        k, _, v = line.partition(":")
        cur[k] = v.strip()
        last = k
    if cur:
        pkgs.append(cur)
    return [p for p in pkgs if p.get("Status", "").endswith(" installed") and p.get("Package") and p.get("Version")]


def _dep_names(field: str) -> list[str]:
    out = []
    for alt in field.split(","):
        first = alt.split("|")[0].strip()
        m = re.match(r"^([a-z0-9][a-z0-9+.\-]*)", first)
        if m:
            out.append(m.group(1))
    return out


def collect_status(status: dict[str, str] | None, text: str, eco: str) -> tuple[list[Package], DepGraph]:
    entries = parse_status(text)
    groups: dict[tuple[str, str], list[dict]] = {}
    src_of: dict[str, tuple[str, str]] = {}
    for e in entries:
        src, src_ver = e["Package"], e["Version"]
        if e.get("Source"):
            m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", e["Source"])
            if m:
                src = m.group(1)
                src_ver = m.group(2) or e["Version"]
        groups.setdefault((src, src_ver), []).append(e)
        src_of[e["Package"]] = (src, src_ver)

    g = DepGraph()
    pkgs = []
    for (src, ver), bins in sorted(groups.items()):
        node = f"{src}@{ver}"
        g.add_node(node, node)
        pkgs.append(Package(
            ecosystem=eco, name=src, version=ver, source="apt", location=str(DPKG_STATUS), scope="global",
            meta={"node": node, "kind": "deb", "binaries": [{"name": b["Package"], "version": b["Version"],
                                                             "arch": b.get("Architecture", "")} for b in bins],
                  "essential": any(b.get("Essential") == "yes" or b.get("Priority") == "required" for b in bins)},
        ))
    # edges: a binary's Depends/Pre-Depends point at other binaries -> their source nodes
    for e in entries:
        parent = "{}@{}".format(*src_of[e["Package"]])
        for field in ("Pre-Depends", "Depends"):
            for dep in _dep_names(e.get(field, "")):
                if dep in src_of:
                    g.add_edge(parent, "{}@{}".format(*src_of[dep]))
    return pkgs, g


def auto_installed() -> set[str]:
    """Binary packages apt installed only as dependencies (apt's extended_states)."""
    p = Path("/var/lib/apt/extended_states")
    auto = set()
    try:
        cur = None
        for line in p.read_text().splitlines():
            if line.startswith("Package:"):
                cur = line.split(":", 1)[1].strip()
            elif line.startswith("Auto-Installed:") and line.split(":", 1)[1].strip() == "1" and cur:
                auto.add(cur)
    except OSError:
        return set()
    return auto


def _collect(ctx: Context) -> list[Package]:
    eco = deb_ecosystem()
    pkgs, g = collect_status(None, DPKG_STATUS.read_text(errors="replace"), eco or "Debian")
    auto = auto_installed()
    if auto:
        for p in pkgs:
            if any(b["name"] not in auto for b in p.meta["binaries"]):
                g.add_root(p.meta["node"])  # explicitly installed -> chain roots
    finalize(g, pkgs, "dpkg")
    ctx.graphs["dpkg"] = g
    return pkgs


COLLECTOR = Collector("apt", "Debian/Ubuntu packages (dpkg status)", True,
                      lambda ctx: DPKG_STATUS.is_file() and deb_ecosystem() is not None, _collect)
