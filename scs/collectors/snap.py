"""Snap and Flatpak applications (inventory + pending updates; no OSV ecosystem exists for them)."""
from __future__ import annotations

import shutil

from scs.collectors import Collector, Context
from scs.models import Package
from scs.util import run


def parse_snap_list(text: str) -> list[dict]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines or not lines[0].startswith("Name"):
        return []
    out = []
    for ln in lines[1:]:
        cols = ln.split()
        if len(cols) >= 5:
            out.append({"name": cols[0], "version": cols[1], "rev": cols[2], "tracking": cols[3],
                        "publisher": cols[4], "notes": cols[5] if len(cols) > 5 else ""})
    return out


def _snaps(ctx: Context) -> list[Package]:
    items = parse_snap_list(run(["snap", "list", "--unicode=never", "--color=never"], timeout=60) or "")
    pending = {r["name"] for r in parse_snap_list(run(["snap", "refresh", "--list", "--unicode=never"], timeout=120) or "")}
    pkgs = []
    for s in items:
        pkgs.append(Package(
            ecosystem="Snap", name=s["name"], version=s["version"], source="snap", location="/snap/" + s["name"],
            scope="global", direct=True,
            meta={"kind": "snap", "rev": s["rev"], "tracking": s["tracking"], "publisher": s["publisher"],
                  # '*' / '**' mark verified / starred publishers in --unicode=never output
                  "verified_publisher": s["publisher"].endswith("*"), "outdated": s["name"] in pending,
                  "classic": "classic" in s["notes"], "devmode": "devmode" in s["notes"]}))
    return pkgs


def _flatpaks(ctx: Context) -> list[Package]:
    out = run(["flatpak", "list", "--app", "--columns=application,version,branch,origin"], timeout=60) or ""
    upd = run(["flatpak", "remote-ls", "--updates", "--columns=application"], timeout=120) or ""
    pending = {ln.strip() for ln in upd.splitlines() if ln.strip()}
    pkgs = []
    for ln in out.splitlines():
        cols = ln.split("\t")
        if len(cols) >= 4 and cols[0] and cols[0] != "Application ID":
            pkgs.append(Package(ecosystem="Flatpak", name=cols[0], version=cols[1] or cols[2], source="flatpak",
                                location=f"flatpak:{cols[3]}", scope="global", direct=True,
                                meta={"kind": "flatpak", "branch": cols[2], "origin": cols[3],
                                      "outdated": cols[0] in pending}))
    return pkgs


SNAP = Collector("snap", "Snap packages (inventory, pending refreshes)", True,
                 lambda ctx: shutil.which("snap") is not None, _snaps)
FLATPAK = Collector("flatpak", "Flatpak apps (inventory, pending updates)", True,
                    lambda ctx: shutil.which("flatpak") is not None, _flatpaks)
