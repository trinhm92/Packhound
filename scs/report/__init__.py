"""Report renderers. All renderers take the scan result dict (as stored in history)."""
from __future__ import annotations

import os


def short_path(p: str) -> str:
    home = os.path.expanduser("~")
    return "~" + p[len(home):] if p.startswith(home) else p


def where(pkg: dict) -> str:
    """Human label for where a package instance lives, including its dependency chain."""
    src, meta = pkg["source"], pkg.get("meta", {})
    chain = [c for c in pkg.get("chain", []) if not c.startswith("(")]
    via = f" via {' > '.join(chain)}" if chain else ""
    if src == "pip":
        return f"pip env {short_path(meta.get('env', pkg['location']))}{via}"
    if src == "npm-global":
        return f"npm global {short_path(meta.get('root', ''))}{via}"
    if src == "lockfile":
        dev = " [dev]" if pkg.get("dev") else ""
        return f"{short_path(pkg['location'])}{via}{dev}"
    if src == "brew":
        used = meta.get("used_by") or []
        extra = f" (needed by {', '.join(used[:5])}{'…' if len(used) > 5 else ''})" if used else ""
        return f"Homebrew {meta.get('kind', '')}{extra}"
    if src == "cargo":
        return "cargo install"
    return short_path(pkg["location"])
