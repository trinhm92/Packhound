"""Binaries installed with `cargo install` (~/.cargo/.crates2.json)."""
from __future__ import annotations

import os
import re
from pathlib import Path

from scs.collectors import Collector, Context
from scs.models import Package
from scs.util import read_json

_KEY = re.compile(r"^(\S+) (\S+) \((.+)\)$")


def _path() -> Path:
    home = os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo")
    return Path(home) / ".crates2.json"


def _collect(ctx: Context) -> list[Package]:
    data = read_json(_path())
    pkgs = []
    for key, info in (data.get("installs") or {}).items():
        m = _KEY.match(key)
        if not m:
            continue
        name, version, source = m.groups()
        if "crates.io-index" not in source and "index.crates.io" not in source:
            continue  # git/path installs have no registry advisories
        pkgs.append(Package(
            ecosystem="crates.io", name=name, version=version, source="cargo",
            location=str(_path()), scope="global", direct=True,
            meta={"bins": info.get("bins", []), "rustc": (info.get("rustc") or "").split("\n")[0]},
        ))
    return pkgs


COLLECTOR = Collector("cargo", "Rust binaries from `cargo install`", True,
                      lambda ctx: _path().is_file(), _collect)
