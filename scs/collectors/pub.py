"""Dart and Flutter packages in the pub download cache (~/.pub-cache, %LOCALAPPDATA%\\Pub\\Cache).

Like the Maven/Gradle caches: every `dart pub get` / `flutter pub get` on this
machine resolves packages here, so it lists what Dart code has actually used,
including projects outside the --root folders.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from scs.collectors import Collector, Context
from scs.models import Package

HOSTS = ("pub.dev", "pub.dartlang.org")


def pub_cache() -> Path:
    if os.environ.get("PUB_CACHE"):
        return Path(os.environ["PUB_CACHE"])
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "Pub" / "Cache"
    return Path(os.path.expanduser("~/.pub-cache"))


def cached_packages(root: Path) -> list[Package]:
    out: list[Package] = []
    seen = set()
    for host in HOSTS:
        d = root / "hosted" / host
        try:
            with os.scandir(d) as it:
                names = sorted(e.name for e in it if e.is_dir())
        except OSError:
            continue
        for entry in names:
            m = re.match(r"^(.+?)-(\d+\.\d+\.\d+[\w.+\-]*)$", entry)
            if m and (m.group(1), m.group(2)) not in seen:
                seen.add((m.group(1), m.group(2)))
                out.append(Package("Pub", m.group(1), m.group(2), "pub-cache", str(d / entry), scope="global",
                                   meta={"cache": "pub"}))
    return out


COLLECTOR = Collector("pub-cache", "Dart/Flutter packages in the pub download cache", True,
                      lambda ctx: (pub_cache() / "hosted").is_dir(), lambda ctx: cached_packages(pub_cache()))
