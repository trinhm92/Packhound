"""Java libraries downloaded by Maven and Gradle builds on this machine.

Every build resolves its libraries into a per-user cache (~/.m2/repository,
~/.gradle/caches/modules-2), so the caches list what Java code on this
computer has actually used, including projects outside the --root folders.
Only versions with a downloaded .jar/.aar count: Gradle also fetches the
metadata of versions it then rejects during conflict resolution.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from scs.collectors import Collector, Context
from scs.models import Package

BINARIES = (".jar", ".aar")


def gradle_home() -> Path:
    return Path(os.environ.get("GRADLE_USER_HOME") or os.path.expanduser("~/.gradle"))


def maven_repo() -> Path:
    settings = Path(os.path.expanduser("~/.m2/settings.xml"))
    try:
        m = re.search(r"<localRepository>\s*([^<]+?)\s*</localRepository>", settings.read_text(errors="replace"))
        if m and "${" not in m.group(1):
            return Path(os.path.expanduser(m.group(1)))
    except OSError:
        pass
    return Path(os.path.expanduser("~/.m2/repository"))


def _pkg(group: str, artifact: str, version: str, location: Path, cache: str) -> Package:
    return Package("Maven", f"{group}:{artifact}", version, "java-cache", str(location), scope="global",
                   meta={"cache": cache})


def _dirs(path) -> list[str]:
    try:
        with os.scandir(path) as it:
            return sorted(e.path for e in it if e.is_dir())
    except OSError:
        return []


def gradle_cache(base: Path) -> list[Package]:
    """modules-2/files-2.1/<group>/<artifact>/<version>/<sha1>/<file>."""
    root = base / "caches" / "modules-2" / "files-2.1"
    out: list[Package] = []
    for group in _dirs(root):
        for artifact in _dirs(group):
            for version in _dirs(artifact):
                try:
                    has_bin = any(f.endswith(BINARIES) and not f.endswith(("-sources.jar", "-javadoc.jar"))
                                  for h in _dirs(version) for f in os.listdir(h))
                except OSError:
                    continue
                if has_bin:
                    out.append(_pkg(os.path.basename(group), os.path.basename(artifact), os.path.basename(version),
                                    Path(version), "gradle"))
    return out


def maven_cache(root: Path) -> list[Package]:
    """<group path>/<artifact>/<version>/<artifact>-<version>[-classifier].jar."""
    out: list[Package] = []
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        version, artifact = d.name, d.parent.name
        prefix = f"{artifact}-{version}"
        if any(f.startswith(prefix) and f.endswith(BINARIES) for f in filenames):
            rel = d.parent.parent.relative_to(root).parts
            if rel:
                out.append(_pkg(".".join(rel), artifact, version, d, "maven"))
            dirnames[:] = []
    return out


def _collect(ctx: Context) -> list[Package]:
    return gradle_cache(gradle_home()) + maven_cache(maven_repo())


def _available(ctx: Context) -> bool:
    return (gradle_home() / "caches" / "modules-2").is_dir() or maven_repo().is_dir()


COLLECTOR = Collector("java-cache", "Java libraries in the Maven (~/.m2) and Gradle download caches", True,
                      _available, _collect)
