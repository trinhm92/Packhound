"""Tools people installed globally, outside any project folder, read from disk (nothing is run or installed).

gems          Ruby gems of every Ruby on the machine (rbenv, rvm, chruby, asdf, mise, Homebrew, Windows
              RubyInstaller, `gem install --user-install`, sudo-installed system gems); Apple's bundled gems
              are marked as the vendor's
go-binary     programs in GOBIN / GOPATH/bin: the module list and Go version a Go binary records at build time
              (its "buildinfo"), parsed from the file, so old dependencies and an old standard library compiled
              into a tool are found
dotnet-tool   `dotnet tool install -g` tools (~/.dotnet/tools/.store)
composer      `composer global require` packages (Composer home's composer.lock)
corepack      pnpm / yarn versions Corepack downloaded
nuget-cache   NuGet's download cache (~/.nuget/packages), like the Maven/Gradle caches
"""
from __future__ import annotations

import glob
import os
import re
from pathlib import Path

from scs.collectors import Collector, Context
from scs.models import Package

HOME = os.path.expanduser("~")
IS_WIN = os.name == "nt"


def _globs(*patterns: str) -> list[str]:
    return sorted({p for pat in patterns for p in glob.glob(os.path.expanduser(pat))})


def _short(p: str) -> str:
    return "~" + p[len(HOME):] if p.startswith(HOME) else p


# ---------------------------------------------------------------- Ruby gems

GEM_SPEC_DIRS = [
    "~/.rbenv/versions/*/lib/ruby/gems/*/specifications", "~/.rvm/gems/*/specifications",
    "~/.rubies/*/lib/ruby/gems/*/specifications", "~/.gem/ruby/*/specifications",
    "~/.local/share/gem/ruby/*/specifications", "~/.asdf/installs/ruby/*/lib/ruby/gems/*/specifications",
    "~/.local/share/mise/installs/ruby/*/lib/ruby/gems/*/specifications",
    "/opt/homebrew/lib/ruby/gems/*/specifications", "/usr/local/lib/ruby/gems/*/specifications",
    "/opt/homebrew/Cellar/ruby*/*/lib/ruby/gems/*/specifications",
    "/usr/local/Cellar/ruby*/*/lib/ruby/gems/*/specifications",
    "/Library/Ruby/Gems/*/specifications",              # `sudo gem install` on macOS's Ruby
    "/System/Library/Frameworks/Ruby.framework/Versions/*/usr/lib/ruby/gems/*/specifications",  # Apple's
    "/var/lib/gems/*/specifications",                   # `sudo gem install` on Debian/Ubuntu's Ruby
    "C:/Ruby*/lib/ruby/gems/*/specifications",
]
_GEM_FILE = re.compile(r"^(.+?)-(\d[\w.]*?)(?:-(?:x86|x64|arm|aarch|universal|java|mingw|mswin)[\w\-]*)?\.gemspec$")


def gem_tool(spec_dir: Path) -> str:
    """The `gem` command of the Ruby that owns these gems (for the fix steps)."""
    for prefix in list(spec_dir.parents)[3:6]:  # <prefix>/lib/ruby/gems/X.Y.0/specifications
        for name in ("gem", "gem.bat", "gem.cmd"):
            if (prefix / "bin" / name).is_file():
                return str(prefix / "bin" / name)
    return "gem"


def gems() -> list[Package]:
    out: list[Package] = []
    seen = set()
    for d in _globs(*GEM_SPEC_DIRS):
        spec_dir = Path(d)
        real = os.path.realpath(d)
        if real in seen:
            continue
        seen.add(real)
        vendor = d.startswith("/System/")
        tool = "/usr/bin/gem" if vendor else gem_tool(spec_dir)
        for sub in (spec_dir, spec_dir / "default"):  # default gems ship with Ruby and can be updated too
            try:
                names = os.listdir(sub)
            except OSError:
                continue
            for f in names:
                m = _GEM_FILE.match(f)
                if m:
                    out.append(Package("RubyGems", m.group(1), m.group(2), "gem", str(sub / f), scope="global",
                                       meta={"gem": tool, "gem_home": str(spec_dir.parent), "vendor_managed": vendor,
                                             "vendor": "Apple" if vendor else "", "default": sub.name == "default",
                                             "display": f"Ruby gems in {_short(str(spec_dir.parent))}"}))
    return out


# ---------------------------------------------------------------- Go binaries (buildinfo)

BUILDINFO_MAGIC = b"\xff Go buildinf:"
MAX_BINARY = 512 * 1024 * 1024


def _uvarint(data: bytes, i: int) -> tuple[int, int]:
    x = shift = 0
    while i < len(data):
        b = data[i]
        x |= (b & 0x7F) << shift
        i += 1
        if b < 0x80:
            return x, i
        shift += 7
    raise ValueError("truncated varint")


def buildinfo(path: Path) -> tuple[str, str] | None:
    """(Go version, module info text) recorded in a Go ≥ 1.18 binary, read from the file without running it."""
    try:
        if path.stat().st_size > MAX_BINARY:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    i = data.find(BUILDINFO_MAGIC)
    if i < 0 or len(data) < i + 32 or not data[i + 15] & 0x2:  # older binaries store pointers instead
        return None
    j = i + 32
    n, j = _uvarint(data, j)
    version = data[j:j + n].decode(errors="replace")
    j += n
    n, j = _uvarint(data, j)
    mod = data[j:j + n]
    if len(mod) >= 33 and mod[-17] == 0x0A:  # 16-byte sentinels around the text
        mod = mod[16:-16]
    return version, mod.decode(errors="replace")


def go_binary_packages(path: Path) -> list[Package]:
    info = buildinfo(path)
    if not info:
        return []
    version, modinfo = info
    main, deps = "", []
    for line in modinfo.splitlines():
        f = line.split("\t")
        if f[0] == "path" and len(f) > 1:
            main = f[1]
        elif f[0] in ("mod", "dep") and len(f) >= 3:
            deps.append([f[0], f[1], f[2]])
        elif f[0] == "=>" and len(f) >= 3 and deps:  # replacement of the previous module
            deps[-1][1:3] = [f[1], f[2]]
    meta = {"binary": str(path), "main": main, "go": version.lstrip("go"),
            "display": f"Go program {path.name} ({_short(str(path))})"}
    out = []
    m = re.match(r"go(\d+\.\d+(?:\.\d+)?)", version)
    if m:  # its compiled-in standard library
        out.append(Package("Go", "stdlib", m.group(1), "go-binary", str(path), scope="global", direct=True, meta=dict(meta)))
    for kind, mod, ver in deps:
        if ver.startswith("v") and ver != "(devel)":
            out.append(Package("Go", mod, ver.lstrip("v"), "go-binary", str(path), scope="global",
                               direct=kind == "mod", meta=dict(meta)))
    return out


def go_bin_dirs() -> list[Path]:
    dirs = [os.environ.get("GOBIN", "")] + [os.path.join(p, "bin") for p in
                                            (os.environ.get("GOPATH") or os.path.join(HOME, "go")).split(os.pathsep)]
    return [Path(d) for d in dict.fromkeys(dirs) if d and os.path.isdir(d)]


def go_binaries() -> list[Package]:
    out: list[Package] = []
    for d in go_bin_dirs():
        for f in sorted(d.iterdir()):
            if f.is_file() and not f.is_symlink():
                out.extend(go_binary_packages(f))
    return out


# ---------------------------------------------------------------- .NET tools, NuGet cache

def _nuspec_id(folder: Path, fallback: str) -> str:
    for spec in folder.glob("*.nuspec"):
        try:
            m = re.search(r"<id>\s*([^<]+?)\s*</id>", spec.read_text(encoding="utf-8-sig", errors="replace"))
        except OSError:
            continue
        if m:
            return m.group(1)
    return fallback


def dotnet_tools() -> list[Package]:
    out: list[Package] = []
    store = Path(HOME) / ".dotnet" / "tools" / ".store"
    for ver_dir in _globs(str(store / "*" / "*")):
        lower_id, version = Path(ver_dir).parent.name, Path(ver_dir).name
        pkg_dir = Path(ver_dir) / lower_id / version
        if re.match(r"\d", version) and pkg_dir.is_dir():
            out.append(Package("NuGet", _nuspec_id(pkg_dir, lower_id), version, "dotnet-tool", ver_dir, scope="global",
                               direct=True, meta={"display": ".NET global tools (~/.dotnet/tools)"}))
    return out


def nuget_root() -> Path:
    return Path(os.environ.get("NUGET_PACKAGES") or os.path.join(HOME, ".nuget", "packages"))


def nuget_cache() -> list[Package]:
    out: list[Package] = []
    for ver_dir in _globs(str(nuget_root() / "*" / "*")):
        p = Path(ver_dir)
        if re.match(r"\d", p.name) and any(p.glob("*.nupkg*")):  # fully extracted packages only
            out.append(Package("NuGet", _nuspec_id(p, p.parent.name), p.name, "nuget-cache", ver_dir, scope="global",
                               meta={"cache": "nuget"}))
    return out


# ---------------------------------------------------------------- Composer global, Corepack

def composer_home() -> Path | None:
    cands = [os.environ.get("COMPOSER_HOME", ""), os.path.join(HOME, ".composer"), os.path.join(HOME, ".config", "composer"),
             os.path.join(os.environ.get("APPDATA", ""), "Composer") if IS_WIN else ""]
    return next((Path(c) for c in cands if c and (Path(c) / "composer.lock").is_file()), None)


def composer_global(ctx: Context) -> list[Package]:
    from scs.collectors.lockfiles import parse_composer_lock
    from scs.graph import finalize
    home = composer_home()
    if not home:
        return []
    lock = home / "composer.lock"
    pkgs, graph = parse_composer_lock(lock)
    for p in pkgs:
        p.scope = "global"
        p.meta["display"] = f"Composer global packages ({_short(str(home))})"
    if graph is not None:
        finalize(graph, pkgs, str(lock))
        ctx.graphs[str(lock)] = graph
    return pkgs


COREPACK_ROOTS = ["~/.cache/node/corepack", "~/Library/Caches/node/corepack", "~/AppData/Local/node/corepack"]


def corepack() -> list[Package]:
    out: list[Package] = []
    for root in COREPACK_ROOTS:
        for pm_dir in _globs(f"{root}/pnpm/*", f"{root}/yarn/*", f"{root}/v1/pnpm/*", f"{root}/v1/yarn/*"):
            p = Path(pm_dir)
            if re.fullmatch(r"\d+\.\d+\.\d+(?:[\w.\-]*)", p.name) and p.parent.name in ("pnpm", "yarn"):
                out.append(Package("npm", p.parent.name, p.name, "corepack", pm_dir, scope="global", direct=True,
                                   meta={"display": f"{p.parent.name} {p.name} downloaded by Corepack"}))
    return out


def _collect(ctx: Context) -> list[Package]:
    return gems() + go_binaries() + dotnet_tools() + composer_global(ctx) + corepack()


COLLECTOR = Collector("global-tools", "Globally installed gems, Go programs, .NET tools, Composer packages, "
                      "Corepack package managers", True, lambda ctx: True, _collect)
NUGET_CACHE = Collector("nuget-cache", ".NET packages in the NuGet download cache", True,
                        lambda ctx: nuget_root().is_dir(), lambda ctx: nuget_cache())
