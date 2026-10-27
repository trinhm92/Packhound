"""Language runtimes and the developer tools that ship with the OS.

runtimes  JDKs, Node.js, Python and Go installations themselves (the packages
          inside them are other collectors' job). Versions come from files the
          runtime ships (JDK `release`, Go `VERSION`, pyenv/nvm folder names);
          only when there is none is the binary asked for its version. Shims and
          macOS stubs (/usr/bin/python3, /usr/bin/java) are never run: they can
          pop up an install dialog.
devtools  git, curl and OpenSSH from Apple (Command Line Tools / Xcode / macOS)
          or Windows, which no package manager reports. Homebrew, APT and winget
          copies are inventoried by those collectors.
"""
from __future__ import annotations

import glob
import os
import platform
import re
import subprocess
from pathlib import Path

from scs.collectors import Collector, Context
from scs.models import Package

HOME = os.path.expanduser("~")
IS_MAC, IS_WIN = platform.system() == "Darwin", os.name == "nt"
BREW_PREFIXES = ("/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew")

# JDK `release` IMPLEMENTOR -> endoflife.date product with that vendor's update releases
JDK_PRODUCTS = {
    "Eclipse Adoptium": "eclipse-temurin", "Amazon.com Inc.": "amazon-corretto", "Azul Systems, Inc.": "azul-zulu",
    "Microsoft": "microsoft-build-of-openjdk", "Oracle Corporation": "oracle-jdk", "Red Hat, Inc.": "redhat-build-of-openjdk",
    "SAP SE": "sapmachine",
}
REFERENCE_JDK = "eclipse-temurin"  # other builds (Homebrew, JetBrains, BellSoft…) follow the same OpenJDK updates
LABELS = {"java": "Java (JDK)", "node": "Node.js", "python": "Python", "go": "Go"}


def _version_of(cmd: list[str]) -> str:
    """First version-looking token a `--version` call prints (stdout or stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:p\d+)?)", (r.stdout or "") + (r.stderr or ""))
    return m.group(1) if m else ""


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(65536)
    except OSError:
        return ""


def _globs(*patterns: str) -> list[str]:
    return sorted({p for pat in patterns for p in glob.glob(os.path.expanduser(pat))})


def _runtime(name: str, version: str, home: str, manager: str, product: str, cycle: str, **meta) -> Package:
    how = "" if manager == "installer" else f"{manager}, "
    display = meta.pop("display", None) or f"{LABELS[name]} {version} ({how}{_short(home)})"
    eco, pkg = ("Go", "stdlib") if name == "go" else ("Runtime", name)
    return Package(eco, pkg, version, "runtime", home, scope="global", direct=True,
                   meta={"runtime": name, "manager": manager, "product": product, "cycle": cycle, "display": display, **meta})


def _short(p: str) -> str:
    return "~" + p[len(HOME):] if p.startswith(HOME) else p


def _manager(path: str) -> str:
    rp = os.path.realpath(path).replace("\\", "/")  # markers below use forward slashes, also on Windows
    for marker, name in (("/.sdkman/", "SDKMAN"), ("/.pyenv/", "pyenv"), ("/.nvm/", "nvm"), ("/.volta/", "Volta"),
                         ("/fnm/", "fnm"), ("/uv/python/", "uv"), ("/.asdf/", "asdf"), ("/mise/", "mise"),
                         ("/Cellar/", "Homebrew"), ("/.gradle/jdks/", "Gradle toolchains"),
                         ("Android Studio", "Android Studio"), ("/pkg/mod/golang.org/toolchain", "Go toolchain cache"),
                         ("/Library/Frameworks/Python.framework", "python.org installer"),
                         ("/Library/Developer/CommandLineTools", "Apple Command Line Tools"),
                         ("/Applications/Xcode", "Xcode")):
        if marker in rp:
            return name
    return "installer"


# ---------------------------------------------------------------- JDKs

def _jdk_version(raw: str) -> str:
    """'1.8.0_392' -> '8.0.392'; '17.0.9' stays."""
    m = re.match(r"1\.8\.0_(\d+)", raw)
    return f"8.0.{m.group(1)}" if m else raw


def jdk_homes() -> list[str]:
    pats = []
    if IS_MAC:
        pats += ["/Library/Java/JavaVirtualMachines/*/Contents/Home", "~/Library/Java/JavaVirtualMachines/*/Contents/Home",
                 "/Applications/Android Studio*.app/Contents/jbr/Contents/Home",
                 "/Applications/IntelliJ IDEA*.app/Contents/jbr/Contents/Home",
                 *(f"{b}/Cellar/openjdk*/*/libexec/openjdk.jdk/Contents/Home" for b in BREW_PREFIXES)]
    elif IS_WIN:
        pf = [os.environ.get(k) for k in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA")]
        for base in filter(None, pf):
            pats += [f"{base}\\{v}\\*" for v in ("Java", "Eclipse Adoptium", "Microsoft", "Zulu", "Amazon Corretto",
                                                 "BellSoft", "Semeru", "Programs\\Eclipse Adoptium")]
            pats.append(f"{base}\\Android\\Android Studio\\jbr")
    else:  # /usr/lib/jvm is the distribution's (covered by the apt collector)
        pats += ["/opt/java/*", "/opt/jdk*", "/opt/android-studio/jbr",
                 *(f"{b}/Cellar/openjdk*/*/libexec" for b in BREW_PREFIXES)]
    pats += ["~/.sdkman/candidates/java/*", "~/.gradle/jdks/*", "~/.jdks/*", "~/.asdf/installs/java/*"]
    homes = []
    for h in _globs(*pats):
        if os.path.basename(h) == "current":
            continue
        if not os.path.isfile(os.path.join(h, "release")):
            nested = glob.glob(os.path.join(h, "*", "Contents", "Home", "release")) + glob.glob(os.path.join(h, "Contents", "Home", "release"))
            if not nested:
                continue
            h = os.path.dirname(nested[0])
        homes.append(h)
    return homes


def jdks() -> list[Package]:
    out, seen = [], set()
    for home in jdk_homes():
        real = os.path.realpath(home)
        if real in seen:
            continue
        seen.add(real)
        rel = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', _read(os.path.join(home, "release")), re.M))
        raw = rel.get("JAVA_VERSION", "")
        if not raw:
            continue
        version = _jdk_version(raw)
        vendor = rel.get("IMPLEMENTOR", "") or "OpenJDK"
        product = JDK_PRODUCTS.get(vendor, REFERENCE_JDK)
        cycle = version.split(".")[0]
        mgr = _manager(home)
        out.append(_runtime("java", version, home, mgr, product, cycle, vendor=vendor,
                            display=f"JDK {version} ({', '.join(dict.fromkeys(x for x in (vendor, mgr) if x != 'installer'))}: "
                                    f"{_short(home)})"))
    return out


# ---------------------------------------------------------------- Node.js

def nodes() -> list[Package]:
    out, seen = [], set()
    pats = ["~/.nvm/versions/node/*", "~/.volta/tools/image/node/*", "~/.local/share/fnm/node-versions/*/installation",
            "~/Library/Application Support/fnm/node-versions/*/installation", "~/.asdf/installs/nodejs/*",
            "~/.local/share/mise/installs/node/*", *(f"{b}/Cellar/node*/*" for b in BREW_PREFIXES)]
    if IS_WIN:
        pats += [f"{os.environ.get('ProgramFiles', 'C:/Program Files')}\\nodejs", "~/AppData/Roaming/nvm/v*"]
    for home in _globs(*pats):
        real = os.path.realpath(home)
        if real in seen:
            continue
        seen.add(real)
        m = re.search(r"v?(\d+\.\d+\.\d+)", os.path.basename(home.rstrip("/\\")) if "installation" not in home
                      else os.path.basename(os.path.dirname(home)))
        version = m.group(1) if m else ""
        if not version:
            exe = os.path.join(home, "node.exe" if IS_WIN else os.path.join("bin", "node"))
            version = _version_of([exe, "--version"]) if os.path.isfile(exe) else ""
        if version:
            out.append(_runtime("node", version, home, _manager(home), "nodejs", version.split(".")[0]))
    return out


# ---------------------------------------------------------------- Python

def pythons() -> list[Package]:
    out, seen = [], set()
    cands: list[tuple[str, str]] = []  # (home, version or "")
    for d in _globs("~/.pyenv/versions/*", "~/.asdf/installs/python/*", "~/.local/share/mise/installs/python/*"):
        if re.fullmatch(r"\d+\.\d+\.\d+", os.path.basename(d)):  # plain CPython (not a pyenv-virtualenv)
            cands.append((d, os.path.basename(d)))
    for d in _globs("~/.local/share/uv/python/cpython-*", "~/Library/Application Support/uv/python/cpython-*"):
        m = re.match(r"cpython-(\d+\.\d+\.\d+)-", os.path.basename(d))
        if m:
            cands.append((d, m.group(1)))
    for b in BREW_PREFIXES:
        for d in _globs(f"{b}/Cellar/python@*/*"):
            cands.append((d, re.sub(r"_\d+$", "", os.path.basename(d))))
    if IS_MAC:
        for d in _globs("/Library/Frameworks/Python.framework/Versions/3.*"):
            cands.append((d, ""))
        for d in ("/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/Current",):
            if os.path.isdir(d):
                cands.append((d, ""))
    if IS_WIN:
        for base in filter(None, (os.environ.get("LOCALAPPDATA", "") + "\\Programs\\Python", os.environ.get("ProgramFiles"))):
            cands += [(d, "") for d in _globs(f"{base}\\Python3*")]
    for home, version in cands:
        real = os.path.realpath(home)
        if real in seen:
            continue
        seen.add(real)
        if not version:
            exe = next((e for e in (os.path.join(home, "python.exe"), os.path.join(home, "bin", "python3"))
                        if os.path.isfile(e)), "")
            version = _version_of([exe, "-I", "-S", "-V"]) if exe else ""
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            continue
        mgr = _manager(home)
        vendor_managed = mgr == "Apple Command Line Tools"
        out.append(_runtime("python", version, home, mgr, "python", ".".join(version.split(".")[:2]),
                            vendor_managed=vendor_managed, vendor="Apple" if vendor_managed else ""))
    return out


# ---------------------------------------------------------------- Go

def _go_requested(ctx: Context) -> set[str]:
    """Toolchain versions the go.mod files under the roots ask for ('toolchain go1.26.4' / 'go 1.26.4')."""
    want = set()
    for lf in ctx.lockfiles:
        if lf.name != "go.mod":
            continue
        for m in re.finditer(r"^(?:toolchain\s+go|go\s+)(\d+\.\d+\.\d+)\s*$", _read(str(lf)), re.M):
            want.add(m.group(1))
    return want


def gos(ctx: Context) -> list[Package]:
    out, seen = [], set()
    roots = ["/usr/local/go", "~/sdk/go*", "~/.asdf/installs/golang/*/go", "~/.local/share/mise/installs/go/*",
             *(f"{b}/Cellar/go*/*/libexec" for b in BREW_PREFIXES)]
    if IS_WIN:
        roots.append(f"{os.environ.get('ProgramFiles', 'C:/Program Files')}\\Go")
    requested = _go_requested(ctx)
    gopath = os.environ.get("GOPATH") or os.path.join(HOME, "go")
    for d in _globs(*roots, os.path.join(gopath, "pkg", "mod", "golang.org", "toolchain@*")):
        real = os.path.realpath(d)
        line = _read(os.path.join(d, "VERSION")).splitlines()[:1]
        m = re.match(r"go(\d+\.\d+(?:\.\d+)?)", line[0]) if line else None
        if real in seen or not m:
            continue
        seen.add(real)
        version = m.group(1)
        mgr = _manager(d)
        if mgr == "Go toolchain cache" and version not in requested:
            continue  # downloaded once for some go.mod; none under the roots asks for it now
        out.append(_runtime("go", version, d, mgr, "go", ".".join(version.split(".")[:2]),
                            display=f"Go {version} toolchain ({mgr}, {_short(d)})"))
    return out


def _collect_runtimes(ctx: Context) -> list[Package]:
    return jdks() + nodes() + pythons() + gos(ctx)


# ---------------------------------------------------------------- OS-bundled developer tools

CPE = {"git": ("git-scm", "git"), "curl": ("haxx", "curl"), "openssh": ("openbsd", "openssh")}


def devtool_binaries() -> list[tuple[str, str, str, list[str]]]:
    """(tool, path, vendor, version command)."""
    out = []
    if IS_MAC:
        for git in ["/Library/Developer/CommandLineTools/usr/bin/git", *_globs("/Applications/Xcode*.app/Contents/Developer/usr/bin/git")]:
            out.append(("git", git, "Apple", [git, "--version"]))
        out += [("curl", "/usr/bin/curl", "Apple", ["/usr/bin/curl", "--version"]),
                ("openssh", "/usr/bin/ssh", "Apple", ["/usr/bin/ssh", "-V"])]
    elif IS_WIN:
        sysroot = os.environ.get("SystemRoot", "C:\\Windows")
        out += [("curl", f"{sysroot}\\System32\\curl.exe", "Microsoft", [f"{sysroot}\\System32\\curl.exe", "--version"]),
                ("openssh", f"{sysroot}\\System32\\OpenSSH\\ssh.exe", "Microsoft", [f"{sysroot}\\System32\\OpenSSH\\ssh.exe", "-V"])]
    return [b for b in out if os.path.isfile(b[1])]


def _collect_devtools(ctx: Context) -> list[Package]:
    out = []
    for tool, path, vendor, cmd in devtool_binaries():
        version = _version_of(cmd)
        if not version:
            continue
        where = {"Apple": "Xcode" if "/Xcode" in path else "Command Line Tools" if "CommandLineTools" in path else "macOS",
                 "Microsoft": "Windows"}[vendor]
        out.append(Package("Dev-tool", tool, version, "devtool", path, scope="global", direct=True,
                           meta={"cpe": CPE[tool], "vendor": vendor, "vendor_managed": True,
                                 "display": f"{tool} from {vendor} ({where}: {path})"}))
    return out


RUNTIMES = Collector("runtimes", "Language runtimes: JDKs, Node.js, Python and Go toolchains", True,
                     lambda ctx: True, _collect_runtimes)
DEVTOOLS = Collector("devtools", "git, curl and OpenSSH bundled with macOS/Xcode or Windows", True,
                     lambda ctx: IS_MAC or IS_WIN, _collect_devtools)
