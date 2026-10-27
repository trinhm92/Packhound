"""Dry-run patch plan built from triage decisions.

Groups the chosen fixes by where they apply (Homebrew, each Python env, each
global Node prefix, each project), and for every target lists: backup steps,
the consolidated upgrade commands, verification commands and rollback. Nothing
is executed: output is a terminal summary, a Markdown plan and a guarded shell
script for review (Phase 4 adds an executor).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional

from scs import cooldown, fixers, handfix, shell, toolchain
from scs.models import finding_key
from scs.policy import Decisions
from scs.report import short_path
from scs.versions import is_major_bump, major

SH = shell.current()  # dialect of the machine the plan is built for (tests may swap it)


def q(s: str) -> str:
    return SH.q(s)


DEFAULT_ACTIONS = ("patch", "verify", "respond")


@dataclass
class Item:
    finding: dict
    pkg: dict
    action: str  # patch | verify | respond

    @property
    def name(self) -> str:
        return self.pkg["name"]

    @property
    def fix(self) -> str | None:
        return self.finding.get("fix_version")


@dataclass
class Target:
    kind: str     # brew | pip | npm-global | cargo | project
    id: str       # env path / prefix / project dir
    title: str
    items: list[Item] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    backup: list[str] = field(default_factory=list)
    change: list[str] = field(default_factory=list)
    verify: list[str] = field(default_factory=list)
    rollback: list[str] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)
    elevate: bool = False  # Windows: commands need an Administrator (UAC) prompt
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        meta = self.items[0].pkg.get("meta") or {} if self.items else {}
        return {"kind": self.kind, "id": self.id, "title": self.title, "warnings": self.warnings,
                "packages": [{"name": i.name, "from": i.pkg["version"], "to": i.fix, "action": i.action,
                              "direct": i.pkg.get("direct"), "ecosystem": i.pkg["ecosystem"],
                              "location": i.pkg["location"], "lockfile": (i.pkg.get("meta") or {}).get("lockfile"),
                              "binaries": (i.pkg.get("meta") or {}).get("binaries"),
                              "top": next((c for c in i.pkg.get("chain", []) if not c.startswith("(")), None)}
                             for i in self.items],
                "backup": [SH.adapt(c) for c in self.backup], "change": [SH.adapt(c) for c in self.change],
                "verify": [SH.adapt(c) for c in self.verify], "rollback": [SH.adapt(c) for c in self.rollback],
                "manual": self.manual, "elevate": self.elevate,
                # what the executor needs to snapshot and re-check this target
                "meta": {"site": self.items[0].pkg["location"] if self.kind == "pip" and self.items else None,
                         "python": meta.get("python"), "root": meta.get("root"), **self.meta}}


def _slug(s: str) -> str:
    base = re.sub(r"[^A-Za-z0-9]+", "-", os.path.basename(s.rstrip("/")) or "root").strip("-")
    return f"{base}-{hashlib.sha1(s.encode()).hexdigest()[:6]}"


def _uniq(xs: list[str]) -> list[str]:
    out: list[str] = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def needs_root(path: str) -> bool:
    """POSIX: the folder is not writable by this user, so changes need sudo."""
    if os.name == "nt" or not path or (hasattr(os, "geteuid") and os.geteuid() == 0):
        return False
    return os.path.exists(path) and not os.access(path, os.W_OK)


ADMIN_DIRS = ("C:\\Program Files", "C:\\ProgramData", "C:\\Windows", "C:/Program Files", "C:/ProgramData")


def needs_admin(path: str) -> bool:
    """Windows: machine-wide folders need an elevated process (UAC)."""
    if os.name != "nt" or not path:
        return False
    roots = [os.environ.get(v, "") for v in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemRoot")]
    low = os.path.normcase(os.path.abspath(path))
    return any(r and low.startswith(os.path.normcase(r)) for r in roots + list(ADMIN_DIRS))


def scs_cmd(root: bool = False) -> str:
    """Command prefix that runs scs itself from a plan step (as root when the folder needs it)."""
    cmd = " ".join(q(a) for a in fixers.self_argv())
    if not getattr(sys, "frozen", False):
        pp = q(fixers.package_parent())
        cmd = f"env PYTHONPATH={pp} {cmd}" if SH.name == "sh" else f"set PYTHONPATH={pp}&& {cmd}"
    return f"sudo {cmd}" if root and SH.name == "sh" else cmd


PY_REQ = re.compile(r"needs python >=\s*(\d+\.\d+)[^,]*, but env (.+?) uses python")


def python_blocker(finding: dict) -> Optional[str]:
    """Minimum Python minor version the fix needs, when the env's interpreter is older."""
    for r in finding.get("reasons", []):
        m = PY_REQ.search(r)
        if m:
            return m.group(1)
    return None


def migratable(env: str, site: str) -> bool:
    return bool(fixers.pyenv_exe()) and (fixers.is_pyenv_env(env) or bool(fixers.MAC_USER_SITE.search(site)))


def _warn(t: Target, it: Item) -> None:
    for r in it.finding.get("reasons", []):
        if r.startswith("dev-only"):
            continue
        m = re.search(r"but (.+?) uses ", r)  # toolchain reasons name the project/env they are about
        if m and not m.group(1).startswith("env ") and m.group(1) != os.path.basename(t.id.rstrip("/")):
            continue
        if m and m.group(1).startswith("env ") and m.group(1)[4:] != (it.pkg.get("meta") or {}).get("env", t.id):
            continue
        msg = f"{it.name} {it.pkg['version']} → {it.fix}: {r}"
        if msg not in t.warnings:
            t.warnings.append(msg)


# ---------------------------------------------------------------- target builders

def _brew(t: Target) -> None:
    t.backup.append(f"brew list --versions > {SH.path('BACKUP', 'brew-versions.txt')}")
    formulae = _uniq([i.name for i in t.items if i.action != "respond" and i.pkg["ecosystem"] == "Homebrew"])
    casks = _uniq([i.name for i in t.items if i.action != "respond" and i.pkg["ecosystem"] == "Homebrew-cask"])
    bad = _uniq([i.name for i in t.items if i.action == "respond"])
    pinned = _uniq([i.name for i in t.items if (i.pkg.get("meta") or {}).get("pinned")])
    if pinned:
        t.change.append(f"brew unpin {' '.join(pinned)}   # pinned on purpose: confirm before unpinning")
    if formulae:
        t.change.append(f"brew upgrade {' '.join(formulae)}")
    if casks:
        t.change.append(f"brew upgrade --cask {' '.join(casks)}")
    if bad:
        t.change.append(f"brew uninstall {' '.join(bad)}")
    t.verify.append("brew missing")
    dependents = _uniq([d for i in t.items for d in (i.pkg.get("meta") or {}).get("used_by", [])])
    if dependents:
        t.manual.append(f"Re-test tools built on the upgraded formulae: {', '.join(dependents[:15])}"
                        + (" …" if len(dependents) > 15 else ""))
    t.rollback.append("# Homebrew cannot reliably downgrade. Old versions are listed in $BACKUP/brew-versions.txt;"
                      " use a versioned formula (e.g. name@N) or `brew extract` if you must go back.")


def _apt(t: Target) -> None:
    t.backup.append("dpkg-query -W -f='${Package}=${Version}\\n' > " + SH.path("BACKUP", "dpkg-versions.txt"))
    ups, bad, old = [], [], []
    for i in t.items:
        bins = [b["name"] for b in (i.pkg.get("meta") or {}).get("binaries", [])] or [i.name]
        (bad if i.action == "respond" else ups).extend(bins)
        old += [f"{b['name']}={b['version']}" for b in (i.pkg.get("meta") or {}).get("binaries", [])]
    t.change.append("sudo apt-get update")
    if ups:
        t.change.append("sudo apt-get install --only-upgrade -y " + " ".join(q(b) for b in _uniq(ups)))
    if bad:
        t.change.append("sudo apt-get remove -y " + " ".join(q(b) for b in _uniq(bad)))
    t.verify += ['test -z "$(dpkg --audit)"', "sudo apt-get check -q",
                 'test -z "$(systemctl --failed --no-legend --plain 2>/dev/null)"']
    if any(i.name.startswith("linux") for i in t.items):
        t.manual.append("Kernel updated: reboot to run it (`/var/run/reboot-required` exists until you do).")
    t.manual.append("Services keep old libraries loaded until restarted: `sudo needrestart -r l` lists them "
                    "(`sudo apt install needrestart` if missing).")
    if any("esm" in (i.fix or "") for i in t.items):
        t.manual.append("Some fixes come from Ubuntu Pro (ESM): run `sudo pro attach <token>` first, or they will not install.")
    t.rollback.append("sudo apt-get install -y --allow-downgrades " + " ".join(q(o) for o in _uniq(old))
                      + "   # only while the old .debs are still in /var/cache/apt/archives or the archive")


def _debian_managed(site: Path) -> bool:
    """/usr/local and ~/.local installs of a Debian/Ubuntu system Python are also PEP 668 managed."""
    m = re.search(r"python(3\.\d+)", str(site))
    if not m or not str(site).startswith(("/usr/local/lib/python", os.path.expanduser("~/.local/lib/python"))):
        return False
    return Path(f"/usr/lib/python{m.group(1)}/EXTERNALLY-MANAGED").exists()


OS_PY = ("/Library/Developer/CommandLineTools", "/Applications/Xcode", "/System/", "/usr/lib")
BREW_PREFIXES = ("/opt/homebrew/", "/usr/local/", "/home/linuxbrew/.linuxbrew/")


def _externally_managed(site: Path, py: str) -> bool:
    """PEP 668 marker: in the interpreter's stdlib folder (Homebrew keeps it in the Cellar, behind symlinks)."""
    if (site.parent / "EXTERNALLY-MANAGED").exists() or _debian_managed(site):
        return True
    m = re.search(r"python(\d+\.\d+)", str(site))
    try:
        real = Path(py).resolve()
    except OSError:
        return False
    return bool(m) and (real.parent.parent / "lib" / f"python{m.group(1)}" / "EXTERNALLY-MANAGED").exists()


def _no_record(site: Path, name: str, version: str) -> Optional[Path]:
    """The package's .dist-info folder when it has no RECORD (pip refuses to uninstall it)."""
    norm = re.sub(r"[-_.]+", "_", name).lower()
    for d in site.glob("*.dist-info"):
        n, _, v = d.name[:-10].rpartition("-")
        if re.sub(r"[-_.]+", "_", n).lower() == norm and v == version:
            return None if (d / "RECORD").is_file() else d
    return None


_PIP_CUTOFF: dict[str, bool] = {}


def _pip_cutoff_flag(py: str, days: int) -> str:
    """pip >= 26 holds back new releases itself (--uploaded-prior-to), dependencies included."""
    if days <= 0:
        return ""
    if py not in _PIP_CUTOFF:
        try:
            r = subprocess.run([py, "-m", "pip", "install", "--help"], capture_output=True, text=True, timeout=60)
            _PIP_CUTOFF[py] = "--uploaded-prior-to" in r.stdout
        except (OSError, subprocess.SubprocessError):
            _PIP_CUTOFF[py] = False
    return f" --uploaded-prior-to P{days}D" if _PIP_CUTOFF[py] else ""


def _pip(t: Target) -> None:
    meta = t.items[0].pkg.get("meta") or {}
    env = meta.get("env", t.id)
    py = meta.get("python", "python3")
    site = Path(t.items[0].pkg["location"])
    flags = ""
    if "/Library/Python/" in env or "/.local/lib/python" in str(site):
        py = "/usr/bin/python3" if "/Library/Python/" in env else py
        flags += " --user"
    if env.startswith(OS_PY):
        t.warnings.append("Apple/OS-managed Python: only Apple or your OS vendor can update it.")
        t.manual.append("Nothing to change here: the vendor ships these files.")
        return
    if _externally_managed(site, py):
        # Homebrew and Debian/Ubuntu mark their Pythons as managed (PEP 668). Files under this
        # site-packages are not owned by brew/apt packages, so pip may change them; the snapshot
        # of site-packages makes it reversible.
        flags += " --break-system-packages"
        t.manual.append("This Python is marked as managed by Homebrew/your OS: scs updates its add-on packages "
                        "with pip (--break-system-packages) after saving a copy of site-packages.")
    elif not flags and not os.path.exists(py):
        t.warnings.append(f"Interpreter {py} not found; locate the python that owns {short_path(env)}.")
    sudo = "sudo " if needs_root(str(site)) else ""
    t.elevate = needs_admin(str(site))
    snap = SH.path("BACKUP", f"pip-{_slug(str(site))}.txt")
    t.backup.append(f"{q(py)} -m pip freeze --all > {snap}")
    pip = f"{sudo}{q(py)} -m pip install{flags}"
    blocked = [i for i in t.items if python_blocker(i.finding)]
    for i in blocked:
        t.manual.append(f"{i.name} {i.pkg['version']} → {i.fix} needs Python {python_blocker(i.finding)}+, newer than this "
                        f"environment: choose “Move old Python environments to a newer Python” to fix it.")
    todo = [i for i in t.items if i not in blocked]
    days = t.meta.get("min_age", 0)
    cut = _pip_cutoff_flag(py, days)
    pins: dict[str, str] = {}
    for i in [i for i in todo if i.action != "respond" and i.fix]:
        pick = cooldown.pick("PyPI", i.name, i.fix, days)
        if pick["version"] is None:
            t.manual.append(cooldown.held_note(i.name, i.fix, pick, days))
            todo.remove(i)
        elif days and not cut and not pick.get("unknown"):
            pins[i.name] = pick["version"]  # this pip can't hold back new releases itself: pin an old-enough one
    spec = lambda i: f"{i.name}=={pins[i.name]}" if i.name in pins else f"{i.name}>={i.fix}"
    pip += cut
    # installed by Homebrew/the OS without pip's RECORD file: pip cannot uninstall the old copy, so the new
    # one is installed over it and the stale metadata folder removed (site-packages is snapshotted first)
    norecord = [i for i in todo if i.action != "respond" and i.fix and _no_record(site, i.name, i.pkg["version"])]
    for i in norecord:
        old_meta = _no_record(site, i.name, i.pkg["version"])
        t.change.append(f"{pip} --upgrade --ignore-installed --no-deps {q(spec(i))} && "
                        f"{q(py)} -c {q(f'import shutil; shutil.rmtree({str(old_meta)!r})')}")
    todo = [i for i in todo if i not in norecord]
    ups = _uniq([spec(i) for i in todo if i.action != "respond" and i.fix])
    bad = _uniq([i.name for i in todo if i.action == "respond"])
    # parents that may pin an old version: upgraded too, but only if the plain upgrade leaves a conflict
    parents = _uniq([c.split("@")[0] for i in todo if i.action != "respond" and not i.pkg.get("direct")
                     for c in (i.pkg.get("chain") or [])[-1:] if not c.startswith("(")])
    if ups:
        cmd = f"{pip} --upgrade " + " ".join(q(u) for u in ups)
        if parents:
            cmd = (f"{cmd} && ({q(py)} -m pip check || "
                   f"{pip} --upgrade " + " ".join(q(u) for u in ups + parents) + ")")
        t.change.append(cmd)
    if bad:
        t.change.append(f"{sudo}{q(py)} -m pip uninstall -y{' --break-system-packages' if 'break' in flags else ''} "
                        + " ".join(q(b) for b in bad))
    t.verify.append(f"{q(py)} -m pip check")
    tops = _uniq([x.split("@")[0] for i in todo + norecord for x in (i.pkg.get("meta") or {}).get("introduced_by", [])]
                 + [i.name for i in todo + norecord if i.pkg.get("direct") and i.action != "respond"])
    if tops and (ups or norecord):
        # import what was upgraded and the tools built on it, before and after (new failures roll back)
        t.verify.append(f"{q(py)} {q(fixers.py_smoke_path())} " + " ".join(q(x) for x in tops[:15]))
    if days and (ups or norecord):
        # anything pip brought in (dependencies included) must be old enough, or the change is rolled back
        t.verify.append(f"{scs_cmd()} fixer age-check --python {q(py)} --since {snap} --min-age {days}")
    t.rollback.append(f"{sudo}{q(py)} -m pip install{flags} -r {snap}")


def _py_migrate(t: Target) -> None:
    meta = t.items[0].pkg.get("meta") or {}
    env, site = meta.get("env", t.id), t.meta.get("site_mode", "")
    to = max((python_blocker(i.finding) for i in t.items), key=lambda v: [int(x) for x in v.split(".")])
    t.meta.update({"env": env, "to": to, "sites": sorted({i.pkg["location"] for i in t.items})})
    wants = _uniq([f"{i.name}>={i.fix}" for i in t.items if i.fix and i.action != "respond"])
    retire = SH.path("BACKUP", "retired")
    base = f"{scs_cmd()} fixer py-migrate --env {q(env)} --to {to} --retire-to {retire}" + (f" --site {q(site)}" if site else "")
    t.change.append(base + "".join(f" --want {q(w)}" for w in wants))
    t.rollback.append(f"{scs_cmd()} fixer py-migrate --undo --env {q(env)} --to {to} --retire-to {retire}")
    t.verify.append(f"{q(fixers.pyenv_exe() or 'pyenv')} version")
    who = f"Python {os.path.basename(env)} (pyenv)" if not site else f"the user packages of {short_path(env)}"
    t.warnings.append(f"Moves {who} to Python {to}: its packages are reinstalled on Python {to}, and the old folder "
                      "is moved into scs's backups (rollback puts it back). Scripts that hard-code the old path stop working.")
    if not site:
        t.manual.append(f"If `pyenv global` used {os.path.basename(env)}, it switches to the new {to}.x. Projects with a "
                        f".python-version of {os.path.basename(env)} must be pointed at the new version.")
    else:
        t.manual.append("Run those tools with your pyenv Python from now on (python3 -m … or the commands pip installs).")


def npm_prefix(root: Path) -> Path:
    """<prefix>/lib/node_modules on macOS/Linux; <prefix>\\node_modules on Windows (and nvm-windows)."""
    return root.parent.parent if root.parent.name == "lib" else root.parent


def npm_exe(prefix: Path) -> Optional[str]:
    for c in (prefix / "bin" / "npm", prefix / "npm.cmd"):
        if c.is_file():
            return str(c)
    return None


def tool_bins(root: Path, tool: str) -> list[str]:
    """The commands a global tool installs (for a `--version` smoke test)."""
    try:
        pkg = json.loads((root / tool / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    b = pkg.get("bin") or {}
    names = [tool.split("/")[-1]] if isinstance(b, str) else list(b)
    prefix = npm_prefix(root)
    out = []
    for n in names[:2]:
        for c in (prefix / "bin" / n, prefix / f"{n}.cmd"):
            if c.is_file():
                out.append(str(c))
                break
    return out


def _tool_versions(root: Path, prefix: str) -> tuple[dict[str, str], Optional[str]]:
    """Installed top-level tool versions in a global node_modules, and the Node version that runs them."""
    versions = {}
    for pj in list(root.glob("*/package.json")) + list(root.glob("@*/*/package.json")):
        try:
            d = json.loads(pj.read_text(encoding="utf-8"))
            versions[d["name"]] = d["version"]
        except (OSError, ValueError, KeyError):
            continue
    return versions, toolchain.node_version_for_root(str(root))


def _npm_global(t: Target) -> None:
    root = Path(t.id)
    prefix = npm_prefix(root)
    sudo = "sudo " if needs_root(str(root)) else ""
    t.elevate = needs_admin(str(root))
    exe = npm_exe(prefix)
    npm = sudo + (q(exe) if exe else f"npm --prefix {q(str(prefix))}")
    days = t.meta.get("min_age", 0)
    before = f" --before {cooldown.npm_before(days)}" if days else ""  # dependencies resolve to old-enough releases
    snap = SH.path("BACKUP", f"npm-global-{_slug(str(prefix))}.json")
    t.backup.append(f"{npm} ls -g --depth=0 --json > {snap}")
    installs, removes, rollbacks, touched = [], [], [], []
    bundled: dict[str, dict[str, str]] = {}   # top-level tool -> {bundled package: fixed version}
    for i in t.items:
        top = next((c for c in i.pkg.get("chain", []) if not c.startswith("(")), None)
        if i.action == "respond":
            removes.append(top or i.name)
        elif i.pkg.get("direct"):
            pick = cooldown.pick("npm", i.name, i.fix, days, ok=lambda v, f=i.fix: major(v) == major(f))
            if pick["version"] is None:
                t.manual.append(cooldown.held_note(i.name, i.fix, pick, days))
                continue
            installs.append(f"{i.name}@{pick['version']}")
            rollbacks.append(f"{i.name}@{i.pkg['version']}")
            touched.append(i.name)
        elif top:
            fix = i.fix if i.fix and i.fix != "latest" else ""
            bundled.setdefault(top, {})[i.name] = fix
    nested = []
    if bundled:
        tools, node = _tool_versions(root, str(prefix))
        for tool, needs in sorted(bundled.items()):
            installed = tools.get(tool, "")
            names = ", ".join(sorted(needs))
            if not installed:
                t.manual.append(f"{names}: bundled inside {tool}, whose installed version could not be read.")
                continue
            pick = toolchain.npm_tool_update(tool, installed, node, {k: v for k, v in needs.items() if v}, min_age=days)
            if pick.get("error"):
                t.manual.append(f"{names}: bundled inside {tool}; {pick['error']}, so it was left alone.")
                continue
            touched.append(tool)
            if pick["version"]:
                # newest release in the same major that runs on this Node and ships the fixed versions
                installs.append(f"{tool}@{pick['version']}")
                rollbacks.append(f"{tool}@{installed}")
                t.manual.append(f"{names} are bundled inside {tool}: updating {tool} {installed} → {pick['version']} "
                                f"(newest {installed.split('.')[0]}.x that runs on Node {node or '?'} and includes the fixes).")
                if tool == "npm" and "homebrew" in t.id.lower():
                    t.manual.append("Homebrew lets npm update itself here; a later `brew upgrade node` may put back the npm "
                                    "bundled with node. Run Fix again afterwards if that happens.")
                continue
            # no release of the tool ships the fix yet: replace the bundled copies in place
            specs = {}
            for k, v in sorted(needs.items()):
                p = cooldown.pick("npm", k, v, days) if v else {"version": None}
                if v and p["version"] is None:
                    t.manual.append(cooldown.held_note(k, v, p, days))
                elif v:
                    specs[k] = v
            if not specs:
                continue
            majors = [k for k, v in specs.items() if any(
                i.name == k and is_major_bump(i.pkg["version"], v) for i in t.items)]
            flagged = _uniq([f"{i.name}@{i.pkg['version']}" for i in t.items if i.name in specs
                             and next((c for c in i.pkg.get("chain", []) if not c.startswith("(")), None) == tool])
            cmd = (f"{scs_cmd(bool(sudo))} fixer npm-nested --root {q(str(root))} --tool {q(tool)}"
                   + "".join(f" --set {q(f'{k}@{v}')}" for k, v in specs.items())
                   + "".join(f" --from {q(x)}" for x in flagged) + (" --allow-major" if majors else "")
                   + (f" --min-age {days}" if days else ""))
            nested.append(cmd)
            t.manual.append(f"No {tool} release includes the fixed {names} yet, so scs replaces the copies inside {tool} "
                            f"(verified download, then {tool} is load-tested). Reinstalling or updating {tool} undoes this; "
                            "scan again afterwards.")
            if majors:
                t.warnings.append(f"{', '.join(majors)} inside {tool} jump(s) a major version: {tool} may use an API "
                                  f"that changed. scs load-tests {tool} and undoes the change if it fails to start.")
    if installs:
        t.change.append(f"{npm} install -g{before} " + " ".join(q(x) for x in _uniq(installs)))
    t.change += nested
    if removes:
        t.change.append(f"{npm} uninstall -g " + " ".join(q(x) for x in _uniq(removes)))
    t.verify.append(f"{npm} ls -g --depth=0")
    for tool in _uniq(touched):
        t.verify += [f"{q(b)} --version" for b in tool_bins(root, tool)]
    t.manual = _uniq(t.manual)
    if rollbacks:
        t.rollback.append(f"{npm} install -g{before} " + " ".join(q(x) for x in _uniq(rollbacks)))
    t.rollback.append(f"# previous top-level versions are recorded in {snap}")


def _cargo(t: Target) -> None:
    t.backup.append(f"cargo install --list > {SH.path('BACKUP', 'cargo-install-list.txt')}")
    for i in t.items:
        t.change.append(f"cargo install {q(i.name)} --locked --force" + (f" --version {q(i.fix)}" if i.fix else ""))
        t.rollback.append(f"cargo install {q(i.name)} --locked --force --version {q(i.pkg['version'])}")
    t.verify += [f"{q(b)} --version" for i in t.items for b in (i.pkg.get("meta") or {}).get("bins", [])[:1]]


def _in_git(d: Path) -> bool:
    return any((p / ".git").exists() for p in [d, *d.parents])


def _npm_family(t: Target, lockfile: str, items: list[Item], proj: dict, d: str) -> None:
    tool = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm"}[lockfile]
    berry = tool == "yarn" and (Path(d) / ".yarnrc.yml").exists()
    days = t.meta.get("min_age", 0)
    before = f" --before {cooldown.npm_before(days)}" if days and tool == "npm" else ""
    if days and tool != "npm":
        t.manual.append(f"{tool} can't be told to skip new releases from the command line here: set "
                        + ("npmMinimalAgeGate in .yarnrc.yml" if tool == "yarn" else "minimumReleaseAge in pnpm-workspace.yaml")
                        + f" to {days} days ({days * 1440} minutes) to hold back releases younger than that.")
    direct_ok, direct_bump, transitive, bad = [], [], [], []
    for i in items:
        if i.action == "respond":
            bad.append(i)
        elif i.pkg.get("direct"):
            conflict = any("excludes" in r for r in i.finding.get("reasons", []))
            (direct_bump if conflict else direct_ok).append(i)
        else:
            transitive.append(i)
    if direct_ok:
        names = " ".join(q(i.name) for i in direct_ok)
        t.change.append({"npm": f"npm update{before} {names}", "yarn": f"yarn up {names}" if berry else f"yarn upgrade {names}",
                         "pnpm": f"pnpm update {names}"}[tool])
    if direct_bump:
        specs = " ".join(q(f"{i.name}@^{i.fix}") for i in direct_bump)
        t.change.append({"npm": f"npm install{before} {specs}", "yarn": f"yarn up {specs}" if berry else f"yarn upgrade {specs}",
                         "pnpm": f"pnpm add {specs}"}[tool])
    field_name = {"npm": "overrides", "yarn": "resolutions", "pnpm": "pnpm.overrides"}[tool]
    versions_per_name: dict[str, set[str]] = {}
    for i in transitive:
        versions_per_name.setdefault(i.name, set()).add(i.pkg["version"])
    in_range = []
    for i in transitive:
        intro = ", ".join((i.pkg.get("meta") or {}).get("introduced_by", [])[:3]) or "a dependency"
        if is_major_bump(i.pkg["version"], i.fix or i.pkg["version"]):
            t.manual.append(f"{i.name} {i.pkg['version']} → {i.fix} is a major bump inside {intro}: upgrade "
                            f"{intro} instead; forcing it with {field_name} may break that package.")
            continue
        in_range.append(i)
        if len(versions_per_name[i.name]) == 1:
            t.manual.append(f"If {i.name} is still {i.pkg['version']} after the update (a parent pins it), force it: "
                            f"npm pkg set {q(f'{field_name}.{i.name}=^{i.fix}')} && {tool} install")
        else:
            t.manual.append(f"{i.name} is installed in several versions ({', '.join(sorted(versions_per_name[i.name]))}); "
                            f"if one stays vulnerable, override it under its parent ({intro}), not globally.")
    if in_range:
        names = " ".join(_uniq([q(i.name) for i in in_range]))
        # updates nested copies within the ranges their parents declare (fixes here are same-major)
        t.change.append({"npm": f"npm update{before} {names}", "yarn": f"yarn up -R {names}" if berry else f"yarn upgrade {names}",
                         "pnpm": f"pnpm update {names}"}[tool])
        t.verify.append({"npm": "npm ls", "yarn": "yarn why", "pnpm": "pnpm why"}[tool] + " "
                        + " ".join(_uniq([q(i.name) for i in in_range][:8]))
                        + "   # confirm the fixed versions")
    for i in bad:
        t.manual.append(f"MALICIOUS {i.name}@{i.pkg['version']}: pin a known-good version ({field_name} or the "
                        f"direct dependency), delete node_modules, reinstall, then follow the incident checklist.")
    scripts = proj.get("scripts") or []
    run = {"npm": "npm run", "yarn": "yarn", "pnpm": "pnpm run"}[tool]
    t.verify.insert(0, {"npm": f"npm ls --all > {SH.devnull}", "yarn": "yarn install --immutable" if berry else "yarn check --integrity",
                        "pnpm": "pnpm install --frozen-lockfile"}[tool])
    for s in ("build", "test", "lint"):
        if s in scripts:
            t.verify.append(f"{run} {s}")
    t.rollback.append({"npm": "npm ci", "yarn": "yarn install", "pnpm": "pnpm install --frozen-lockfile"}[tool]
                      + "   # after restoring package.json and the lockfile")


def _project(t: Target) -> None:
    d = t.id
    proj = toolchain.detect_project(d)
    by_lock: dict[str, list[Item]] = {}
    for i in t.items:
        by_lock.setdefault((i.pkg.get("meta") or {}).get("lockfile", ""), []).append(i)
    files = sorted(set(by_lock) | {"package.json", "pyproject.toml", "Cargo.toml", "go.sum", "Gemfile", "composer.json"})
    files = [f for f in files if (Path(d) / f).exists()]
    if _in_git(Path(d)):
        t.backup.append(f"git -C {q(d)} status --porcelain   # start from a clean tree")
        t.backup.append(f"git -C {q(d)} switch -c scs/security-updates-{date.today().isoformat()}")
        t.rollback.append(f"git -C {q(d)} checkout -- {' '.join(q(f) for f in files)}")
    else:
        bdir = SH.path("BACKUP", _slug(d))
        t.backup.append(SH.copy_files([str(Path(d) / f) for f in files], bdir))
        t.rollback.append(SH.copy_back(bdir, d))
    for rt in ("python", "node", "go", "rust", "ruby", "php"):
        if rt in proj:
            t.manual.append(f"Build with {rt} {proj[rt]['value']} ({proj[rt]['source']})")

    for lockfile, items in by_lock.items():
        names = [q(i.name) for i in items if i.action != "respond"]
        bad = [i for i in items if i.action == "respond"]
        if lockfile in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
            _npm_family(t, lockfile, items, proj, d)
            continue
        if lockfile == "poetry.lock":
            conflicts = [i for i in items if any("excludes" in r for r in i.finding.get("reasons", []))]
            if conflicts:
                t.change.append("poetry add " + " ".join(q(f"{i.name}@^{i.fix}") for i in conflicts))
            if names:
                t.change.append(f"poetry update {' '.join(names)}")
            t.verify.append("poetry check --lock")
            if any(m in proj.get("markers", []) for m in ("tests", "test", "pytest.ini", "tox.ini")):
                t.verify.append("poetry run pytest")
            t.rollback.append("poetry install --sync   # after restoring the lockfile")
        elif lockfile == "uv.lock":
            if names:
                t.change.append("uv lock " + " ".join(f"--upgrade-package {n}" for n in names) + " && uv sync")
            if any(m in proj.get("markers", []) for m in ("tests", "test", "pytest.ini", "tox.ini")):
                t.verify.append("uv run pytest")
            t.rollback.append("uv sync --locked   # after restoring uv.lock")
        elif lockfile == "Pipfile.lock":
            if names:
                t.change.append(f"pipenv update {' '.join(names)}")
            t.verify.append("pipenv check")
            t.rollback.append("pipenv sync   # after restoring Pipfile.lock")
        elif lockfile.startswith("requirements"):
            for i in items:
                if i.action != "respond" and i.fix:
                    expr = (f"s/^{re.escape(i.name)}=={re.escape(i.pkg['version'])}([[:space:]]|$)/"
                            f"{i.name}=={i.fix}\\1/")
                    t.change.append(f"sed -i.bak -E {q(expr)} {q(lockfile)}")
            t.manual.append(f"Reinstall from {lockfile} in the project's venv: python -m pip install -r {lockfile}")
        elif lockfile == "Cargo.lock":
            for i in items:
                if i.fix:
                    t.change.append(f"cargo update -p {q(i.name + '@' + i.pkg['version'])} --precise {q(i.fix)}")
            t.verify += ["cargo build --locked", "cargo test --locked"]
            t.rollback.append("cargo build   # after restoring Cargo.lock")
        elif lockfile == "go.mod":
            specs = [q(f"{i.name}@v{i.fix}" + ("+incompatible" if "+incompatible" in i.pkg["version"] else ""))
                     for i in items if i.fix]
            if specs:
                t.change.append(f"go get {' '.join(specs)} && go mod tidy")
            t.verify += ["go build ./...", "go vet ./...", "go test ./..."]
            t.rollback.append("go mod download   # after restoring go.mod and go.sum")
        elif lockfile == "Gemfile.lock":
            if names:
                t.change.append(f"bundle update --conservative {' '.join(names)}")
            t.verify.append("bundle exec rake test" if "Rakefile" in proj.get("markers", []) else "bundle check")
            t.rollback.append("bundle install   # after restoring Gemfile.lock")
        elif lockfile in handfix.MANUAL_LOCKFILES:
            for i in items:
                for st in handfix.steps(i.pkg["ecosystem"], i.name, i.pkg["version"], i.fix, i.pkg):
                    t.manual.append(st["text"] + (f"  `{st['cmd']}`" if st.get("cmd") else ""))
        elif lockfile == "composer.lock":
            if names:
                t.change.append(f"composer update {' '.join(names)} --with-dependencies")
            t.verify.append("composer validate && composer audit")
            t.rollback.append("composer install   # after restoring composer.lock")
        for i in bad:
            if lockfile not in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"):
                t.manual.append(f"MALICIOUS {i.name}@{i.pkg['version']} in {lockfile}: pin a known-good version, "
                                f"rebuild the environment from scratch, then follow the incident checklist.")
    mk = Path(d) / "Makefile"
    if mk.is_file() and re.search(r"^test:", mk.read_text(errors="replace"), re.M):
        t.verify.append("make test")
    t.change = [f"{SH.cd(d)} && {c}" for c in _uniq(t.change)]
    t.verify = [f"{SH.cd(d)} && {c}" for c in _uniq(t.verify)]
    t.rollback = _uniq([c if c.startswith(("git ", "cp ", "copy ")) else f"{SH.cd(d)} && {c}" for c in t.rollback])
    t.manual = _uniq(t.manual)


# unattended: the source/package agreements are winget's standard terms for its public catalog
WINGET_AUTO = "--accept-source-agreements --accept-package-agreements --disable-interactivity"


def _winget(t: Target) -> None:
    t.backup.append(f"winget export -o {SH.path('BACKUP', 'winget-export.json')} --include-versions --disable-interactivity")
    for i in t.items:
        t.change.append(f"winget upgrade --id {q(i.name)} --exact --silent {WINGET_AUTO}")
        t.rollback.append(f"winget install --id {q(i.name)} --exact --version {q(i.pkg['version'])} --force --silent "
                          f"{WINGET_AUTO}")
    t.manual.append("Installers can close or restart running apps: save your work and close them first.")


def _choco(t: Target) -> None:
    pinned = [i.name for i in t.items if (i.pkg.get("meta") or {}).get("pinned")]
    names = _uniq([i.name for i in t.items if i.name not in pinned])
    t.elevate = True  # Chocolatey installs machine-wide: Windows asks for Administrator approval (UAC)
    if pinned:
        t.warnings.append(f"pinned in Chocolatey, left alone: {', '.join(pinned)}")
    t.backup.append(f"choco list --limit-output > {SH.path('BACKUP', 'choco-list.txt')}")
    if names:
        t.change.append(f"choco upgrade {' '.join(q(n) for n in names)} -y --no-progress")
    t.rollback += [f"choco install {q(i.name)} --version {q(i.pkg['version'])} -y --allow-downgrade --force"
                   for i in t.items if i.name in names]


def _scoop(t: Target) -> None:
    names = _uniq([i.name for i in t.items])
    t.backup.append(f"scoop export > {SH.path('BACKUP', 'scoop-export.json')}")
    t.change.append(f"scoop update {' '.join(q(n) for n in names)}")
    t.rollback += [f"scoop reset {q(i.name + '@' + i.pkg['version'])}" for i in t.items]
    t.manual.append("Scoop keeps the previous versions until `scoop cleanup`; don't clean up until you have verified.")


def _snap(t: Target) -> None:
    names = _uniq([i.name for i in t.items])
    t.change.append(f"sudo snap refresh {' '.join(q(n) for n in names)}")
    t.rollback += [f"sudo snap revert {q(n)}" for n in names]


def _flatpak(t: Target) -> None:
    names = _uniq([i.name for i in t.items])
    t.change.append(f"flatpak update -y --noninteractive {' '.join(q(n) for n in names)}")
    t.manual.append("Rollback: `flatpak remote-info --log flathub <app>` lists commits; "
                    "`flatpak update --commit=<previous> <app>` goes back.")


def _programs(t: Target) -> None:
    """Installed programs not managed by a package manager: winget can usually update them by name."""
    for i in t.items:
        t.change.append(f"winget upgrade --name {q(i.name)} --exact --silent {WINGET_AUTO}")
    t.warnings.append("Updated through winget by program name; the previous version cannot be restored automatically.")
    t.verify.append("winget list --disable-interactivity --accept-source-agreements")


def _manual(t: Target) -> None:
    """Runtimes, OS-bundled tools and build caches: steps for the user, nothing scs runs."""
    for i in t.items:
        for st in handfix.steps(i.pkg["ecosystem"], i.name, i.pkg["version"], i.fix, i.pkg):
            t.manual.append(f"{i.name} {i.pkg['version']}: {st['text']}" + (f"  `{st['cmd']}`" if st.get("cmd") else "")
                            + (f" {st['link']}" if st.get("link") else ""))
    t.manual = _uniq(t.manual)


BUILDERS = {"brew": _brew, "apt": _apt, "pip": _pip, "npm-global": _npm_global, "cargo": _cargo, "project": _project,
            "winget": _winget, "choco": _choco, "scoop": _scoop, "snap": _snap, "flatpak": _flatpak,
            "programs": _programs, "py-migrate": _py_migrate, "manual": _manual}


# ---------------------------------------------------------------- assembly

def _target_for(p: dict) -> tuple[str, str, str]:
    meta = p.get("meta") or {}
    src = p["source"]
    if src == "brew":
        return "brew", "brew", "Homebrew"
    if src == "apt":
        return "apt", "apt", f"APT packages ({p['ecosystem'].replace(':LTS', ' LTS').replace(':', ' ')})"
    if src == "pip":
        env = meta.get("env", p["location"])
        rt = meta.get("runtime")
        return "pip", p["location"], f"Python {rt + ' ' if rt else ''}env {short_path(env)}"
    if src == "npm-global":
        root = meta.get("root", p["location"])
        return "npm-global", root, f"Global npm {short_path(root)}"
    if src == "cargo":
        return "cargo", "cargo", "cargo install"
    if src in ("winget", "choco", "snap", "flatpak"):
        return src, src, {"winget": "winget packages", "choco": "Chocolatey packages", "snap": "Snap packages",
                          "flatpak": "Flatpak apps"}[src]
    if src == "scoop":
        root = meta.get("root", "scoop")
        return "scoop", root, f"Scoop apps {short_path(root)}"
    if src == "programs":
        return "programs", "programs", "Windows programs (manual updates)"
    if src in handfix.MANUAL_SOURCES:
        return "manual", "manual", "Runtimes, OS tools and build caches (update by hand)"
    d = meta.get("project", str(Path(p["location"]).parent))
    return "project", d, f"Project {short_path(d)}"


OUTDATED_SOURCES = {"formula": ("brew", "Homebrew"), "cask": ("brew", "Homebrew-cask"), "snap": ("snap", "Snap"),
                    "flatpak": ("flatpak", "Flatpak"), "winget": ("winget", "winget"), "choco": ("choco", "chocolatey"),
                    "scoop": ("scoop", "scoop")}


def _outdated_items(result: dict) -> list[tuple[dict, dict]]:
    """Pending updates from package managers without a CVE feed, as (pseudo-finding, package) pairs."""
    out = []
    for o in result.get("outdated", []):
        src, eco = OUTDATED_SOURCES.get(o.get("kind") or "", (o.get("source"), o.get("ecosystem")))
        src, eco = o.get("source") or src, o.get("ecosystem") or eco
        if not src or src not in BUILDERS:
            continue
        latest = o.get("latest") or "latest"
        pkg = {"name": o["name"], "version": o["version"], "source": src, "ecosystem": eco, "direct": True, "chain": [],
               "location": o.get("location", ""), "meta": {**(o.get("meta") or {}), "kind": o.get("kind")}}
        finding = {"name": o["name"], "version": o["version"], "ecosystem": eco, "fix_version": latest,
                   "reasons": [], "advisories": [], "bucket": "patch"}
        out.append((finding, pkg))
    return out


def build(result: dict, decisions: Decisions, actions: tuple[str, ...] = DEFAULT_ACTIONS,
          suggested: bool = False, include_outdated: bool = False, migrate: bool = False,
          min_age: Optional[int] = None) -> dict:
    """migrate=True: fixes that need a newer Python move their environment to one (pyenv).
    min_age: release-age cooldown in days (None: the configured fix_min_age_days; 0: off)."""
    if min_age is None:
        from scs.config import load_config
        min_age = int(load_config().fix_min_age_days)
    targets: dict[tuple[str, str], Target] = {}
    untriaged = 0
    for f in result["findings"]:
        if f["ecosystem"] == "file":
            continue
        d = decisions.get(finding_key(f), {a["id"] for a in f["advisories"]})
        action = d["action"] if d else None
        if action is None:
            untriaged += 1
            if suggested and f["bucket"] in ("patch", "respond", "verify"):
                action = f["bucket"]
        if action not in actions:
            continue
        if action != "respond" and not f.get("fix_version"):
            continue
        for p in f["packages"]:
            kind, tid, title = _target_for(p)
            env = (p.get("meta") or {}).get("env", "")
            site_mode = "" if fixers.is_pyenv_env(env) else p["location"]
            if kind == "pip" and migrate and python_blocker(f) and migratable(env, p["location"]):
                kind, tid = "py-migrate", site_mode or env
                title = (f"Move Python {os.path.basename(env)} (pyenv) to a newer Python" if not site_mode
                         else f"Move user packages of {short_path(env)} to a newer Python")
            t = targets.setdefault((kind, tid), Target(kind, tid, title))
            if kind == "py-migrate":
                t.meta["site_mode"] = site_mode
            it = Item(f, p, action)
            t.items.append(it)
            if action == "verify":
                _warn(t, it)
    if include_outdated:
        for f, p in _outdated_items(result):
            kind, tid, title = _target_for(p)
            t = targets.setdefault((kind, tid), Target(kind, tid, title))
            if not any(i.name == p["name"] for i in t.items):
                t.items.append(Item(f, p, "update"))
    for t in targets.values():
        t.meta["min_age"] = cooldown.days_for([i.finding for i in t.items], min_age)
        BUILDERS[t.kind](t)
    order = {"apt": 0, "brew": 0, "winget": 0, "choco": 0, "scoop": 0, "snap": 0, "flatpak": 0, "programs": 0, "manual": 0,
             "pip": 1, "npm-global": 2, "cargo": 3, "project": 4,
             "py-migrate": 5}  # last: scs itself may be running from a Python that gets retired
    # migrations: user sites move into the current pyenv Python, and the environment scs itself runs
    # from goes last (later steps would lose their interpreter)
    def runs_scs(t: Target) -> bool:
        env = os.path.realpath(t.meta.get("env") or t.id)
        return t.kind == "py-migrate" and os.path.realpath(sys.executable).startswith(env + os.sep)
    ts = sorted(targets.values(), key=lambda t: (order[t.kind], runs_scs(t), bool(t.meta.get("site_mode")), t.id))
    iocs = [f for f in result["findings"] if f["ecosystem"] == "file"]
    return {
        "scan": {"host": result["host"], "started": result["started"], "scan_id": result.get("scan_id")},
        "created": date.today().isoformat(),
        "untriaged": untriaged,
        "min_age": min_age,
        "shell": SH.name,
        "ioc_files": [f["name"] for f in iocs],
        "targets": [t.to_dict() for t in ts],
    }


# ---------------------------------------------------------------- rendering

def to_markdown(plan: dict) -> str:
    lines = [f"# Patch plan — {plan['scan']['host']}",
             "", f"Scan {plan['scan']['started']} · created {plan['created']} · **dry run: nothing has been executed**", ""]
    if plan["untriaged"]:
        lines += [f"> {plan['untriaged']} findings are not triaged and not included. Run `scs triage`.", ""]
    for path in plan["ioc_files"]:
        lines += [f"> **IOC file:** `{path}`: inspect and remove it, then follow the incident checklist.", ""]
    for t in plan["targets"]:
        lines += [f"## {t['title']}", ""]
        lines += [f"- `{p['name']}` {p['from']} → {p['to'] or 'remove'} ({p['action']}"
                  f"{', direct' if p['direct'] else ', transitive' if p['direct'] is False else ''})"
                  for p in t["packages"]]
        lines.append("")
        if t["warnings"]:
            lines += ["**Check before applying**", ""] + [f"- ⚠️ {w}" for w in t["warnings"]] + [""]
        for title, key in (("Backup", "backup"), ("Apply", "change"), ("Verify", "verify"), ("Rollback", "rollback")):
            if t[key]:
                lines += [f"**{title}**", "", "```bash", *t[key], "```", ""]
        if t["manual"]:
            lines += ["**Notes**", ""] + [f"- {m}" for m in t["manual"]] + [""]
    return "\n".join(lines)


def to_script(plan: dict) -> str:
    if plan.get("shell") == "cmd":
        return to_cmd_script(plan)
    out = ["#!/usr/bin/env bash",
           f"# scs patch plan for {plan['scan']['host']} (scan {plan['scan']['started']}). Generated {plan['created']}.",
           "# DRY RUN ARTIFACT: review every command. Run one target at a time, e.g.:",
           "#   SCS_CONFIRM=1 bash plan.sh target_2",
           "set -euo pipefail",
           'BACKUP="${BACKUP:-$HOME/.local/share/scs/backups/$(date +%Y%m%d-%H%M%S)}"',
           'mkdir -p "$BACKUP"', ""]
    names = []
    for n, t in enumerate(plan["targets"], 1):
        fn = f"target_{n}"
        names.append((fn, t["title"]))
        out.append(f"{fn}() {{  # {t['title']}")
        out.append("  :  # no-op keeps the body valid when every step is a comment")
        for w in t["warnings"]:
            out.append(f"  # WARNING: {w}")
        for title, key in (("backup", "backup"), ("apply", "change"), ("verify", "verify")):
            if t[key]:
                out.append(f"  echo '== {t['title']}: {title}'")
                out += [f"  {c}" for c in t[key]]
        out.append("}")
        out.append(f"rollback_{n}() {{  # {t['title']}")
        out.append("  :")
        out += [f"  {c}" for c in t["rollback"]]
        out += ["}", ""]
    out += ['if [ "${SCS_CONFIRM:-}" != "1" ] || [ $# -eq 0 ]; then',
            '  echo "Targets:"'] + [f'  echo "  {fn}  {title}"' for fn, title in names] + [
            '  echo "Review this file, then run: SCS_CONFIRM=1 bash $0 <target> [<target> ...]"',
            "  exit 1", "fi", 'for t in "$@"; do "$t"; done', ""]
    return "\n".join(out)


def to_cmd_script(plan: dict) -> str:
    """Windows batch version: each target is a label; a failing command stops that target."""
    out = ["@echo off", "setlocal EnableExtensions",
           f"rem scs patch plan for {plan['scan']['host']} (scan {plan['scan']['started']}). Generated {plan['created']}.",
           "rem DRY RUN ARTIFACT: review every command. Run one target at a time, e.g.:",
           "rem   set SCS_CONFIRM=1 && plan.cmd target_2",
           'if "%BACKUP%"=="" set "BACKUP=%LOCALAPPDATA%\\scs\\backups\\plan"',
           'if not exist "%BACKUP%" mkdir "%BACKUP%"',
           'if not "%SCS_CONFIRM%"=="1" goto :usage', 'if "%~1"=="" goto :usage',
           ":next", 'if "%~1"=="" exit /b 0', 'call :%~1 || exit /b 1', "shift", "goto :next", ""]
    names = []
    for n, t in enumerate(plan["targets"], 1):
        names.append((f"target_{n}", t["title"]))
        out.append(f":target_{n}")
        out.append(f"rem {t['title']}")
        out += [f"rem WARNING: {w}" for w in t["warnings"]]
        for title, key in (("backup", "backup"), ("apply", "change"), ("verify", "verify")):
            for c in t[key]:
                out.append(c if c.startswith("rem ") else f"{c} || exit /b 1")
        out += ["exit /b 0", "", f":rollback_{n}"]
        out += [c if c.startswith("rem ") else f"{c} || exit /b 1" for c in t["rollback"]]
        out += ["exit /b 0", ""]
    out += [":usage", "echo Targets:"] + [f"echo   {fn}  {title}" for fn, title in names] + [
        "echo Review this file, then run: set SCS_CONFIRM=1 ^&^& %~nx0 target_N", "exit /b 1", ""]
    return "\r\n".join(out)
