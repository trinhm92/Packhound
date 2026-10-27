"""Fix operations that are more than one package-manager command.

The executor runs plans as shell commands, so these are exposed as `scs fixer …`
subcommands (run with sudo / elevation when the target folder needs it):

  npm-nested   replace vulnerable copies of a package *inside* a globally installed tool
               (npm bundles undici, firebase-tools pins uuid, …) when no release of the
               tool ships the fix. Tarballs are verified against the registry's integrity
               hash, missing dependencies are installed next to the new copy, native
               packages are rebuilt, and the copy and the packages that use it are
               load-tested before and after (a new failure undoes the change).
  py-migrate   move a Python environment whose fixes need a newer Python to a newer
               interpreter (pyenv / pyenv-win): install it, reinstall the env's top-level
               packages there, switch `pyenv global`, and retire the old env into the
               run's backup folder (restored by rollback).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from scs import cooldown, toolchain
from scs.util import USER_AGENT, data_dir, http_json, urlopen
from scs.versions import vkey

PY_TOOLS = {"pip", "setuptools", "wheel"}


def self_argv() -> list[str]:
    """How to start scs itself from a plan command (frozen apps have no `python -m scs`)."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--cli"]
    return [sys.executable, "-m", "scs"]


def package_parent() -> str:
    """Directory that must be on PYTHONPATH for `python -m scs` to work from any folder."""
    return str(Path(__file__).resolve().parent.parent)


def _major(v: str) -> int:
    m = re.match(r"\d+", v)
    return int(m.group()) if m else 0


# ---------------------------------------------------------------- npm: patch inside a global tool

class FixError(Exception):
    pass


def node_for_root(root: Path) -> str:
    """The node binary that runs tools installed in a global node_modules."""
    prefix = root.parent.parent if root.parent.name == "lib" else root.parent
    for cand in (prefix / "bin" / "node", prefix / "node.exe", prefix / "node"):
        if cand.is_file():
            return str(cand)
    return shutil.which("node") or "node"


def npm_for_root(root: Path) -> str:
    prefix = root.parent.parent if root.parent.name == "lib" else root.parent
    for cand in (prefix / "bin" / "npm", prefix / "npm.cmd", prefix / "npm"):
        if cand.is_file():
            return str(cand)
    return shutil.which("npm") or "npm"


def _read_pkg(d: Path) -> dict:
    try:
        return json.loads((d / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def find_copies(tool_dir: Path, name: str) -> list[Path]:
    """Every installed copy of `name` inside a tool (hoisted or nested), not following symlinks."""
    out = []
    parts = name.split("/")
    for dirpath, dirnames, _ in os.walk(tool_dir):
        if os.path.basename(dirpath) == "node_modules":
            cand = Path(dirpath, *parts)
            if (cand / "package.json").is_file() and not cand.is_symlink():
                out.append(cand)
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
    return sorted(out)


def _registry_doc(name: str, version: str) -> dict:
    return http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}/{version}", retries=2)


def best_version(name: str, rng: str, min_age: int = 0) -> Optional[str]:
    """Newest stable release in the range that was published at least min_age days ago."""
    doc = toolchain.npm_packument(name)
    if not doc:
        return None
    times = cooldown.npm_times(name) if min_age else None
    ok = [v for v in doc["versions"] if re.fullmatch(r"\d+\.\d+\.\d+", v) and _safe_ok(v, rng)
          and cooldown.old_enough(times, v, min_age)]
    return max(ok, key=vkey) if ok else None


def _safe_ok(version: str, rng: str) -> bool:
    try:
        return toolchain.npm_ok(version, rng)
    except (ValueError, IndexError, KeyError):
        return False


def _download(doc: dict) -> bytes:
    dist = doc.get("dist") or {}
    url = dist.get("tarball")
    if not url or not url.startswith("https://"):
        raise FixError(f"{doc.get('name')}@{doc.get('version')}: registry gave no https tarball")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=180) as r:
        data = r.read()
    integrity = dist.get("integrity", "")
    if integrity.startswith("sha512-"):
        if base64.b64encode(hashlib.sha512(data).digest()).decode() != integrity[7:]:
            raise FixError(f"{doc['name']}@{doc['version']}: tarball does not match the registry's sha512")
    elif dist.get("shasum"):
        if hashlib.sha1(data).hexdigest() != dist["shasum"]:
            raise FixError(f"{doc['name']}@{doc['version']}: tarball does not match the registry's shasum")
    else:
        raise FixError(f"{doc['name']}@{doc['version']}: registry gave no integrity hash")
    return data


def _extract(data: bytes, dest: Path) -> None:
    """npm tarballs hold one top folder (usually package/); strip it, refuse anything escaping dest."""
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            parts = Path(m.name.replace("\\", "/")).parts[1:]
            if not parts or m.name.startswith("/") or ".." in parts:
                continue
            if not (m.isfile() or m.isdir()):
                continue  # npm itself ignores links in tarballs
            target = dest.joinpath(*parts)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with open(target, "wb") as f:
                shutil.copyfileobj(src, f)
            os.chmod(target, 0o755 if m.mode & 0o111 else 0o644)


def _resolves(name: str, rng: str, start: Path, stop: Path) -> bool:
    """Would Node find a copy of `name` satisfying `rng` from package dir `start` (up to the tool dir)?"""
    d = start
    while True:
        if d.name != "node_modules":
            cand = d.joinpath("node_modules", *name.split("/"))
            if (cand / "package.json").is_file():
                return _safe_ok(_read_pkg(cand).get("version", "0"), rng)
        if d == stop or d.parent == d:
            return False
        d = d.parent


def _needs_build(d: Path, pkg: dict) -> bool:
    scripts = pkg.get("scripts") or {}
    return bool(pkg.get("gypfile") or (d / "binding.gyp").is_file()
                or any(k in scripts for k in ("preinstall", "install", "postinstall")))


class NestedPatcher:
    def __init__(self, root: Path, tool: str, out: Callable[[str], None] = print, budget: int = 40, min_age: int = 0):
        self.root = Path(root)
        self.min_age = min_age  # release-age cooldown for every version fetched (see scs/cooldown.py)
        self.tool_dir = self.root / tool
        self.tool = tool
        self.out = out
        self.budget = budget  # max packages fetched in one run (guards against dependency explosions)
        self.node = node_for_root(self.root)
        self.npm = npm_for_root(self.root)
        self.changed: list[tuple[Path, Path]] = []  # (live path, moved-aside old copy)

    # -- install one package version at dest (dest must not exist), with missing deps nested under it
    def _install(self, name: str, version: str, dest: Path, depth: int = 0) -> list[Path]:
        if self.budget <= 0 or depth > 6:
            raise FixError("too many new dependencies to install safely; update the tool instead")
        self.budget -= 1
        doc = _registry_doc(name, version)
        _extract(_download(doc), dest)
        built = [dest] if _needs_build(dest, _read_pkg(dest)) else []
        deps = {**(doc.get("dependencies") or {}), **(doc.get("optionalDependencies") or {})}
        for dep, rng in sorted(deps.items()):
            if _resolves(dep, rng, dest, self.tool_dir):
                continue
            v = best_version(dep, rng, self.min_age)
            if not v:
                if dep in (doc.get("optionalDependencies") or {}):
                    continue
                raise FixError(f"{name}@{version} needs {dep}@{rng}, which is not on the registry")
            self.out(f"   + {dep}@{v} (needed by {name}@{version})")
            built += self._install(dep, v, dest.joinpath("node_modules", *dep.split("/")), depth + 1)
        return built

    def _load(self, name: str, from_dir: Path) -> tuple[bool, str]:
        """Can Node load `name` as seen from `from_dir` (CommonJS, falling back to ESM import)?"""
        js = ("const [n,f]=process.argv.slice(1);const r=require('module').createRequire(require('path').join(f,'x.js'));"
              "const fail=e=>{console.error(String(e&&e.message||e).split('\\n')[0]);process.exit(1)};"
              "try{r(n);process.exit(0)}catch(e){if(!/ERR_REQUIRE_(ESM|ASYNC_MODULE)|ERR_PACKAGE_PATH_NOT_EXPORTED/.test(e.code||''))fail(e);"
              "let u;try{u=require('url').pathToFileURL(r.resolve(n)).href}catch(e2){fail(e)}"
              "import(u).then(()=>process.exit(0),fail)}")
        try:
            r = subprocess.run([self.node, "-e", js, name, str(from_dir)], capture_output=True, text=True, timeout=60,
                               stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, str(e)
        return r.returncode == 0, (r.stderr or r.stdout).strip()[:300]

    def _users(self, copy: Path, name: str) -> list[tuple[str, Path]]:
        """Packages that would load this copy: (package name, dir to resolve it from)."""
        nm = copy.parent if "/" not in name else copy.parent.parent  # the node_modules holding the copy
        owner = nm.parent
        cands = [owner] if (owner / "package.json").is_file() else []
        try:
            for e in os.scandir(nm):
                d = Path(e.path)
                sub = [Path(s.path) for s in os.scandir(d)] if e.name.startswith("@") and d.is_dir() else [d]
                cands += [s for s in sub if s != copy]
        except OSError:
            pass
        out = []
        for d in cands:
            pkg = _read_pkg(d)
            deps = {**(pkg.get("dependencies") or {}), **(pkg.get("optionalDependencies") or {})}
            if name in deps and pkg.get("name"):
                out.append((pkg["name"], d.parent.parent if d.parent.name.startswith("@") else d.parent))
        return out[:12]

    def patch(self, specs: dict[str, str], allow_major: bool = False, only: Optional[dict[str, set[str]]] = None) -> dict:
        """specs: name -> fixed version; only: name -> the flagged versions (other copies are left alone)."""
        if not (self.tool_dir / "package.json").is_file():
            raise FixError(f"{self.tool} is not installed in {self.root}")
        done, skipped = [], []
        for name, fix in sorted(specs.items()):
            copies = [c for c in find_copies(self.tool_dir, name)
                      if vkey(_read_pkg(c).get("version", "0")) < vkey(fix)
                      and (not (only or {}).get(name) or _read_pkg(c).get("version") in only[name])]
            if not copies:
                self.out(f"   {name}: no copy older than {fix} inside {self.tool} (already fixed)")
                continue
            target = best_version(name, f"^{fix}", self.min_age) or fix  # newest release in the fix's own major line
            if not cooldown.old_enough(cooldown.npm_times(name) if self.min_age else None, target, self.min_age):
                raise FixError(f"{name} {target} was published less than {self.min_age} days ago; waiting before installing it")
            for copy in copies:
                old = _read_pkg(copy).get("version", "?")
                if _major(old) != _major(target) and not allow_major:
                    skipped.append(f"{name} {old} → {target} (major version change: needs 'apply groups that need care')")
                    self.out(f"   skip {name} {old} → {target}: major version change")
                    continue
                users = self._users(copy, name)
                before = {u: self._load(*u)[0] for u in [(name, copy.parent.parent if "/" in name else copy.parent)] + users}
                self.out(f"   {name} {old} → {target}  ({copy.relative_to(self.root)})")
                staged = copy.with_name(copy.name + ".scs-new")
                shutil.rmtree(staged, ignore_errors=True)
                try:
                    built = self._install(name, target, staged)
                except Exception:
                    shutil.rmtree(staged, ignore_errors=True)
                    raise
                aside = copy.with_name(copy.name + f".scs-old-{int(time.time())}")
                os.replace(copy, aside)
                os.replace(staged, copy)
                self.changed.append((copy, aside))
                for b in built:
                    real = copy / b.relative_to(staged) if b != staged else copy
                    self._rebuild(real)
                regressed = [f"{u[0]}: {msg}" for u, ok_before in before.items() if ok_before
                             for ok, msg in [self._load(*u)] if not ok]
                if regressed:
                    raise FixError(f"after updating {name}, Node can no longer load " + "; ".join(regressed[:3]))
                done.append({"name": name, "from": old, "to": target, "path": str(copy)})
        self._record(done)
        for live, aside in self.changed:
            shutil.rmtree(aside, ignore_errors=True)
        self.changed = []
        return {"patched": done, "skipped": skipped}

    def _rebuild(self, pkg_dir: Path) -> None:
        if os.environ.get("npm_config_ignore_scripts", "").lower() == "true":
            raise FixError(f"{pkg_dir.name} has a native build step, but install scripts are disabled")
        name = _read_pkg(pkg_dir).get("name", pkg_dir.name)
        cwd = pkg_dir.parent.parent if pkg_dir.parent.name.startswith("@") else pkg_dir.parent
        cwd = cwd.parent  # the package that owns this node_modules
        self.out(f"   building {name} (it has an install step)…")
        r = subprocess.run([self.npm, "rebuild", name], cwd=str(cwd), capture_output=True, text=True, timeout=1800,
                           stdin=subprocess.DEVNULL)
        if r.returncode != 0:
            raise FixError(f"building {name} failed: " + ((r.stderr or r.stdout).strip().splitlines() or ["?"])[-1][:240])

    def _record(self, done: list[dict]) -> None:
        if not done:
            return
        marker = self.tool_dir / ".scs-patched.json"
        try:
            data = json.loads(marker.read_text()) if marker.is_file() else {}
        except ValueError:
            data = {}
        for d in done:
            data[d["name"]] = {"from": d["from"], "to": d["to"], "at": time.strftime("%Y-%m-%d"),
                               "note": f"patched by scs inside {self.tool}; reinstalling {self.tool} undoes it"}
        marker.write_text(json.dumps(data, indent=1))

    def undo(self) -> None:
        for live, aside in reversed(self.changed):
            if aside.exists():
                shutil.rmtree(live, ignore_errors=True)
                os.replace(aside, live)
        self.changed = []


def npm_nested(root: str, tool: str, specs: dict[str, str], allow_major: bool = False,
               out: Callable[[str], None] = print, only: Optional[dict[str, set[str]]] = None, min_age: int = 0) -> int:
    p = NestedPatcher(Path(root), tool, out, min_age=min_age)
    try:
        res = p.patch(specs, allow_major, only)
    except Exception as e:
        p.undo()
        out(f"ERROR: {e}")
        return 1
    if res["patched"]:
        out(f"patched {len(res['patched'])} copy(ies) inside {tool}")
    if res["skipped"] and not res["patched"]:
        out("ERROR: nothing patched: " + "; ".join(res["skipped"]))
        return 3
    return 0


# ---------------------------------------------------------------- python: release-age check

def _freeze(lines: str) -> dict[str, str]:
    out = {}
    for line in lines.splitlines():
        name, sep, version = line.strip().partition("==")
        if sep and name and not name.startswith("#"):
            out[_norm(name)] = version.strip()
    return out


def age_check(python: str, since: str, min_age: int, out: Callable[[str], None] = print) -> int:
    """Exit 1 when a package that changed since the `pip freeze` in `since` was published < min_age days ago."""
    if not os.path.isfile(since):
        return 0  # baseline run (before the change): nothing has changed yet
    with open(since, encoding="utf-8", errors="replace") as fh:
        before = _freeze(fh.read())
    r = subprocess.run([python, "-m", "pip", "freeze", "--all"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        out(f"ERROR: pip freeze failed: {r.stderr.strip()[:300]}")
        return 1
    changed = {n: v for n, v in _freeze(r.stdout).items() if before.get(n) != v}
    if not changed:
        return 0
    bad, unknown = cooldown.too_new(changed, min_age)
    for b in bad:
        out(f"too new: {b}: installed releases must be at least {min_age} days old")
    for u in unknown:
        out(f"cannot read the release date of {u} from PyPI")
    if not bad and not unknown:
        out(f"{len(changed)} changed package(s), all released at least {min_age} days ago")
    return 1 if bad or unknown else 0


# ---------------------------------------------------------------- build environment check

def build_check(python: str, allow_vulnerable: bool = False, out: Callable[[str], None] = print) -> int:
    """Gate for the packaging scripts: every package about to be bundled into the app is looked up in OSV
    (malicious and vulnerable releases) and its site-packages is checked for code that runs at startup."""
    from scs.collectors.python import scan_site
    from scs.enrich import osv
    from scs.malware.packages import scan_site_packages
    r = subprocess.run([python, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        out(f"ERROR: cannot run {python}: {r.stderr.strip()[:200]}")
        return 1
    site = Path(r.stdout.strip())
    pkgs = scan_site(site, "build")
    out(f"build environment: {len(pkgs)} package(s) in {site}")
    hits = osv.lookup([(p.ecosystem, p.name, p.version) for p in pkgs])
    if osv.LAST_RUN.get("failed"):
        out(f"ERROR: OSV lookup incomplete ({osv.LAST_RUN.get('first_error', '')[:200]}): can't vouch for this environment")
        return 1
    bad = vulnerable = 0
    for (eco, name, version), advs in sorted(hits.items()):
        mal = [a for a in advs if a.malicious]
        if mal:
            bad += 1
            out(f"MALICIOUS  {name} {version}: {', '.join(a.id for a in mal)}")
        else:
            vulnerable += 1
            out(f"vulnerable {name} {version}: " + ", ".join(f"{a.id} ({a.severity}, fixed in {', '.join(a.fixed) or 'none'})"
                                                            for a in advs[:4]))
    findings, _ = scan_site_packages([site])
    for f in findings:
        if f.severity in ("critical", "high", "medium"):
            bad += 1
            out(f"SUSPICIOUS {f.title}: {f.path}")
    if bad or (vulnerable and not allow_vulnerable):
        out(f"build-check FAILED: {bad} malicious/suspicious, {vulnerable} vulnerable"
            + ("" if bad else " (re-lock, or pass --allow-vulnerable after reviewing them)"))
        return 1
    out(f"build-check passed ({vulnerable} vulnerable package(s) allowed)" if vulnerable else "build-check passed")
    return 0


# ---------------------------------------------------------------- python: smoke test

PY_SMOKE = r'''"""scs: import the top-level modules of the given distributions (exit 1 if any fails)."""
import importlib, sys
try:
    import importlib.metadata as md
except ImportError:
    md = None
bad = []
for dist in sys.argv[1:]:
    if md is None:
        break
    try:
        d = md.distribution(dist)
    except Exception as e:
        bad.append("%s: not installed (%s)" % (dist, e))
        continue
    mods = [m.strip() for m in (d.read_text("top_level.txt") or "").split() if m.strip() and not m.startswith("_")]
    if not mods:
        for f in d.files or []:
            parts = str(f).replace("\\", "/").split("/")
            if len(parts) > 1 and parts[0].isidentifier():
                mods.append(parts[0])
            elif len(parts) == 1 and parts[0].endswith(".py") and parts[0][:-3].isidentifier():
                mods.append(parts[0][:-3])
    for m in sorted(set(mods))[:4]:
        if m in ("tests", "test", "docs", "examples"):
            continue
        try:
            importlib.import_module(m)
        except BaseException as e:
            bad.append("%s (import %s): %s: %s" % (dist, m, type(e).__name__, str(e).splitlines()[0][:160] if str(e) else ""))
print("\n".join(bad) or "ok")
sys.exit(1 if bad else 0)
'''


def py_smoke_path() -> str:
    """The import smoke test, written where any interpreter (even another user's via sudo) can read it."""
    p = data_dir() / "helpers" / "py_smoke.py"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.is_file() or p.read_text() != PY_SMOKE:
        p.write_text(PY_SMOKE)
    return str(p)


# ---------------------------------------------------------------- python: move an env to a newer Python

def pyenv_exe() -> Optional[str]:
    return shutil.which("pyenv") or shutil.which("pyenv.bat")


def is_pyenv_env(env: str) -> bool:
    return bool(re.search(r"[/\\]\.pyenv[/\\](pyenv-win[/\\])?versions[/\\][^/\\]+$", env.rstrip("/\\")))


def _run(cmd: list[str], out: Callable[[str], None], timeout: int = 3600) -> str:
    out("   $ " + " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    text = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        tail = [ln for ln in text.strip().splitlines() if ln.strip()][-6:]
        raise FixError(f"{os.path.basename(cmd[0])} failed (exit {r.returncode}): " + " | ".join(tail)[:600])
    return text


def latest_pyenv_patch(minor: str, out: Callable[[str], None] = print) -> str:
    text = _run([pyenv_exe() or "pyenv", "install", "--list"], out, timeout=300)
    cands = [ln.strip() for ln in text.splitlines() if re.fullmatch(rf"{re.escape(minor)}\.\d+", ln.strip())]
    if not cands:
        raise FixError(f"pyenv does not know any Python {minor}.x (update pyenv: `brew upgrade pyenv` / `pyenv update`)")
    return max(cands, key=vkey)


def _pyenv_install(pyenv: str, version: str, versions: Path, out: Callable[[str], None]) -> None:
    try:
        _run([pyenv, "install", "-s", version], out, timeout=5400)
    except FixError as e:
        # pyenv reports failure when only its final shim refresh fails; the interpreter itself is fine
        if "rehash" not in str(e) or not (versions / version).is_dir():
            raise
        out("   pyenv installed it but could not refresh its command shims; repairing that")
    _rehash(pyenv, out)


def _rehash(pyenv: str, out: Callable[[str], None]) -> None:
    """`pyenv rehash`, clearing a lock file left behind by a crashed earlier rehash (older than 10 min)."""
    try:
        _run([pyenv, "rehash"], out, 180)
        return
    except FixError as e:
        err = e
    lock = Path(_run([pyenv, "root"], out).strip().splitlines()[-1]) / "shims" / ".pyenv-shim"
    if lock.is_file() and time.time() - lock.stat().st_mtime > 600:
        out(f"   removing a stale pyenv lock left over since {time.strftime('%Y-%m-%d', time.localtime(lock.stat().st_mtime))}")
        lock.unlink()
        _run([pyenv, "rehash"], out, 180)
    else:
        out(f"   warning: `pyenv rehash` failed ({err}); run it once by hand if a new command is not found")


def _pip_problems(python: str) -> set[str]:
    """Lines `pip check` reports (empty when consistent); never raises."""
    r = subprocess.run([python, "-m", "pip", "check", "--disable-pip-version-check"], capture_output=True, text=True,
                       timeout=600, stdin=subprocess.DEVNULL)
    return set() if r.returncode == 0 else {ln.strip() for ln in (r.stdout + r.stderr).splitlines() if ln.strip()}


_CONFLICT = re.compile(r"^(\S+) \S+ has requirement ([A-Za-z0-9_.\-]+)")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def conflict_keys(lines: set[str]) -> set[tuple[str, str]]:
    """(package, requirement) pairs from `pip check` "X 1.0 has requirement Y<2, but you have Y 3" lines."""
    return {(_norm(m.group(1)), _norm(m.group(2))) for ln in lines for m in [_CONFLICT.match(ln)] if m}


def requirements_of(python: str, dist: str) -> list[str]:
    """A distribution's unconditional requirements, as recorded in that environment."""
    code = ("import importlib.metadata as m,sys,json;"
            "print(json.dumps([r for r in (m.requires(sys.argv[1]) or []) if 'extra ==' not in r]))")
    try:
        r = subprocess.run([python, "-c", code, dist], capture_output=True, text=True, timeout=60)
        return [x.split(";")[0].strip() for x in json.loads(r.stdout or "[]")]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def env_python(env: Path) -> Path:
    for c in (env / "bin" / "python", env / "bin" / "python3", env / "python.exe"):
        if c.is_file():
            return c
    raise FixError(f"no python found in {env}")


def top_level_dists(python: str, out: Callable[[str], None]) -> list[str]:
    """Packages installed on purpose (nothing else requires them), minus pip's own tooling."""
    text = _run([python, "-m", "pip", "list", "--not-required", "--format=json", "--disable-pip-version-check"], out, 600)
    start = text.find("[")
    try:
        rows = json.loads(text[start:text.rfind("]") + 1]) if start >= 0 else []
    except ValueError:
        rows = []
    return sorted(r["name"] for r in rows if r["name"].lower() not in PY_TOOLS and not r.get("editable_project_location"))


MAC_USER_SITE = re.compile(r"[/\\]Library[/\\]Python[/\\]\d+\.\d+[/\\]lib[/\\]python[/\\]site-packages$")


def _pyenv_versions_dir(pyenv: str, out: Callable[[str], None]) -> Path:
    root = Path(_run([pyenv, "root"], out).strip().splitlines()[-1])
    win = root / "pyenv-win" / "versions"
    return win if win.is_dir() else root / "versions"


def py_migrate(env: str, to_minor: str, retire_to: str, wants: list[str], site: str = "",
               out: Callable[[str], None] = print) -> int:
    """Move an environment's packages to Python `to_minor` (pyenv), then retire the old environment.

    env mode:  a pyenv version (e.g. ~/.pyenv/versions/3.10.3) is rebuilt as the newest
               `to_minor` patch release; `pyenv global` follows if it pointed at the old one.
    site mode: a user site-packages of an interpreter scs cannot upgrade (Apple's Python 3.9)
               moves into the pyenv global Python if that is new enough, else a new pyenv version.
    """
    pyenv = pyenv_exe()
    if not pyenv:
        out("ERROR: pyenv is not installed; scs migrates environments with pyenv")
        return 1
    old_env = Path(env)
    retire = Path(retire_to)
    retire.mkdir(parents=True, exist_ok=True)
    try:
        tops = _site_tops(site) if site else top_level_dists(str(env_python(old_env)), out)
        versions = old_env.parent if not site and is_pyenv_env(env) else _pyenv_versions_dir(pyenv, out)
        current = _run([pyenv, "global"], out).split()
        new_env = None
        if site and current and current[0] != "system" and vkey(current[0]) >= vkey(to_minor) \
                and (versions / current[0]).is_dir():
            new_env = versions / current[0]  # the user's default Python is already new enough
        if new_env is None:
            version = latest_pyenv_patch(to_minor, out)
            out(f"   installing Python {version} with pyenv (this can take several minutes)…")
            _pyenv_install(pyenv, version, versions, out)
            new_env = versions / version
        if not new_env.is_dir():
            raise FixError(f"pyenv Python folder {new_env} not found after install")
        out(f"   moving {len(tops)} package(s) to {new_env}: {', '.join(tops) or '(none)'}")
        new_py = str(env_python(new_env))
        _run([new_py, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "pip"], out, 900)
        known = _pip_problems(new_py)  # an existing target env may already have conflicts: only new ones count
        # packages whose pins the old env already ignored (pip check listed them) would make the resolver
        # give up; they keep that state: installed without their pinned deps, the rest of their deps normally
        accepted = conflict_keys(_pip_problems(str(env_python(old_env)))) if not site else set()
        upgrading = {_norm(re.split(r"[<>=!~]", w)[0]) for w in wants}
        lenient = {a for a, _ in accepted} - upgrading  # packages upgraded on purpose resolve normally
        normal = [x for x in tops if _norm(x) not in lenient]
        loose = [x for x in tops if _norm(x) in lenient]
        reqs = list(dict.fromkeys(normal + [w for w in wants if _norm(re.split(r"[<>=!~]", w)[0]) not in PY_TOOLS]))
        if loose:
            pinned_away = {b for a, b in accepted if a in {_norm(x) for x in loose}}
            for x in loose:
                for r in requirements_of(str(env_python(old_env)), x):
                    name = _norm(re.split(r"[<>=!~;\[ (]", r, 1)[0])
                    reqs.append(name if name in pinned_away else r)
            reqs = list(dict.fromkeys(reqs))
            out(f"   {', '.join(loose)}: their pins were already not met in {old_env.name}; keeping that as it was")
        if reqs:
            _run([new_py, "-m", "pip", "install", "--disable-pip-version-check", *reqs], out, 3600)
        if loose:
            _run([new_py, "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", *loose], out, 1800)
        new_problems = {ln for ln in _pip_problems(new_py) - known if not (conflict_keys({ln}) & accepted)}
        if new_problems:
            raise FixError("the moved packages conflict: " + " | ".join(sorted(new_problems)[:6]))
        state = {"env": env, "site": site, "new_version": new_env.name, "new_env": str(new_env), "packages": tops}
        if not site and old_env.name in current:
            state["old_global"] = current
            _run([pyenv, "global", *[new_env.name if v == old_env.name else v for v in current]], out)
            _rehash(pyenv, out)
        if site:
            moved_from = Path(site).parent.parent.parent if MAC_USER_SITE.search(site) else Path(site)
        else:
            moved_from = old_env
        dest = retire / moved_from.name
        shutil.move(str(moved_from), str(dest))
        state["retired_from"], state["retired_to"] = str(moved_from), str(dest)
        (retire / "scs-migrate.json").write_text(json.dumps(state, indent=1))
        out(f"   retired {moved_from} → {dest} (rollback puts it back)")
    except Exception as e:
        out(f"ERROR: {e}")
        return 1
    return 0


def _site_tops(site: str) -> list[str]:
    from scs.collectors.python import scan_site
    graphs: dict = {}
    pkgs = scan_site(Path(site), "user", graphs)
    g = graphs.get(site)
    roots = set(g.roots) if g else set()
    return sorted(p.name for p in pkgs if p.meta.get("node") in roots and p.name.lower() not in PY_TOOLS)


def undo_migrate(retire_to: Path) -> list[str]:
    state_file = retire_to / "scs-migrate.json"
    if not state_file.is_file():
        return []
    state = json.loads(state_file.read_text())
    notes = []
    src, dst = Path(state["retired_to"]), Path(state["retired_from"])
    if src.exists() and not dst.exists():
        shutil.move(str(src), str(dst))
        notes.append(f"put {dst} back")
    if state.get("old_global") and pyenv_exe():
        _run([pyenv_exe(), "global", *state["old_global"]], lambda m: None, timeout=60)
        notes.append(f"pyenv global restored to {' '.join(state['old_global'])}")
    notes.append(f"Python {state['new_version']} stays installed (unused)")
    return notes


# ---------------------------------------------------------------- CLI

def add_parser(sub) -> None:
    fx = sub.add_parser("fixer", help="(used by patch plans) multi-step fixes: npm-nested, py-migrate")
    fs = fx.add_subparsers(dest="fixer", required=True)
    n = fs.add_parser("npm-nested", help="update a package bundled inside a global npm tool")
    n.add_argument("--root", required=True, help="global node_modules folder")
    n.add_argument("--tool", required=True)
    n.add_argument("--set", action="append", required=True, metavar="NAME@VERSION", help="fixed version (repeatable)")
    n.add_argument("--from", dest="from_", action="append", default=[], metavar="NAME@VERSION",
                   help="only replace copies at this (flagged) version (repeatable)")
    n.add_argument("--allow-major", action="store_true")
    n.add_argument("--min-age", type=int, default=0, metavar="DAYS", help="skip releases younger than this")
    b = fs.add_parser("build-check", help="check a build environment before packaging: known vulnerabilities, "
                      "malicious packages, startup hooks")
    b.add_argument("--python", required=True, help="the build venv's python")
    b.add_argument("--allow-vulnerable", action="store_true", help="report vulnerable packages but don't fail")
    a = fs.add_parser("age-check", help="fail if pip installed a release younger than --min-age days")
    a.add_argument("--python", required=True)
    a.add_argument("--since", required=True, help="`pip freeze --all` taken before the change")
    a.add_argument("--min-age", type=int, required=True, metavar="DAYS")
    m = fs.add_parser("py-migrate", help="move a Python environment to a newer Python (pyenv) and retire the old one")
    m.add_argument("--env", required=True)
    m.add_argument("--site", default="", help="migrate a user site-packages folder instead of a whole env")
    m.add_argument("--to", required=True, metavar="X.Y")
    m.add_argument("--retire-to", required=True)
    m.add_argument("--want", action="append", default=[], metavar="REQ", help="extra requirement, e.g. pillow>=13")
    m.add_argument("--undo", action="store_true", help="put a retired environment back")
    fx.set_defaults(func=cmd_fixer)


def cmd_fixer(args) -> int:
    if args.fixer == "npm-nested":
        specs = {}
        for s in args.set:
            name, _, version = s.rpartition("@")
            if not name or not version:
                print(f"bad --set {s!r} (want name@version)")
                return 2
            specs[name] = version
        only: dict[str, set[str]] = {}
        for s in args.from_:
            name, _, version = s.rpartition("@")
            only.setdefault(name, set()).add(version)
        return npm_nested(args.root, args.tool, specs, args.allow_major, only=only, min_age=args.min_age)
    if args.fixer == "build-check":
        return build_check(args.python, args.allow_vulnerable)
    if args.fixer == "age-check":
        return age_check(args.python, args.since, args.min_age)
    if args.undo:
        for n in undo_migrate(Path(args.retire_to)):
            print(n)
        return 0
    return py_migrate(args.env, args.to, args.retire_to, args.want, args.site)
