"""Toolchain constraints: which runtime a project/env uses vs. what a fixed version needs.

A fix that needs a newer Python/Node/Go/Rust/Ruby/PHP than the project pins (or
than the environment actually runs) cannot be applied blindly: those findings
go to "Verify first" with the exact conflict spelled out.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Optional

from scs import minitoml
from scs.models import Package, normalize_name
from scs.util import cache_dir, debug, http_json, http_text, read_json, write_json
from scs.versions import vkey

RUNTIME_OF = {"PyPI": "python", "npm": "node", "Go": "go", "crates.io": "rust", "RubyGems": "ruby",
              "Packagist": "php"}
REGISTRY_TTL = 30 * 24 * 3600  # published versions are immutable

# ---------------------------------------------------------------- spec evaluation

_NUM = re.compile(r"\d+")


def _nums(v: str) -> list[int]:
    out = []
    for part in re.split(r"[.+-]", v.strip().lstrip("vV=")):
        m = _NUM.match(part)
        if not m:
            break
        out.append(int(m.group()))
    return out


def _vstr(nums: list[int]) -> str:
    return ".".join(str(n) for n in nums)


def pep440_ok(version: str, spec: str) -> bool:
    """PEP 440 specifiers ('>=3.8,!=3.9.*', '~=3.10'); also RubyGems ('~> 2.8') and PHP-ish ('>=8.1')."""
    for clause in re.split(r"[,]|\s+(?=[<>=!~])", spec):
        c = clause.strip()
        if not c:
            continue
        m = re.match(r"^(~=|~>|===|==|!=|<=|>=|<|>|=)?\s*v?([0-9][0-9A-Za-z.*+-]*)$", c)
        if not m:
            continue
        op, ver = m.group(1) or "==", m.group(2)
        if ver.endswith(".*"):
            prefix = _nums(ver[:-2])
            match = _nums(version)[:len(prefix)] == prefix
            if (op == "==" and not match) or (op == "!=" and match):
                return False
            continue
        v, t = vkey(version), vkey(ver)
        if op in ("~=", "~>"):
            parts = _nums(ver)
            upper = parts[:-1] if len(parts) > 1 else parts[:]
            upper[-1] += 1
            if not (v >= t and v < vkey(_vstr(upper))):
                return False
        elif op in ("==", "===", "="):
            vn, tn = _nums(version), _nums(ver)
            if vn[:len(tn)] != tn:  # "3.10" satisfies ==3.10 and ==3.10.0
                return False
        elif not {"!=": v != t, "<=": v <= t, ">=": v >= t, "<": v < t, ">": v > t}[op]:
            return False
    return True


def _npm_expand(op: str, ver: str) -> list[tuple[str, list[int]]]:
    nums = []
    for p in ver.split(".")[:3]:
        if p in ("x", "X", "*") or not _NUM.match(p):
            break
        nums.append(int(_NUM.match(p).group()))
    n = len(nums)
    full = nums + [0] * (3 - n)
    if n == 0:
        return []
    a, b, c = full

    def nxt(i: int) -> list[int]:
        out = full[:i + 1]
        out[i] += 1
        return out + [0] * (2 - i)

    if op in ("", "="):
        return [("=", full)] if n == 3 else [(">=", full), ("<", nxt(n - 1))]
    if op == "^":
        if a > 0 or n == 1:
            return [(">=", full), ("<", nxt(0))]
        if b > 0 or n == 2:
            return [(">=", full), ("<", nxt(1))]
        return [(">=", full), ("<", nxt(2))]
    if op == "~":
        return [(">=", full), ("<", nxt(0 if n == 1 else 1))]
    if op == ">" and n < 3:
        return [(">=", nxt(n - 1))]
    if op == "<=" and n < 3:
        return [("<", nxt(n - 1))]
    return [(op, full)]


def npm_ok(version: str, rng: str) -> bool:
    """node-semver ranges: '^18.13.0 || >=20.9.0', '~1.2', '1.x', '>=1 <2', '1.0 - 2.0'."""
    rng = rng.strip()
    if rng in ("", "*", "x", "latest"):
        return True
    v = _nums(version) + [0, 0, 0]
    v = v[:3]
    for alt in rng.split("||"):
        alt = alt.strip()
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        comps: list[tuple[str, list[int]]] = []
        if hy:
            comps += [c for c in _npm_expand(">=", hy.group(1)) if c[0] == ">="]
            hi = _npm_expand("", hy.group(2))
            comps += [("<=", hi[0][1])] if hi and hi[0][0] == "=" else [c for c in hi if c[0] == "<"]
        else:
            for op, ver in re.findall(r"(<=|>=|<|>|=|\^|~)?\s*v?([0-9xX*][0-9A-Za-z.*+-]*)", alt):
                comps += _npm_expand(op, ver)
        ok = True
        for op, t in comps:
            if not {"=": v == t, ">=": v >= t, ">": v > t, "<": v < t, "<=": v <= t}[op]:
                ok = False
                break
        if ok:
            return True
    return False


def _caret_style(spec: str) -> bool:
    """Poetry/composer use npm-style ^ and ~ (but not PEP 440 ~= or RubyGems ~>)."""
    return bool(re.search(r"\^|~(?![=>])|\|\|", spec))


def satisfies(runtime: str, version: str, spec: str) -> bool:
    if runtime == "node" or _caret_style(spec):
        return npm_ok(version, spec)
    return pep440_ok(version, spec)


def lower_bound(runtime: str, spec: str) -> Optional[str]:
    """Smallest version mentioned in the spec that satisfies it (the oldest supported runtime)."""
    cands = sorted({m for m in re.findall(r"\d+(?:\.\d+)*", spec)}, key=vkey)
    for c in cands:
        if satisfies(runtime, c, spec):
            return c
    return None


# ---------------------------------------------------------------- project detection

def _first_line(path: Path) -> Optional[str]:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                return line
    except OSError:
        pass
    return None


def _set(info: dict, runtime: str, value: Optional[str] = None, spec: Optional[str] = None, source: str = "") -> None:
    if runtime in info and info[runtime].get("value"):
        return  # an exact pin found earlier wins
    if value:
        value = value.strip().lstrip("v")
        if not re.match(r"^\d+(\.\d+)*$", value):
            return  # 'lts/*', 'stable', 'system' ... not comparable
        info[runtime] = {"value": value, "source": source}
    elif spec and runtime not in info:
        lb = lower_bound(runtime, spec)
        if lb:
            info[runtime] = {"value": lb, "spec": spec, "source": source}


def detect_project(directory: str | Path) -> dict:
    """Runtime versions and dependency pins declared by a project directory."""
    d = Path(directory)
    info: dict = {}
    pins: dict[str, dict[str, str]] = {"npm": {}, "PyPI": {}}

    for name, rt in ((".python-version", "python"), (".nvmrc", "node"), (".node-version", "node"),
                     (".ruby-version", "ruby"), (".go-version", "go"), (".java-version", "java")):
        v = _first_line(d / name)
        if v:
            _set(info, rt, value=re.sub(r"^(python|ruby|node)-", "", v), source=name)
    tv = d / ".tool-versions"
    if tv.is_file():
        for line in tv.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                rt = {"nodejs": "node", "golang": "go"}.get(parts[0], parts[0])
                _set(info, rt, value=parts[1], source=".tool-versions")
    for tc in ("rust-toolchain.toml", "rust-toolchain"):
        p = d / tc
        if p.is_file():
            txt = p.read_text(encoding="utf-8", errors="replace")
            m = re.search(r'channel\s*=\s*"([^"]+)"', txt) or re.match(r"\s*(\S+)", txt)
            if m:
                _set(info, "rust", value=m.group(1), source=tc)

    pkg_json = d / "package.json"
    if pkg_json.is_file():
        try:
            pj = json.loads(pkg_json.read_text(encoding="utf-8"))
        except ValueError:
            pj = {}
        if (pj.get("volta") or {}).get("node"):
            _set(info, "node", value=pj["volta"]["node"], source="package.json volta")
        if (pj.get("engines") or {}).get("node"):
            _set(info, "node", spec=pj["engines"]["node"], source="package.json engines")
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            pins["npm"].update({k: str(v) for k, v in (pj.get(field) or {}).items()})
        info["scripts"] = sorted((pj.get("scripts") or {}).keys())

    pyproject = d / "pyproject.toml"
    if pyproject.is_file():
        try:
            pp = minitoml.load_path(pyproject)
        except (OSError, ValueError):
            pp = {}
        proj = pp.get("project") or {}
        if proj.get("requires-python"):
            _set(info, "python", spec=proj["requires-python"], source="pyproject requires-python")
        poetry = (pp.get("tool") or {}).get("poetry") or {}
        deps = dict(poetry.get("dependencies") or {})
        if isinstance(deps.get("python"), str):
            _set(info, "python", spec=deps.pop("python"), source="pyproject poetry python")
        for name, spec in deps.items():
            if isinstance(spec, dict):
                spec = spec.get("version", "")
            if isinstance(spec, str) and spec:
                pins["PyPI"][normalize_name("PyPI", name)] = spec
        for req in proj.get("dependencies") or []:
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*)", req)
            if m and m.group(3).strip():
                pins["PyPI"][normalize_name("PyPI", m.group(1))] = m.group(3).strip()

    gomod = d / "go.mod"
    if gomod.is_file():
        txt = gomod.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^toolchain\s+go(\S+)", txt, re.M)
        if m:
            _set(info, "go", value=m.group(1), source="go.mod toolchain")
        m = re.search(r"^go\s+(\S+)", txt, re.M)
        if m:
            _set(info, "go", value=m.group(1), source="go.mod go directive")

    cargo = d / "Cargo.toml"
    if cargo.is_file():
        m = re.search(r'^rust-version\s*=\s*"([^"]+)"', cargo.read_text(encoding="utf-8", errors="replace"), re.M)
        if m:
            _set(info, "rust", value=m.group(1), source="Cargo.toml rust-version")

    gemfile = d / "Gemfile"
    if gemfile.is_file():
        m = re.search(r"""^\s*ruby\s+['"]([^'"]+)['"]""", gemfile.read_text(encoding="utf-8", errors="replace"), re.M)
        if m:
            _set(info, "ruby", spec=m.group(1) if re.search(r"[<>~]", m.group(1)) else None,
                 value=None if re.search(r"[<>~]", m.group(1)) else m.group(1), source="Gemfile ruby")

    composer = d / "composer.json"
    if composer.is_file():
        try:
            cj = json.loads(composer.read_text(encoding="utf-8"))
            if (cj.get("require") or {}).get("php"):
                _set(info, "php", spec=cj["require"]["php"].replace("|", " ||"), source="composer.json php")
        except ValueError:
            pass

    info["pins"] = {k: v for k, v in pins.items() if v}
    info["markers"] = sorted(f for f in ("Makefile", "pytest.ini", "tox.ini", "noxfile.py", "Rakefile", "tests", "test")
                             if (d / f).exists())
    return info


def runtime_for(p: Package, projects: dict[str, dict], brew_versions: dict[str, str]) -> Optional[dict]:
    """The runtime version a package instance actually runs on (or is declared for)."""
    rt = RUNTIME_OF.get(p.ecosystem)
    if not rt:
        return None
    if p.source == "pip" and p.meta.get("runtime"):
        return {"value": p.meta["runtime"], "source": "its interpreter"}
    if p.source == "npm-global":
        m = re.search(r"/v?(\d+\.\d+\.\d+)/", p.meta.get("root", ""))
        if m:
            return {"value": m.group(1), "source": "node version of this global prefix"}
        if "node" in brew_versions and "/homebrew/" in p.meta.get("root", "").lower():
            return {"value": brew_versions["node"], "source": "Homebrew node"}
        return None
    if p.source == "cargo":
        m = re.search(r"rustc (\d+\.\d+\.\d+)", p.meta.get("rustc", ""))
        return {"value": m.group(1), "source": "rustc used for install"} if m else None
    if p.source == "lockfile":
        proj = projects.get(p.meta.get("project", ""))
        if proj and rt in proj:
            return proj[rt]
    return None


# ---------------------------------------------------------------- registry requirements

def _go_escape(mod: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), mod)


def _fetch_requirement(eco: str, name: str, version: str) -> Optional[str]:
    q = urllib.parse.quote
    if eco == "PyPI":
        return (http_json(f"https://pypi.org/pypi/{q(name)}/{q(version)}/json").get("info") or {}).get("requires_python") or None
    if eco == "npm":
        return (http_json(f"https://registry.npmjs.org/{q(name, safe='@')}/{q(version)}").get("engines") or {}).get("node") or None
    if eco == "crates.io":
        rv = (http_json(f"https://crates.io/api/v1/crates/{q(name)}/{q(version)}").get("version") or {}).get("rust_version")
        return f">={rv}" if rv else None  # rust-version is a minimum
    if eco == "RubyGems":
        req = http_json(f"https://rubygems.org/api/v2/rubygems/{q(name)}/versions/{q(version)}.json").get("ruby_version")
        return None if not req or req.strip() == ">= 0" else req
    if eco == "Go":
        txt = http_text(f"https://proxy.golang.org/{_go_escape(name)}/@v/v{version}.mod")
        m = re.search(r"^go\s+(\S+)", txt, re.M)
        return f">={m.group(1)}" if m else None
    if eco == "Packagist":
        data = http_json(f"https://repo.packagist.org/p2/{name}.json")
        cur: dict = {}
        for entry in (data.get("packages") or {}).get(name, []):  # minified: fields carry forward
            cur.update({k: v for k, v in entry.items() if v != "__unset"})
            if cur.get("version", "").lstrip("v") == version:
                php = (cur.get("require") or {}).get("php")
                return php.replace("|", " ||") if php else None
        return None
    return None


class Requirements:
    """Cached lookups of the runtime requirement of a specific package version."""

    def __init__(self, offline: bool = False):
        self.offline = offline
        self.path = cache_dir() / "registry.json"
        self.cache: dict = read_json(self.path) if self.path.exists() else {}
        self.dirty = False

    def get(self, eco: str, name: str, version: str) -> Optional[str]:
        key = f"{eco}|{name}|{version}"
        hit = self.cache.get(key)
        if hit and (self.offline or time.time() - hit["t"] < REGISTRY_TTL):
            return hit["req"]
        if self.offline:
            return None
        try:
            req = _fetch_requirement(eco, name, version)
        except Exception as e:
            debug(f"registry lookup {key}: {e}")
            return None
        self.cache[key] = {"t": time.time(), "req": req}
        self.dirty = True
        return req

    def save(self) -> None:
        if self.dirty:
            write_json(self.path, self.cache)


def check(p: Package, fix: str, runtime: Optional[dict], req: Optional[str], ecosystem: str) -> list[str]:
    """Reasons (if any) why applying `fix` to this package instance needs verification."""
    reasons = []
    rt = RUNTIME_OF.get(ecosystem, "")
    if req and runtime and runtime.get("value"):
        try:
            ok = satisfies(rt, runtime["value"], req)
        except (KeyError, ValueError, IndexError):
            ok = True
        if not ok:
            reasons.append(f"{fix} needs {rt} {req}, but {_where(p)} uses {rt} {runtime['value']} ({runtime['source']})")
    return reasons


def pin_conflict(p: Package, fix: str, projects: dict[str, dict]) -> Optional[str]:
    """A direct dependency whose declared range in the manifest excludes the fix."""
    if p.source != "lockfile" or not p.direct:
        return None
    proj = projects.get(p.meta.get("project", ""), {})
    spec = (proj.get("pins") or {}).get(p.ecosystem, {}).get(
        normalize_name(p.ecosystem, p.name) if p.ecosystem == "PyPI" else p.name)
    if not spec or not re.search(r"\d", spec):
        return None
    try:
        allowed = npm_ok(fix, spec) if p.ecosystem == "npm" or _caret_style(spec) else pep440_ok(fix, spec)
    except (KeyError, ValueError, IndexError):
        return None
    if allowed:
        return None
    manifest = "package.json" if p.ecosystem == "npm" else "pyproject.toml"
    return f"{manifest} declares {p.name} '{spec}', which excludes {fix}: widen the range"


def _where(p: Package) -> str:
    if p.source == "lockfile":
        return os.path.basename(p.meta.get("project", "project")) or "project"
    if p.source == "pip":
        return f"env {p.meta.get('env', '')}"
    return p.source


# ---------------------------------------------------------------- global npm tools

NPM_TOOL_TTL = 24 * 3600


def npm_packument(name: str) -> Optional[dict]:
    """Abbreviated registry metadata (all versions with engines + dependencies), cached for a day."""
    path = cache_dir() / "npm-packuments.json"
    cache: dict = read_json(path) if path.exists() else {}
    hit = cache.get(name)
    if hit and time.time() - hit["t"] < NPM_TOOL_TTL:
        return hit["doc"]
    try:
        doc = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}",
                        headers={"Accept": "application/vnd.npm.install-v1+json"}, retries=2)
    except Exception as e:
        debug(f"npm registry {name}: {e}")
        return None
    slim = {"dist-tags": doc.get("dist-tags", {}),
            "versions": {v: {"engines": (m.get("engines") or {}), "deps": m.get("dependencies") or {}}
                         for v, m in (doc.get("versions") or {}).items()}}
    cache[name] = {"t": time.time(), "doc": slim}
    write_json(path, cache)
    return slim


def npm_tool_update(name: str, installed: str, node_version: Optional[str],
                    needs: Optional[dict[str, str]] = None, min_age: int = 0) -> dict:
    """Pick the version to update a global tool to, so bundled vulnerable packages get fixed.

    Newest *stable* release in the installed major whose engines.node accepts the running Node, and
    (when `needs` = {dep: fixed_version}) whose declared dependency ranges allow the fixed versions,
    published at least `min_age` days ago. Also reports the overall latest and whether it would run on this Node (for a "check first" note).
    """
    doc = npm_packument(name)
    if not doc:
        return {"error": f"could not read {name} from the npm registry"}
    def ok_node(v: str) -> bool:
        spec = doc["versions"][v]["engines"].get("node")
        return not node_version or not spec or npm_ok(node_version, spec)

    def covers(v: str) -> bool:
        # bundled deps: only a range whose *lowest* allowed version is >= the fix guarantees it
        deps = doc["versions"][v]["deps"]
        for d, fix in (needs or {}).items():
            if d in deps:
                lb = lower_bound("node", deps[d])
                if lb and vkey(lb) < vkey(fix):
                    return False
        return True

    stable = [v for v in doc["versions"] if re.fullmatch(r"\d+\.\d+\.\d+", v)]
    if min_age:
        from scs import cooldown
        times = cooldown.npm_times(name)
        stable = [v for v in stable if cooldown.old_enough(times, v, min_age)]
    major = (_nums(installed) or [0])[0]
    same = sorted((v for v in stable if _nums(v)[0] == major and vkey(v) > vkey(installed) and ok_node(v) and covers(v)),
                  key=vkey)
    latest = doc["dist-tags"].get("latest", "")
    return {"version": same[-1] if same else None, "latest": latest,
            "latest_runs_here": bool(latest) and latest in doc["versions"] and ok_node(latest),
            "latest_engines": doc["versions"].get(latest, {}).get("engines", {}).get("node", "")}


_node_versions: dict[str, Optional[str]] = {}


def node_version_for_root(root: str) -> Optional[str]:
    """Version of the Node.js that runs the tools in a global node_modules (<prefix>/lib/node_modules)."""
    if root in _node_versions:
        return _node_versions[root]
    m = re.search(r"/v?(\d+\.\d+\.\d+)/", root)  # nvm/fnm/volta keep the version in the path
    version = m.group(1) if m else None
    if not version:
        import subprocess
        prefix = os.path.dirname(os.path.dirname(root.rstrip("/")))
        for exe in (os.path.join(prefix, "bin", "node"), "node"):
            try:
                out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15).stdout.strip()
            except (OSError, subprocess.TimeoutExpired):
                continue
            if out:
                version = out.lstrip("v")
                break
    _node_versions[root] = version
    return version
