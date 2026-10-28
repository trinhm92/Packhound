"""Project lockfiles under the configured roots.

Every parser returns (packages, graph). The graph links the project's direct
dependencies to everything they pull in, so findings can show the full chain
of effect. Discovery also records virtualenvs and git repos under the roots.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Callable, Optional

from scs import minitoml, miniyaml
from scs.collectors import Collector, Context
from scs.graph import DepGraph, finalize
from scs.models import Package, normalize_name
from scs.util import debug, run

MAX_LOCKFILE_BYTES = 60 * 1024 * 1024

Parsed = tuple[list[Package], Optional[DepGraph]]


def _pkg(eco: str, name: str, version: str, lockfile: Path, node: str | None = None, **kw) -> Package:
    meta = {"project": str(lockfile.parent), "lockfile": lockfile.name}
    if node:
        meta["node"] = node
    return Package(ecosystem=eco, name=name, version=version, source="lockfile",
                   location=str(lockfile), scope="project", meta=meta, **kw)


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _read_toml(path: Path) -> dict:
    try:
        return minitoml.load_path(path)
    except (OSError, ValueError) as e:
        debug(f"cannot parse {path}: {e}")
        return {}


def _split_spec(spec: str) -> str:
    """'@scope/name@^1.0' -> '@scope/name'; 'name@npm:1.0' -> 'name'."""
    spec = spec.strip().strip('"').strip("'")
    idx = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    return spec[:idx] if idx > 0 else spec


def _manifest_deps(pkg_json: dict) -> list[tuple[str, str, str]]:
    out = []
    for field, kind in (("dependencies", "prod"), ("optionalDependencies", "prod"),
                        ("devDependencies", "dev")):
        for name, rng in (pkg_json.get(field) or {}).items():
            out.append((name, str(rng), kind))
    return out


# ---------------------------------------------------------------- npm family

def _resolve_npm(packages: dict, from_key: str, name: str) -> str | None:
    """Node's module resolution over package-lock 'packages' paths."""
    base = from_key
    while True:
        cand = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if cand in packages:
            entry = packages[cand]
            if entry.get("link") and entry.get("resolved") in packages:
                return entry["resolved"]
            return cand
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def parse_package_lock(path: Path) -> Parsed:
    d = json.loads(path.read_text(encoding="utf-8"))
    out: list[Package] = []
    packages = d.get("packages")
    if not isinstance(packages, dict):
        return _parse_package_lock_v1(path, d), None

    g = DepGraph()
    for key, info in packages.items():
        if info.get("link"):
            continue
        segs = [s.rstrip("/") for s in key.split("node_modules/")[1:]] if "node_modules/" in key else []
        name = info.get("name") or (segs[-1] if segs else (key or d.get("name") or "(root)"))
        version = info.get("version") or ""
        g.add_node(key, f"{name}@{version}" if version and key else name)
        if segs and version:
            out.append(_pkg("npm", name, version, path, node=key, dev=bool(info.get("dev")),
                            chain=segs[:-1]))
        for field in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            if field == "devDependencies" and key and "node_modules/" in key:
                continue  # dev deps of installed packages are never installed
            for dep in info.get(field) or {}:
                target = _resolve_npm(packages, key, dep)
                if target is None:
                    continue
                if "node_modules/" not in key:  # root project or workspace member
                    g.add_root(target, "dev" if field == "devDependencies" else "prod")
                else:
                    g.add_edge(key, target)
    return out, g


def _parse_package_lock_v1(path: Path, d: dict) -> list[Package]:
    out: list[Package] = []

    def walk(deps: dict, chain: list[str]) -> None:
        for name, info in deps.items():
            if info.get("version"):
                out.append(_pkg("npm", name, info["version"], path, dev=bool(info.get("dev")),
                                direct=not chain, chain=list(chain)))
            walk(info.get("dependencies") or {}, chain + [name])

    walk(d.get("dependencies") or {}, [])
    return out


def _yarn_blocks(text: str) -> list[dict]:
    blocks: list[dict] = []
    cur: dict | None = None
    section = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if indent == 0:
            specs = [x.strip().strip('"').strip("'") for x in s.rstrip(":").split(",")]
            cur = {"specs": [x for x in specs if x], "deps": []}
            blocks.append(cur)
            section = None
            continue
        if cur is None:
            continue
        if indent == 2:
            section = None
            m = re.match(r'^version:?\s+"?([^"\s]+)"?', s)
            if m:
                cur["version"] = m.group(1)
            elif s.rstrip(":") in ("dependencies", "optionalDependencies"):
                section = s.rstrip(":")
        elif indent >= 4 and section:
            if re.match(r'^("[^"]+"|[^\s"]+):\s', s):  # berry: name: "npm:^1"
                k, v = s.split(":", 1) if not s.startswith('"') else (s[:s.index('"', 1) + 1], s[s.index('"', 1) + 2:])
            else:  # yarn 1: name "^1"
                k, _, v = s.rpartition(" ")
            cur["deps"].append((k.strip().strip('"'), v.strip().strip('"')))
    return blocks


def parse_yarn_lock(path: Path) -> Parsed:
    blocks = _yarn_blocks(path.read_text(encoding="utf-8"))
    g = DepGraph()
    by_spec: dict[str, str] = {}
    by_name: dict[str, list[str]] = {}
    out: list[Package] = []
    seen: set[str] = set()
    workspace_roots: list[tuple[str, str]] = []
    for b in blocks:
        if not b["specs"] or b["specs"][0] == "__metadata" or "version" not in b:
            continue
        name = _split_spec(b["specs"][0])
        version = b["version"]
        if any("@workspace:" in s for s in b["specs"]) or "use.local" in version:
            workspace_roots.extend(b["deps"])
            continue
        node = f"{name}@{version}"
        g.add_node(node, node)
        for s in b["specs"]:
            by_spec[s] = node
        by_name.setdefault(name, []).append(node)
        b["node"] = node
        if node not in seen:
            seen.add(node)
            out.append(_pkg("npm", name, version, path, node=node))

    def lookup(dep: str, rng: str) -> str | None:
        for spec in (f"{dep}@{rng}", f"{dep}@npm:{rng}"):
            if spec in by_spec:
                return by_spec[spec]
        cands = by_name.get(dep, [])
        return cands[0] if len(cands) == 1 else None

    for b in blocks:
        if "node" in b:
            for dep, rng in b["deps"]:
                t = lookup(dep, rng)
                if t:
                    g.add_edge(b["node"], t)
    manifest = _read_json(path.parent / "package.json")
    roots = _manifest_deps(manifest) or [(n, r, "prod") for n, r in workspace_roots]
    for dep, rng, kind in roots:
        t = lookup(dep, rng)
        if t:
            g.add_root(t, kind)
    return out, g


def _pnpm_ref_to_id(name: str, ref: str, major: int) -> str | None:
    ref = str(ref)
    if ref.startswith(("link:", "file:", "workspace:")):
        return None
    if ref.startswith("/"):
        return ref[1:]
    if not ref[:1].isdigit():
        return ref  # alias: "string-width@4.2.3"
    return f"{name}/{ref}" if major < 6 else f"{name}@{ref}"


def _pnpm_key_to_nv(key: str, major: int) -> tuple[str, str]:
    key = key.lstrip("/")
    if major < 6 and re.match(r"^(@[^/]+/)?[^@/]+/\d", key):
        name, _, version = key.rpartition("/")
        return name, version.split("_")[0]
    base = re.sub(r"\(.*$", "", key)
    name = _split_spec(base)
    return name, base[len(name) + 1:]


def parse_pnpm_lock(path: Path) -> Parsed:
    d = miniyaml.loads(path.read_text(encoding="utf-8"))
    ver = str(d.get("lockfileVersion", "5")).strip("'\"")
    try:
        major = int(float(ver))
    except ValueError:
        major = 5
    entries = d.get("snapshots") if isinstance(d.get("snapshots"), dict) else d.get("packages") or {}
    meta_entries = d.get("packages") or {}
    g = DepGraph()
    out: list[Package] = []
    seen = set()
    for key, info in entries.items():
        node = key.lstrip("/")
        name, version = _pnpm_key_to_nv(key, major)
        if not name or not version:
            continue
        g.add_node(node, f"{name}@{version}")
        info = info if isinstance(info, dict) else {}
        for field in ("dependencies", "optionalDependencies"):
            for dep, ref in (info.get(field) or {}).items():
                child = _pnpm_ref_to_id(dep, ref, major)
                if child:
                    g.add_edge(node, child)
        if (name, version) not in seen:
            seen.add((name, version))
            dev = bool((meta_entries.get(key) or {}).get("dev") == "true" or info.get("dev") == "true")
            out.append(_pkg("npm", name, version, path, node=node, dev=dev))

    importers = d.get("importers") if isinstance(d.get("importers"), dict) else {".": d}
    for imp in importers.values():
        if not isinstance(imp, dict):
            continue
        for field, kind in (("dependencies", "prod"), ("optionalDependencies", "prod"), ("devDependencies", "dev")):
            for dep, val in (imp.get(field) or {}).items():
                ref = val.get("version", "") if isinstance(val, dict) else val
                child = _pnpm_ref_to_id(dep, ref, major) if ref else None
                if child:
                    g.add_root(child, kind)
    return out, g


# ------------------------------------------------------------- Python family

def _pep508_name(req: str) -> str | None:
    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
    return m.group(1) if m else None


def pyproject_roots(pyproject: dict) -> list[tuple[str, str]]:
    """(normalized name, prod|dev) for the project's direct dependencies."""
    roots: list[tuple[str, str]] = []
    proj = pyproject.get("project") or {}
    for req in proj.get("dependencies") or []:
        if (n := _pep508_name(req)):
            roots.append((n, "prod"))
    for reqs in (proj.get("optional-dependencies") or {}).values():
        roots += [(n, "prod") for r in reqs if (n := _pep508_name(r))]
    for group, reqs in (pyproject.get("dependency-groups") or {}).items():
        roots += [(n, "dev") for r in reqs if isinstance(r, str) and (n := _pep508_name(r))]
    poetry = (pyproject.get("tool") or {}).get("poetry") or {}
    roots += [(n, "prod") for n in (poetry.get("dependencies") or {}) if n.lower() != "python"]
    roots += [(n, "dev") for n in (poetry.get("dev-dependencies") or {})]
    for gname, group in (poetry.get("group") or {}).items():
        kind = "prod" if gname == "main" else "dev"
        roots += [(n, kind) for n in (group.get("dependencies") or {})]
    return [(normalize_name("PyPI", n), k) for n, k in roots]


def _name_graph(path: Path, eco: str, entries: list[tuple[str, str, list[str]]],
                roots: list[tuple[str, str]], dev_names: set[str] = frozenset()) -> Parsed:
    """Graph for lockfiles that reference dependencies by name only."""
    g = DepGraph()
    ids: dict[str, list[str]] = {}
    out = []
    for name, version, _ in entries:
        node = f"{normalize_name(eco, name)}@{version}"
        g.add_node(node, f"{name}@{version}")
        ids.setdefault(normalize_name(eco, name), []).append(node)
        out.append(_pkg(eco, name, version, path, node=node, dev=normalize_name(eco, name) in dev_names))
    for name, version, deps in entries:
        node = f"{normalize_name(eco, name)}@{version}"
        for dep in deps:
            for child in ids.get(normalize_name(eco, dep), []):
                g.add_edge(node, child)
    for name, kind in roots:
        for node in ids.get(normalize_name(eco, name), []):
            g.add_root(node, kind)
    return out, g


def parse_poetry_lock(path: Path) -> Parsed:
    d = _read_toml(path)
    entries, dev = [], set()
    for p in d.get("package") or []:
        if not p.get("name") or not p.get("version"):
            continue
        if (p.get("source") or {}).get("type") in ("directory", "file", "git"):
            continue
        entries.append((p["name"], p["version"], list((p.get("dependencies") or {}).keys())))
        if p.get("category") == "dev":
            dev.add(normalize_name("PyPI", p["name"]))
    roots = pyproject_roots(_read_toml(path.parent / "pyproject.toml"))
    return _name_graph(path, "PyPI", entries, roots, dev)


def parse_uv_lock(path: Path) -> Parsed:
    d = _read_toml(path)
    entries, roots = [], []
    for p in d.get("package") or []:
        src = p.get("source") or {}
        deps = [x.get("name") for x in p.get("dependencies") or [] if isinstance(x, dict)]
        opt = [x.get("name") for reqs in (p.get("optional-dependencies") or {}).values() for x in reqs if isinstance(x, dict)]
        dev = [x.get("name") for reqs in (p.get("dev-dependencies") or {}).values() for x in reqs if isinstance(x, dict)]
        if any(k in src for k in ("editable", "virtual", "directory", "path")):
            roots += [(n, "prod") for n in deps + opt if n] + [(n, "dev") for n in dev if n]
            continue
        if p.get("name") and p.get("version"):
            entries.append((p["name"], p["version"], [n for n in deps + opt if n]))
    return _name_graph(path, "PyPI", entries, roots)


def parse_pipfile_lock(path: Path) -> Parsed:
    d = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for section, dev in (("default", False), ("develop", True)):
        for name, info in (d.get(section) or {}).items():
            v = (info.get("version") or "").lstrip("=")
            if v:
                out.append(_pkg("PyPI", name, v, path, dev=dev))
    return out, None


def parse_requirements(path: Path) -> Parsed:
    out = []
    dev = any(t in path.name.lower() for t in ("dev", "test", "lint"))
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s,\\]+)$", line)
        if m:
            out.append(_pkg("PyPI", m.group(1), m.group(3), path, dev=dev, direct=True))
    return out, None


# ------------------------------------------------------------- other ecosystems

def parse_cargo_lock(path: Path) -> Parsed:
    d = _read_toml(path)
    g = DepGraph()
    out = []
    by_name: dict[str, list[tuple[str, str]]] = {}
    pkgs = d.get("package") or []
    for p in pkgs:
        node = f"{p['name']}@{p['version']}"
        g.add_node(node, node)
        by_name.setdefault(p["name"], []).append((p["version"], node))
        if "registry+" in p.get("source", ""):
            out.append(_pkg("crates.io", p["name"], p["version"], path, node=node))

    def resolve(dep: str) -> list[str]:
        parts = dep.split(" ")
        cands = by_name.get(parts[0], [])
        if len(parts) > 1:
            cands = [c for c in cands if c[0] == parts[1]]
        return [n for _, n in cands]

    for p in pkgs:
        node = f"{p['name']}@{p['version']}"
        local = "source" not in p  # workspace member: its deps are direct deps
        for dep in p.get("dependencies") or []:
            for child in resolve(dep):
                if local:
                    g.add_root(child)
                else:
                    g.add_edge(node, child)
    return out, g


def parse_go_mod(path: Path) -> Parsed:
    requires: list[tuple[str, str, bool]] = []
    replaces: dict[str, tuple[str, str] | None] = {}  # old -> (new, version) or None for local path
    block = None
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.split("//")[0].strip()
        indirect = "// indirect" in line
        for kw in ("require", "replace"):
            if s.startswith(f"{kw} ("):
                block, s = kw, ""
            elif s.startswith(f"{kw} "):
                s = f"{kw}:{s[len(kw) + 1:]}"
        if block and s == ")":
            block = None
            continue
        if not s:
            continue
        kind, body = (s.split(":", 1) if s.startswith(("require:", "replace:")) else (block, s))
        if kind == "require":
            parts = body.split()
            if len(parts) >= 2:
                requires.append((parts[0], parts[1], indirect))
        elif kind == "replace" and "=>" in body:
            old, new = (x.split() for x in body.split("=>", 1))
            if not new:
                continue
            target = None if new[0].startswith((".", "/")) or len(new) < 2 else (new[0], new[1])
            replaces[old[0]] = target
    out = []
    for mod, ver, indirect in requires:
        if mod in replaces:
            if replaces[mod] is None:
                continue  # replaced by a local directory: not a registry module
            mod, ver = replaces[mod]
        out.append(_pkg("Go", mod, ver.lstrip("v"), path, node=f"{mod}@{ver}", direct=not indirect))
    g = _go_mod_graph(path)
    if g is not None:
        # go.mod lists indirect modules too; only the non-indirect ones are the project's choices
        direct = {p.meta["node"] for p in out if p.direct}
        g.roots = {n: k for n, k in g.roots.items() if n in direct}
    return out, g


def _go_mod_graph(path: Path) -> DepGraph | None:
    """`go mod graph` from the local module cache only (no network, no toolchain download)."""
    if not shutil.which("go"):
        return None
    out = run(["go", "-C", str(path.parent), "mod", "graph"], timeout=60,
              env_extra={"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOFLAGS": "-mod=readonly"})
    if not out:
        return None
    g = DepGraph()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        a, b = parts
        g.add_node(b, b)
        if "@" not in a:  # the main module
            g.add_root(b)
        else:
            g.add_node(a, a)
            g.add_edge(a, b)
    return g


def parse_gemfile_lock(path: Path) -> Parsed:
    entries: list[tuple[str, str, list[str]]] = []
    roots: list[tuple[str, str]] = []
    section = None
    in_specs = False
    cur: list[str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(" "):
            section, in_specs, cur = line.strip(), False, None
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        if section == "DEPENDENCIES":
            m = re.match(r"^ {2}([^\s!(]+)", line)
            if m:
                roots.append((m.group(1), "prod"))
            continue
        if not in_specs:
            continue
        m = re.match(r"^ {4}([^\s(]+) \(([^)]+)\)$", line)
        if m:
            version = re.sub(r"-(x86|arm|aarch|universal|java|x64).*$", "", m.group(2))
            cur = []
            if section == "GEM":
                entries.append((m.group(1), version, cur))
            continue
        m = re.match(r"^ {6}([^\s(]+)", line)
        if m and cur is not None:
            cur.append(m.group(1))
    return _name_graph(path, "RubyGems", entries, roots)


def parse_composer_lock(path: Path) -> Parsed:
    d = json.loads(path.read_text(encoding="utf-8"))
    entries, dev = [], set()
    for section, is_dev in (("packages", False), ("packages-dev", True)):
        for p in d.get(section) or []:
            if p.get("name") and p.get("version"):
                deps = [n for n in (p.get("require") or {}) if "/" in n]
                entries.append((p["name"], p["version"].lstrip("v"), deps))
                if is_dev:
                    dev.add(p["name"])
    manifest = _read_json(path.parent / "composer.json")
    roots = [(n, "prod") for n in (manifest.get("require") or {}) if "/" in n]
    roots += [(n, "dev") for n in (manifest.get("require-dev") or {}) if "/" in n]
    return _name_graph(path, "Packagist", entries, roots, dev)


# ---------------------------------------------------------------- Java (Maven / Gradle) and .NET

def _maven_version(v: str) -> str | None:
    """A literal version; ranges ('[1.0,2.0)') and unresolved properties are skipped."""
    v = (v or "").strip()
    if not v or v[0] in "[(" or "${" in v or "," in v:
        return None
    return v


def parse_gradle_lockfile(path: Path) -> Parsed:
    """gradle.lockfile: 'group:artifact:version=conf1,conf2' per resolved module."""
    out: list[Package] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords, _, confs = line.partition("=")
        parts = coords.split(":")
        if len(parts) != 3 or not _maven_version(parts[2]):
            continue
        dev = bool(confs) and all("test" in c.lower() for c in confs.split(","))
        out.append(_pkg("Maven", f"{parts[0]}:{parts[1]}", parts[2], path, dev=dev))
    return out, None


def parse_version_catalog(path: Path) -> Parsed:
    """gradle/libs.versions.toml: the libraries a Gradle build declares directly."""
    d = _read_toml(path)
    versions = d.get("versions") or {}

    def resolve(v) -> str | None:
        if isinstance(v, dict):
            if "ref" in v:
                v = versions.get(v["ref"])
                if isinstance(v, dict):
                    v = v.get("strictly") or v.get("require") or v.get("prefer")
            else:
                v = v.get("strictly") or v.get("require") or v.get("prefer")
        return _maven_version(v) if isinstance(v, str) else None

    out: list[Package] = []
    for entry in (d.get("libraries") or {}).values():
        if isinstance(entry, str):
            parts = entry.split(":")
            name, ver = (":".join(parts[:2]), parts[2]) if len(parts) == 3 else (None, None)
            ver = _maven_version(ver or "")
        elif isinstance(entry, dict):
            name = entry.get("module") or (f"{entry['group']}:{entry['name']}" if entry.get("group") and entry.get("name") else None)
            ver = resolve(entry.get("version"))
        else:
            continue
        if name and ver and name.count(":") == 1:
            out.append(_pkg("Maven", name, ver, path, direct=True))
    for entry in (d.get("plugins") or {}).values():  # Gradle plugins (Android Gradle Plugin, Kotlin…) by artifact
        if isinstance(entry, dict) and plugin_artifact(entry.get("id", "")):
            ver = resolve(entry.get("version"))
            if ver:
                out.append(_pkg("Maven", plugin_artifact(entry["id"]), ver, path, direct=True, dev=True))
    if path.parent.name == "gradle":  # <project>/gradle/libs.versions.toml
        for p in out:
            p.meta["project"] = str(path.parent.parent)
    return out, None


_XML_NS = re.compile(r"^\{[^}]*\}")


def parse_pom(path: Path) -> Parsed:
    """pom.xml: direct dependencies with literal (or property-resolved) versions."""
    import xml.etree.ElementTree as ET
    text = path.read_text(encoding="utf-8", errors="replace")
    if "<!ENTITY" in text:
        raise ValueError("pom.xml declares XML entities: not parsed")
    root = ET.fromstring(text)
    for el in root.iter():
        el.tag = _XML_NS.sub("", el.tag) if isinstance(el.tag, str) else el.tag

    def txt(el, tag: str) -> str:
        child = el.find(tag)
        return (child.text or "").strip() if child is not None else ""

    props_el, parent = root.find("properties"), root.find("parent")
    props = {c.tag: (c.text or "").strip() for c in (list(props_el) if props_el is not None else [])}
    props["project.version"] = txt(root, "version") or (txt(parent, "version") if parent is not None else "")
    if parent is not None:
        props["project.parent.version"] = txt(parent, "version")

    def subst(v: str) -> str:
        for _ in range(5):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
            if new == v:
                break
            v = new
        return v

    out: list[Package] = []
    seen = set()
    sections = [root.find("dependencies"), root.find("dependencyManagement/dependencies")]
    for sec in sections:
        for dep in (sec if sec is not None else []):
            g, a, v = txt(dep, "groupId"), txt(dep, "artifactId"), _maven_version(subst(txt(dep, "version")))
            if not (g and a and v) or txt(dep, "scope") == "import" or (g, a, v) in seen:
                continue
            seen.add((g, a, v))
            out.append(_pkg("Maven", f"{subst(g)}:{a}", v, path, direct=True, dev=txt(dep, "scope") == "test"))
    return out, None


def parse_nuget_lock(path: Path) -> Parsed:
    """NuGet packages.lock.json (all target frameworks)."""
    d = json.loads(path.read_text(encoding="utf-8-sig"))
    out: list[Package] = []
    seen = set()
    for deps in (d.get("dependencies") or {}).values():
        for name, info in (deps or {}).items():
            kind, ver = info.get("type", ""), info.get("resolved")
            if kind == "Project" or not ver or (name.lower(), ver) in seen:
                continue
            seen.add((name.lower(), ver))
            out.append(_pkg("NuGet", name, ver, path, direct=kind == "Direct"))
    return out, None


# ---------------------------------------------------------------- Android build scripts

# Gradle plugin ids -> the Maven artifact that carries their code (and their advisories)
PLUGIN_ARTIFACTS = {
    "com.android.application": "com.android.tools.build:gradle", "com.android.library": "com.android.tools.build:gradle",
    "com.android.test": "com.android.tools.build:gradle", "com.android.dynamic-feature": "com.android.tools.build:gradle",
    "com.google.gms.google-services": "com.google.gms:google-services",
    "com.google.firebase.crashlytics": "com.google.firebase:firebase-crashlytics-gradle",
}
_GRADLE_CONF = (r"(?:implementation|api|compileOnly|runtimeOnly|classpath|kapt|ksp|annotationProcessor|"
                r"coreLibraryDesugaring|lintChecks|\w+Implementation|\w+Api|\w+CompileOnly|\w+RuntimeOnly)")
_GRADLE_DEP = re.compile(_GRADLE_CONF + r"""\s*\(?\s*(?:platform\(\s*)?["']([\w.\-]+):([\w.\-]+):([^"'\s:@]+)["']""")
_GRADLE_PLUGIN = re.compile(r"""\bid\s*\(?\s*["']([\w.\-]+)["']\s*\)?\s+version\s*\(?\s*["']([^"'\s]+)["']""")
_GRADLE_VAR = re.compile(r"""^\s*(?:def|val|var|ext\.|extra\[")?\s*["']?([\w]+)["']?\]?\s*=\s*["']([\w.\-+]+)["']""", re.M)


def plugin_artifact(plugin_id: str) -> str | None:
    if plugin_id in PLUGIN_ARTIFACTS:
        return PLUGIN_ARTIFACTS[plugin_id]
    if plugin_id.startswith("org.jetbrains.kotlin."):
        return "org.jetbrains.kotlin:kotlin-gradle-plugin"
    return None


def _gradle_vars(path: Path) -> dict[str, str]:
    """Version variables from this script, the root build script and gradle.properties above it."""
    out: dict[str, str] = {}
    for d in [path.parent, *path.parents][:4][::-1]:  # outermost first; the module's own values win
        for name in ("gradle.properties", "build.gradle", "build.gradle.kts"):
            f = d / name
            if f.is_file():
                text = f.read_text(encoding="utf-8", errors="replace")
                if name == "gradle.properties":
                    out.update(re.findall(r"^\s*([\w.]+)\s*=\s*([\w.\-+]+)\s*$", text, re.M))
                else:
                    out.update(_GRADLE_VAR.findall(text))
    return out


def parse_gradle_build(path: Path) -> Parsed:
    """Dependencies written directly in build.gradle(.kts) (projects without a lockfile or version catalog)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?m)//.*$", "", text)
    variables = _gradle_vars(path)

    def resolve(v: str) -> str | None:
        m = re.fullmatch(r"\$\{?([\w.]+)\}?", v)
        if m:
            v = variables.get(m.group(1).split(".")[-1], "")
        return _maven_version(v) if v and "+" not in v and "$" not in v else None

    out: list[Package] = []
    seen = set()
    for m in _GRADLE_DEP.finditer(text):
        conf = m.group(0).split("(")[0].split()[0]
        version = resolve(m.group(3))
        name = f"{m.group(1)}:{m.group(2)}"
        if version and (name, version) not in seen:
            seen.add((name, version))
            out.append(_pkg("Maven", name, version, path, direct=True, dev="test" in conf.lower()))
    for plugin_id, ver in _GRADLE_PLUGIN.findall(text):
        art, version = plugin_artifact(plugin_id), resolve(ver)
        if art and version and (art, version) not in seen:
            seen.add((art, version))
            out.append(_pkg("Maven", art, version, path, direct=True, dev=True))  # build tooling
    return out, None


# ---------------------------------------------------------------- Flutter / Dart, iOS (Swift, CocoaPods, Carthage)

def parse_pubspec_lock(path: Path) -> Parsed:
    d = miniyaml.loads(path.read_text(encoding="utf-8"))
    out: list[Package] = []
    for name, info in (d.get("packages") or {}).items():
        if not isinstance(info, dict) or info.get("source") != "hosted" or not info.get("version"):
            continue  # sdk / path / git packages are not on pub.dev
        dep = str(info.get("dependency", ""))
        out.append(_pkg("Pub", name, str(info["version"]), path, direct=dep.startswith("direct"), dev=dep == "direct dev"))
    return out, None


def swift_url(location: str) -> str:
    """Repository URL -> OSV SwiftURL package name: 'https://github.com/apple/swift-nio.git' -> 'github.com/apple/swift-nio'."""
    loc = re.sub(r"^git@([^:]+):", r"\1/", location.strip())
    loc = re.sub(r"^[a-z+]+://", "", loc)
    loc = re.sub(r"^[^@/]+@", "", loc)  # user@host
    return re.sub(r"\.git$", "", loc.rstrip("/"))


def parse_package_resolved(path: Path) -> Parsed:
    """Swift Package Manager Package.resolved (format 1, 2 and 3)."""
    d = json.loads(path.read_text(encoding="utf-8"))
    pins = d.get("pins") or (d.get("object") or {}).get("pins") or []
    out: list[Package] = []
    for p in pins:
        loc, version = p.get("location") or p.get("repositoryURL") or "", (p.get("state") or {}).get("version")
        if loc and version and p.get("kind", "remoteSourceControl") == "remoteSourceControl":
            out.append(_pkg("SwiftURL", swift_url(loc), version, path))
    return out, None


def parse_cartfile_resolved(path: Path) -> Parsed:
    out: list[Package] = []
    for m in re.finditer(r'^(github|git)\s+"([^"]+)"\s+"v?([^"]+)"', path.read_text(encoding="utf-8"), re.M):
        repo = f"github.com/{m.group(2)}" if m.group(1) == "github" else swift_url(m.group(2))
        if re.match(r"\d", m.group(3)):
            out.append(_pkg("SwiftURL", repo, m.group(3), path))
    return out, None


def parse_podfile_lock(path: Path) -> Parsed:
    """CocoaPods: inventory only (no advisory database covers CocoaPods; IOC packs still match names)."""
    text = path.read_text(encoding="utf-8")
    local = set(re.findall(r"^  ([^\s:]+):\n    :path:", text, re.M))  # EXTERNAL SOURCES with a local path
    out: list[Package] = []
    seen = set()
    section = text.split("\nDEPENDENCIES:")[0]
    for name, version in re.findall(r"^  - \"?([^\s\"(]+)\"? \(([^)]+)\)", section, re.M):
        base = name.split("/")[0]  # subspecs (Firebase/Core) belong to the pod
        if base in local or (base, version) in seen:
            continue
        seen.add((base, version))
        out.append(_pkg("CocoaPods", base, version, path))
    return out, None


# ---------------------------------------------------------------- Bun, Deno, Elixir, R, C/C++, .NET projects

def _jsonc(text: str) -> dict:
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", text))  # bun.lock allows trailing commas


def _split_at_version(spec: str) -> tuple[str, str]:
    i = spec.rfind("@")
    return (spec[:i], spec[i + 1:]) if i > 0 else (spec, "")


def parse_bun_lock(path: Path) -> Parsed:
    d = _jsonc(path.read_text(encoding="utf-8"))
    direct = {n for ws in (d.get("workspaces") or {}).values() for f in ("dependencies", "devDependencies",
                                                                           "optionalDependencies") for n in (ws.get(f) or {})}
    out: list[Package] = []
    for entry in (d.get("packages") or {}).values():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        name, version = _split_at_version(entry[0])
        if version and re.match(r"\d", version):
            out.append(_pkg("npm", name, version, path, direct=name in direct))
    return out, None


def parse_deno_lock(path: Path) -> Parsed:
    d = json.loads(path.read_text(encoding="utf-8"))
    npm = d.get("npm") or (d.get("packages") or {}).get("npm") or {}
    out: list[Package] = []
    for key in npm:
        name, version = _split_at_version(key.split("_")[0])
        if version:
            out.append(_pkg("npm", name, version, path))
    return out, None


def parse_mix_lock(path: Path) -> Parsed:
    text = path.read_text(encoding="utf-8")
    return [_pkg("Hex", n, v, path) for n, v in re.findall(r'\{:hex,\s*:"?([\w]+)"?,\s*"([^"]+)"', text)], None


def parse_renv_lock(path: Path) -> Parsed:
    d = json.loads(path.read_text(encoding="utf-8"))
    out = [_pkg("CRAN", p.get("Package", n), p["Version"], path) for n, p in (d.get("Packages") or {}).items()
           if p.get("Version") and p.get("Source") == "Repository" and p.get("Repository", "CRAN") in ("CRAN", "RSPM", "PPM")]
    return out, None


def parse_conan_lock(path: Path) -> Parsed:
    d = json.loads(path.read_text(encoding="utf-8"))
    refs = [*(d.get("requires") or []), *(d.get("build_requires") or []), *(d.get("python_requires") or [])]
    refs += [n.get("ref", "") for n in ((d.get("graph_lock") or {}).get("nodes") or {}).values()]  # lockfile v1
    out: list[Package] = []
    for ref in refs:
        m = re.match(r"([\w.+\-]+)/([\w.+\-]+)", ref or "")
        if m and not any(p.name == m.group(1) and p.version == m.group(2) for p in out):
            out.append(_pkg("ConanCenter", m.group(1), m.group(2), path))
    return out, None


def parse_msbuild(path: Path) -> Parsed:
    """PackageReference in .csproj/.fsproj/.vbproj, PackageVersion in Directory.Packages.props."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    out: list[Package] = []
    for tag in re.finditer(r"<Package(?:Reference|Version)\b([^>]*?)(/>|>(.*?)</Package(?:Reference|Version)>)", text, re.S):
        attrs, body = tag.group(1), tag.group(3) or ""
        name = re.search(r'\bInclude="([^"]+)"', attrs)
        ver = re.search(r'\bVersion="([^"]+)"', attrs) or re.search(r"<Version>([^<]+)</Version>", body)
        version = ver.group(1).strip("[] ") if ver else ""
        if name and version and re.fullmatch(r"[\d][\w.\-]*", version):
            out.append(_pkg("NuGet", name.group(1), version, path, direct=True))
    return out, None


# ---------------------------------------------------------------- GitHub Actions used by workflows

_USES = re.compile(r"""^\s*-?\s*uses:\s*['"]?([\w.\-]+/[\w.\-]+)(?:/[^@\s'"]*)?@([^\s'"#]+)['"]?(?:\s*#\s*(\S+))?""", re.M)


def parse_workflow(path: Path) -> Parsed:
    """Actions and their versions: a tag (v4.2.1), or the version in the comment of a SHA pin (@<sha> # v4.2.1)."""
    out: list[Package] = []
    seen = set()
    for repo, ref, comment in _USES.findall(path.read_text(encoding="utf-8", errors="replace")):
        label = comment if re.fullmatch(r"[0-9a-f]{40}", ref) else ref
        m = re.fullmatch(r"v?(\d+(?:\.\d+)*)", label or "")
        if m and (repo.lower(), m.group(1)) not in seen:
            seen.add((repo.lower(), m.group(1)))
            p = _pkg("GitHub Actions", repo, m.group(1), path, direct=True)
            p.meta.update(lockfile="workflow", project=str(path.parents[2]), workflow=path.name, ref=ref)
            out.append(p)
    return out, None


PARSERS: dict[str, Callable[[Path], Parsed]] = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_uv_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom,
    "gradle.lockfile": parse_gradle_lockfile,
    "libs.versions.toml": parse_version_catalog,
    "packages.lock.json": parse_nuget_lock,
    "build.gradle": parse_gradle_build,
    "build.gradle.kts": parse_gradle_build,
    "pubspec.lock": parse_pubspec_lock,
    "Package.resolved": parse_package_resolved,
    "Cartfile.resolved": parse_cartfile_resolved,
    "Podfile.lock": parse_podfile_lock,
    "bun.lock": parse_bun_lock,
    "deno.lock": parse_deno_lock,
    "mix.lock": parse_mix_lock,
    "renv.lock": parse_renv_lock,
    "conan.lock": parse_conan_lock,
    "Directory.Packages.props": parse_msbuild,
}
_REQ = re.compile(r"^requirements[\w.-]*\.txt$")
BUILD_FILES = {"gradle-wrapper.jar", "gradle-wrapper.properties", "maven-wrapper.jar", "maven-wrapper.properties",
               "gradlew", "mvnw", ".gitlab-ci.yml"}


def parser_for(name: str, parent: Path | None = None) -> Callable[[Path], Parsed] | None:
    if name in PARSERS:
        return PARSERS[name]
    if _REQ.match(name):
        return parse_requirements
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return parse_msbuild
    if parent is not None and parent.name == "workflows" and parent.parent.name == ".github" \
            and name.endswith((".yml", ".yaml")):
        return parse_workflow
    return None


def discover(ctx: Context) -> None:
    """Walk the roots once, recording lockfiles, virtualenvs and git repos."""
    cfg = ctx.config
    exclude = set(cfg.exclude_dirs)
    for root in cfg.expanded_roots():
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if "pyvenv.cfg" in filenames:
                ctx.venvs.append(Path(dirpath))
                dirnames[:] = []
                continue
            if ".git" in dirnames:
                ctx.repos.append(Path(dirpath))
            if len(Path(dirpath).parts) - base_depth >= cfg.max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for f in filenames:
                path = Path(dirpath) / f
                if parser_for(f, path.parent):
                    ctx.lockfiles.append(path)
                if f in BUILD_FILES or (dirpath.endswith(os.path.join(".github", "workflows")) and f.endswith((".yml", ".yaml"))):
                    ctx.build_files.append(path)


def _collect(ctx: Context) -> list[Package]:
    discover(ctx)
    out: list[Package] = []
    for lf in ctx.lockfiles:
        try:
            if lf.stat().st_size > MAX_LOCKFILE_BYTES:
                ctx.errors.append(f"skipped oversized lockfile {lf}")
                continue
            pkgs, graph = parser_for(lf.name, lf.parent)(lf)  # type: ignore[misc]
        except Exception as e:
            ctx.errors.append(f"{lf}: {e!r}")
            debug(f"failed to parse {lf}: {e!r}")
            continue
        if graph is not None:
            finalize(graph, pkgs, str(lf))
            ctx.graphs[str(lf)] = graph
        out.extend(pkgs)
    return out


COLLECTOR = Collector("lockfile", "Project lockfiles under --root folders", False,
                      lambda ctx: bool(ctx.config.roots), _collect)
