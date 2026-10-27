"""Exact, offline snapshots taken right before a target is patched.

Rollback must not depend on the network or on registries still serving old
versions, so each target kind snapshots what is actually on disk:
  project     manifests + lockfiles (copied); node_modules and .venv (cloned)
  pip         the environment's site-packages and bin directories (cloned)
  npm-global  the top-level tool directories being changed + bin links (cloned)
  cargo       ~/.cargo install metadata + the installed binaries (copied)
  py-migrate  the old environment itself (moved into the backup folder by the fixer)
  brew        nothing reliable: reported as not restorable
On APFS (macOS) clones are copy-on-write (`cp -c`), so even large trees are
cheap; on Linux `cp --reflink=auto` is used, falling back to a real copy.
Restore never deletes the failed state: it is moved into the backup folder.
"""
from __future__ import annotations

import glob
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

MANIFESTS = ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
             ".yarnrc.yml", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock", "Cargo.toml",
             "Cargo.lock", "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock"]
CLONE_DIRS = ["node_modules", ".venv", "venv"]


class SnapshotError(Exception):
    pass


def clone_tree(src: Path, dst: Path) -> str:
    """Copy-on-write clone where the filesystem supports it. Returns the method used."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    if platform.system() == "Darwin":
        if subprocess.run(["cp", "-cRp", str(src), str(dst)], capture_output=True).returncode == 0:
            return "clone"
        shutil.rmtree(dst, ignore_errors=True)
    elif subprocess.run(["cp", "-a", "--reflink=auto", str(src), str(dst)], capture_output=True).returncode == 0:
        return "reflink-or-copy"
    shutil.copytree(src, dst, symlinks=True)
    return "copy"


def _mv(src: Path, dst: Path) -> None:
    """Move, falling back to `sudo -n mv` for root-owned locations (sudo was unlocked for the change)."""
    try:
        shutil.move(str(src), str(dst))
    except PermissionError:
        if os.name == "nt":
            raise
        r = subprocess.run(["sudo", "-n", "mv", str(src), str(dst)], capture_output=True, text=True)
        if r.returncode != 0:
            raise SnapshotError(f"cannot move {src} back (permission denied, sudo not available): {r.stderr.strip()}")


def _put_back(saved: Path, live: Path, graveyard: Path) -> None:
    """Move the failed live copy aside (kept for inspection) and the saved copy into place."""
    if live.exists() or live.is_symlink():
        graveyard.parent.mkdir(parents=True, exist_ok=True)
        _mv(live, graveyard)
    live.parent.mkdir(parents=True, exist_ok=True)
    _mv(saved, live)


def _requirements_files(d: Path) -> list[str]:
    return [os.path.basename(p) for p in glob.glob(str(d / "requirements*.txt"))]


def take(target: dict, backup: Path) -> dict:
    kind = target["kind"]
    backup.mkdir(parents=True, exist_ok=True)
    if kind == "project":
        d = Path(target["id"])
        names = MANIFESTS + _requirements_files(d)
        present = [n for n in names if (d / n).is_file()]
        for n in present:
            (backup / "files").mkdir(exist_ok=True)
            shutil.copy2(d / n, backup / "files" / n)
        cloned = {}
        for sub in CLONE_DIRS:
            if (d / sub).is_dir() and not (d / sub).is_symlink():
                cloned[sub] = clone_tree(d / sub, backup / "trees" / sub)
        return {"kind": kind, "restorable": True, "files": present, "absent": [n for n in names if n not in present],
                "trees": cloned}
    if kind == "pip":
        site = Path(target["meta"]["site"])
        env_bin = site.parent.parent.parent / "bin" if site.parent.parent.name == "lib" else None
        trees = {"site": clone_tree(site, backup / "trees" / "site")}
        if env_bin and env_bin.is_dir():
            trees["bin"] = clone_tree(env_bin, backup / "trees" / "bin")
        return {"kind": kind, "restorable": True, "site": str(site), "bin": str(env_bin) if env_bin else None,
                "trees": trees}
    if kind == "npm-global":
        root = Path(target["id"])
        tools = sorted({p.get("top") or p["name"] for p in target["packages"]})
        saved = {}
        for t in tools:
            if (root / t).is_dir():
                saved[t] = clone_tree(root / t, backup / "tools" / t.replace("/", "__"))
        bin_dir = root.parent.parent / "bin"
        links = {}
        if bin_dir.is_dir():
            for e in os.scandir(bin_dir):
                if e.is_symlink():
                    links[e.name] = os.readlink(e.path)
        (backup / "bin-links.json").write_text(json.dumps(links))
        return {"kind": kind, "restorable": True, "root": str(root), "tools": list(saved), "missing_tools":
                [t for t in tools if t not in saved], "bin": str(bin_dir)}
    if kind == "cargo":
        home = Path(os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo"))
        files = [home / ".crates2.json", home / ".crates.toml"]
        files += [home / "bin" / b for b in os.listdir(home / "bin")] if (home / "bin").is_dir() else []
        (backup / "cargo").mkdir(exist_ok=True)
        saved = []
        for f in files:
            if f.is_file():
                shutil.copy2(f, backup / "cargo" / f.name)
                saved.append(str(f))
        return {"kind": kind, "restorable": True, "files": saved}
    if kind == "apt":
        from scs.collectors import dpkg
        wanted = {b["name"] for p in target["packages"] for b in (p.get("binaries") or [])}
        versions = {}
        for e in dpkg.parse_status(dpkg.DPKG_STATUS.read_text(errors="replace")):
            if e["Package"] in wanted:
                versions[e["Package"]] = e["Version"]
        (backup / "apt-versions.json").write_text(json.dumps(versions, indent=1))
        return {"kind": kind, "restorable": True, "best_effort": True, "versions": versions}
    if kind == "py-migrate":
        # the fixer moves the old environment into $BACKUP/retired; rollback moves it back
        return {"kind": kind, "restorable": True, "via": "plan-rollback", "env": target["meta"].get("env")}
    if kind in ("winget", "choco", "scoop", "snap"):
        # these managers keep (scoop, snap) or can reinstall (winget, choco) the previous version:
        # rollback runs the plan's own rollback commands
        return {"kind": kind, "restorable": True, "best_effort": kind in ("winget", "choco"), "via": "plan-rollback",
                "versions": {p["name"]: p["from"] for p in target["packages"]}}
    return {"kind": kind, "restorable": False,
            "reason": f"{kind} cannot reliably downgrade; versions were recorded only"}


def restore(target: dict, state: dict, backup: Path) -> list[str]:
    """Put the snapshot back. Returns human-readable notes."""
    if not state.get("restorable"):
        raise SnapshotError(state.get("reason", "not restorable"))
    kind = state["kind"]
    notes = []
    graveyard = backup / "failed-state"
    if kind == "project":
        d = Path(target["id"])
        for n in state["files"]:
            if (d / n).exists():
                graveyard.mkdir(parents=True, exist_ok=True)
                shutil.copy2(d / n, graveyard / n)
            shutil.copy2(backup / "files" / n, d / n)
        for n in state["absent"]:
            if (d / n).is_file():  # created by the failed change
                graveyard.mkdir(parents=True, exist_ok=True)
                shutil.move(str(d / n), str(graveyard / n))
        for sub in state["trees"]:
            _put_back(backup / "trees" / sub, d / sub, graveyard / sub)
        notes.append(f"restored {len(state['files'])} manifest/lock files and {', '.join(state['trees']) or 'no'} trees")
    elif kind == "pip":
        _put_back(backup / "trees" / "site", Path(state["site"]), graveyard / "site")
        if state.get("bin") and "bin" in state["trees"]:
            _put_back(backup / "trees" / "bin", Path(state["bin"]), graveyard / "bin")
        notes.append("restored site-packages and bin")
    elif kind == "npm-global":
        root = Path(state["root"])
        for t in state["tools"]:
            _put_back(backup / "tools" / t.replace("/", "__"), root / t, graveyard / "tools" / t.replace("/", "__"))
        links = json.loads((backup / "bin-links.json").read_text())
        bin_dir = Path(state["bin"])
        for name, dest in links.items():
            p = bin_dir / name
            if os.path.lexists(p) and (not p.is_symlink() or os.readlink(p) != dest):
                graveyard.mkdir(parents=True, exist_ok=True)
                shutil.move(str(p), str(graveyard / f"bin-{name}"))
            if not os.path.lexists(p):
                os.symlink(dest, p)
        notes.append(f"restored {', '.join(state['tools'])}")
        if state.get("missing_tools"):
            notes.append(f"newly installed (not removed): {', '.join(state['missing_tools'])}")
    elif kind == "cargo":
        for f in state["files"]:
            shutil.copy2(backup / "cargo" / Path(f).name, f)
        notes.append(f"restored {len(state['files'])} cargo files")
    elif kind == "apt":
        pins = [f"{n}={v}" for n, v in sorted(state["versions"].items())]
        r = subprocess.run(["sudo", "-n", "apt-get", "install", "-y", "--allow-downgrades", *pins],
                           capture_output=True, text=True, env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
                           timeout=1800)
        (backup / "apt-rollback.log").write_text(r.stdout + r.stderr)
        if r.returncode != 0:
            raise SnapshotError("apt downgrade failed (old versions no longer available?): "
                                + (r.stderr.strip().splitlines() or ["see apt-rollback.log"])[-1])
        notes.append(f"downgraded {len(pins)} package(s) to their recorded versions")
    return notes
