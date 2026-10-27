"""Write hash-locked build requirements for the desktop app: packaging/locks/build-<platform>.txt.

Resolves packaging/requirements-build.txt for a target platform from PyPI's metadata (no package
code is downloaded or run), picks for every dependency the newest release that is at least
--min-age days old, and records the SHA-256 of every file of that release. The build scripts then
install with `pip --require-hashes --no-deps`, so a build can only ever use these exact files.

    python3 packaging/lock_build_deps.py              # both platforms, 7-day cooldown
    python3 packaging/lock_build_deps.py --platform windows --min-age 14

Packages published only as source (no wheel) go to build-<platform>-sdist.txt; they are installed
in a second step, without build isolation, so their build backend is the hash-locked setuptools.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pip._vendor.packaging.markers import default_environment
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name
from pip._vendor.packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parent
PLATFORMS = {
    # marker environment of the Python each build script uses (python.org 3.13)
    "macos": {"sys_platform": "darwin", "platform_system": "Darwin", "os_name": "posix", "platform_machine": "arm64"},
    "windows": {"sys_platform": "win32", "platform_system": "Windows", "os_name": "nt", "platform_machine": "AMD64"},
}
PYTHON = "3.13"


CTX = ssl.create_default_context()
if not CTX.cert_store_stats().get("x509_ca"):  # python.org builds ship without CA certificates: use the OS's
    for cafile in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
        if os.path.isfile(cafile):
            CTX.load_verify_locations(cafile=cafile)
            break


def pypi(name: str, version: str = "") -> dict:
    url = f"https://pypi.org/pypi/{name}/{version + '/' if version else ''}json"
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "scs-lock"}), timeout=60,
                                context=CTX) as r:
        return json.load(r)


def choose(name: str, spec, cutoff: datetime, wheel_tags: tuple[str, ...]) -> tuple[str, list[dict], bool]:
    doc = pypi(name)
    ok = []
    for v, files in doc["releases"].items():
        try:
            ver = Version(v)
        except InvalidVersion:
            continue
        files = [f for f in files if not f.get("yanked")]
        if ver.is_prerelease or not files or not spec.contains(ver):
            continue
        first = min(datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files)
        if first > cutoff:
            continue  # too new: the cooldown
        usable = [f for f in files if f["packagetype"] == "sdist" or any(t in f["filename"] for t in wheel_tags)]
        if usable:
            ok.append((ver, v, files))
    if not ok:
        raise SystemExit(f"no release of {name} matches {spec or 'any'} and is older than {cutoff:%Y-%m-%d}")
    _, v, files = max(ok)
    return v, files, any(f["packagetype"] == "bdist_wheel" and any(t in f["filename"] for t in wheel_tags)
                         for f in files)


def resolve(platform: str, min_age: int) -> dict[str, tuple[str, list[dict], bool]]:
    env = {**default_environment(), **PLATFORMS[platform], "python_version": PYTHON, "python_full_version": PYTHON + ".0",
           "implementation_name": "cpython", "platform_python_implementation": "CPython"}
    tags = ("-none-any.whl", "cp313", "abi3", "py3-none", "py2.py3") + (
        ("macosx",) if platform == "macos" else ("win_amd64",))
    cutoff = datetime.now(timezone.utc) - timedelta(days=min_age)
    todo = [Requirement(line.split("#")[0].strip()) for line in _requirements(ROOT / "requirements-build.txt")]
    specs: dict[str, object] = {}
    chosen: dict[str, tuple[str, list[dict], bool]] = {}
    while todo:
        req = todo.pop(0)
        if req.marker and not req.marker.evaluate(env):
            continue
        name = canonicalize_name(req.name)
        specs[name] = (specs[name] & req.specifier) if name in specs else req.specifier
        if name in chosen and specs[name].contains(chosen[name][0]):
            continue
        v, files, wheel = choose(name, specs[name], cutoff, tags)
        chosen[name] = (v, files, wheel)
        for dep in pypi(name, v)["info"].get("requires_dist") or []:
            r = Requirement(dep)
            if r.marker and not r.marker.evaluate({**env, "extra": ""}):
                continue
            todo.append(r)
    return chosen


def _requirements(path: Path) -> list[str]:
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if line.startswith("-r "):
            out += _requirements((path.parent / line[3:].strip()).resolve())
        elif line:
            out.append(line)
    return out


def write(platform: str, chosen: dict, min_age: int) -> None:
    out = ROOT / "locks"
    out.mkdir(exist_ok=True)
    head = (f"# Generated by packaging/lock_build_deps.py for {platform} (Python {PYTHON}); do not edit.\n"
            f"# Every release was public for at least {min_age} days when locked. Regenerate to update.\n")
    wheels, sdists = [], []
    for name, (v, files, wheel) in sorted(chosen.items()):
        hashes = sorted({f["digests"]["sha256"] for f in files})
        entry = f"{name}=={v} \\\n" + " \\\n".join(f"    --hash=sha256:{h}" for h in hashes) + "\n"
        (wheels if wheel else sdists).append(entry)
    (out / f"build-{platform}.txt").write_text(head + "".join(wheels))
    (out / f"build-{platform}-sdist.txt").write_text(head + "# source-only packages, installed after the wheels\n"
                                                     + "".join(sdists))
    print(f"{platform}: {len(wheels)} wheel package(s), {len(sdists)} source-only: "
          + ", ".join(f"{n}=={v}" for n, (v, _, _) in sorted(chosen.items())))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--platform", choices=sorted(PLATFORMS), action="append")
    ap.add_argument("--min-age", type=int, default=7, metavar="DAYS")
    args = ap.parse_args()
    for platform in args.platform or sorted(PLATFORMS):
        write(platform, resolve(platform, args.min_age), args.min_age)
    return 0


if __name__ == "__main__":
    sys.exit(main())
