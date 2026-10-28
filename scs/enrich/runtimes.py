"""Security-update status of language runtimes and build tools (JDK, Node.js, Python, Go, PHP, Ruby, .NET…).

No advisory database lists CVEs by runtime build, so this reports two facts
from the vendors' release data instead of CVE ids:
  * the release line is past end of life: it gets no more security fixes
  * a newer update of the same line exists. Every OpenJDK update release is
    a quarterly security (CPU) release and CPython patch releases carry the
    security fixes; for Node.js only releases nodejs.org marks as security
    releases count.
Go's standard library also gets real CVEs from OSV (package "stdlib").
Sources: endoflife.date (release lines, EOL dates, latest updates) and
nodejs.org/dist/index.json (security flag per release); both cached a day.
"""
from __future__ import annotations

import re
import time
from datetime import date

from scs.models import Advisory, Package
from scs.util import cache_dir, debug, http_json, read_json, write_json
from scs.versions import vkey

TTL = 24 * 3600
# runtimes whose patch releases are how security fixes ship, so "behind the latest patch" is a security finding.
# For build tools and fast-moving runtimes (Gradle, Maven, Bazel, Deno, Bun, GHC, Julia, Rust) a newer release
# is mostly features: only an end-of-life release line is reported.
PATCH_IS_SECURITY = {"java", "python", "php", "ruby", "dotnet", "erlang", "elixir", "perl"}
EOL_URL = "https://endoflife.date/api/{}.json"
NODE_INDEX = "https://nodejs.org/dist/index.json"


def _cached(name: str, url: str, offline: bool):
    path = cache_dir() / f"{name}.json"
    entry = read_json(path) if path.exists() else {}
    if entry and (offline or time.time() - entry.get("t", 0) < TTL):
        return entry.get("data")
    if offline:
        return None
    try:
        data = http_json(url, timeout=30)
    except Exception as e:
        debug(f"{url}: {e}")
        return entry.get("data")  # stale beats nothing
    write_json(path, {"t": time.time(), "data": data})
    return data


def norm(version: str, runtime: str) -> str:
    """Comparable version from a release-data string: '17.0.21+9' / '17.0.21.0.10' -> '17.0.21', '8u462-b08' -> '8.0.462'."""
    v = str(version).strip().lstrip("v")
    if runtime == "java":
        m = re.match(r"(?:1\.)?8u(\d+)", v)
        if m:
            return f"8.0.{m.group(1)}"
        nums = re.findall(r"\d+", v.split("+")[0])
        if nums and nums[0] == "8" and len(nums) >= 2 and nums[1] != "0":  # Corretto 8: 8.<update>.<build>.<n>
            return f"8.0.{nums[1]}"
        return ".".join((nums + ["0", "0"])[:3])
    return v


def _supported(c: dict, today: str) -> bool:
    eol = c.get("eol")
    return eol is False or (isinstance(eol, str) and eol > today)


def _upgrade_line(cycles: list[dict], current: str, runtime: str, today: str) -> dict | None:
    """The nearest newer release line that is still supported (LTS lines for Java and Node.js)."""
    ok = [c for c in cycles if _supported(c, today) and vkey(str(c["cycle"])) > vkey(current)
          and (runtime not in ("java", "node") or c.get("lts"))]
    return min(ok, key=lambda c: vkey(str(c["cycle"])), default=None)


def _latest(c: dict, runtime: str) -> str:
    return norm(c.get("latestJdkVersion") or c.get("latest") or "", runtime)


def _line_for(cycles: list[dict], cycle: str, version: str) -> dict | None:
    """The release line of a version: the longest cycle name that prefixes it ('8.0.32' -> '8', '3.12.1' -> '3.12')."""
    names = {str(c.get("cycle")): c for c in cycles}
    if cycle in names:
        return names[cycle]
    parts = version.split(".")
    for n in range(len(parts), 0, -1):
        if ".".join(parts[:n]) in names:
            return names[".".join(parts[:n])]
    return None


def advisories_for(p: Package, cycles: list[dict], node_index: list | None = None, today: str | None = None) -> list[Advisory]:
    today = today or date.today().isoformat()
    rt, product, cycle = p.meta["runtime"], p.meta["product"], str(p.meta["cycle"])
    from scs.collectors.runtimes import LABELS
    label = {"java": "Java"}.get(rt) or LABELS.get(rt, rt)
    line = _line_for(cycles, cycle, p.version)
    if line is None:
        return []
    cycle = str(line["cycle"])
    refs = [f"https://endoflife.date/{product}"]
    out: list[Advisory] = []
    if not _supported(line, today):
        up = _upgrade_line(cycles, cycle, rt, today)
        fix = [_latest(up, rt)] if up else []
        out.append(Advisory(
            id=f"EOL-{product}-{cycle}", severity="HIGH", source="eol", fixed=fix, references=refs,
            summary=f"{label} {cycle} reached end of life on {line.get('eol')}: it no longer gets security fixes."
                    + (f" Move to {label} {up['cycle']} (latest {fix[0]})." if up else "")))
        return out
    latest = _latest(line, rt)
    if not latest or vkey(latest) <= vkey(p.version):
        return out
    if rt == "node":
        missed = [r["version"] for r in (node_index or []) if r.get("security")
                  and str(r["version"]).lstrip("v").split(".")[0] == cycle
                  and vkey(str(r["version"]).lstrip("v")) > vkey(p.version)]
        if node_index is not None and not missed:
            return out  # newer releases exist, but none of them fixes a vulnerability
        out.append(Advisory(
            id=f"UPDATE-nodejs-{latest}", severity="HIGH", source="eol", fixed=[latest],
            references=["https://nodejs.org/en/blog/vulnerability", *refs],
            summary=f"Node.js {p.version} misses security release(s) {', '.join(sorted(missed, key=vkey)[:4]) or 'of this line'}"
                    f"; the latest {cycle}.x is {latest}."))
    elif rt in PATCH_IS_SECURITY:  # Go: OSV lists the actual stdlib CVEs; build tools: only end of life matters
        what = "quarterly security update (Critical Patch Update)" if rt == "java" else "security and bug-fix release"
        out.append(Advisory(
            id=f"UPDATE-{product}-{latest}", severity="MEDIUM", source="eol", fixed=[latest], references=refs,
            summary=f"{label} {p.version} is behind {latest}, the latest {what} of {label} {cycle}."))
    return out


def lookup(pkgs: list[Package], offline: bool = False) -> tuple[dict, str]:
    """(advisories per package key, status note)."""
    rts = [p for p in pkgs if p.source == "runtime"]
    products = sorted({p.meta["product"] for p in rts})
    cycles = {prod: _cached(f"eol-{prod}", EOL_URL.format(prod), offline) for prod in products}
    node_index = _cached("node-dist-index", NODE_INDEX, offline) if any(p.meta["runtime"] == "node" for p in rts) else None
    out: dict = {}
    missing = [prod for prod, c in cycles.items() if not isinstance(c, list)]
    for p in rts:
        data = cycles.get(p.meta["product"])
        if not isinstance(data, list):
            continue
        advs = advisories_for(p, data, node_index if isinstance(node_index, list) else None)
        if advs:
            out.setdefault(p.key, [])
            out[p.key] += [a for a in advs if a.id not in {x.id for x in out[p.key]}]
    note = f"{len(rts)} runtimes checked against endoflife.date / nodejs.org"
    if missing:
        note = f"INCOMPLETE: no release data for {', '.join(missing)}; " + note
    return out, note
