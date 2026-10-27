"""Release-age cooldown: don't install a package version that was published only days ago.

Most malicious releases (hijacked maintainer accounts, worms such as Shai-Hulud) are spotted and
pulled from PyPI/npm within a day or two. Fixes therefore install the newest version that is at
least `fix_min_age_days` old (default 7; 2 for a vulnerability that is being exploited in the wild),
and the package managers are told the same cutoff so new *dependencies* are held back too:
pip ≥ 26 `--uploaded-prior-to`, npm `--before`. After a pip change, `scs fixer age-check` rejects
anything that still came in too new, and the executor rolls the change back.
Homebrew, APT, winget and Chocolatey packages are reviewed by their maintainers before they ship,
so they are not held back.
"""
from __future__ import annotations

import re
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from scs.util import cache_dir, debug, http_json, read_json, write_json
from scs.versions import vkey

DEFAULT_DAYS = 7
EXPLOITED_DAYS = 2  # cap for a vulnerability on CISA's exploited list: waiting a week is the bigger risk
TTL = 6 * 3600
STABLE = re.compile(r"\d+(\.\d+)*")


def days_for(findings: list[dict], configured: int) -> int:
    """The wait for a change fixing these findings: shorter when one of them is being exploited."""
    if configured <= 0:
        return 0
    kev = any(a.get("kev") for f in findings for a in f.get("advisories", []))
    return min(configured, EXPLOITED_DAYS) if kev else configured


def cutoff(days: int, now: Optional[datetime] = None) -> datetime:
    return (now or datetime.now(timezone.utc)) - timedelta(days=days)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _cached(kind: str, name: str, fetch: Callable[[], dict[str, str]]) -> Optional[dict[str, datetime]]:
    path = cache_dir() / f"release-times-{kind}.json"
    cache: dict = read_json(path) if path.exists() else {}
    hit = cache.get(name)
    if not hit or time.time() - hit["t"] > TTL:
        try:
            hit = {"t": time.time(), "times": fetch()}
        except Exception as e:
            debug(f"release dates of {kind}:{name}: {e}")
            return None
        cache[name] = hit
        write_json(path, cache)
    return {v: _parse(ts) for v, ts in hit["times"].items()}


def pypi_times(name: str) -> Optional[dict[str, datetime]]:
    """{version: first upload time} for every release that still has a non-yanked file."""
    def fetch() -> dict[str, str]:
        doc = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", retries=2)
        out = {}
        for v, files in (doc.get("releases") or {}).items():
            live = [f["upload_time_iso_8601"] for f in files if not f.get("yanked") and f.get("upload_time_iso_8601")]
            if live:
                out[v] = min(live)
        return out
    return _cached("pypi", name.lower(), fetch)


def npm_times(name: str) -> Optional[dict[str, str]]:
    """{version: publish time} from the full npm packument (the abbreviated one has no dates)."""
    def fetch() -> dict[str, str]:
        doc = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}", retries=2, timeout=120)
        versions = set(doc.get("versions") or {})  # unpublished versions keep a time entry but no metadata
        return {v: ts for v, ts in (doc.get("time") or {}).items() if v in versions}
    return _cached("npm", name, fetch)


def times_for(ecosystem: str, name: str) -> Optional[dict[str, datetime]]:
    if ecosystem == "PyPI":
        return pypi_times(name)
    if ecosystem == "npm":
        return npm_times(name)
    return None


def old_enough(times: Optional[dict[str, datetime]], version: str, days: int,
               now: Optional[datetime] = None) -> bool:
    """True when the version was published at least `days` ago (or its date is unknown)."""
    if days <= 0 or not times or version not in times:
        return True
    return times[version] <= cutoff(days, now)


def pick(ecosystem: str, name: str, fix: str, days: int, ok: Callable[[str], bool] = lambda v: True,
         now: Optional[datetime] = None) -> dict:
    """Newest stable version >= fix that is old enough.

    {"version": v} when one exists; {"version": None, "wait_until": date, "released": date} when every
    fixed release is too new; {"version": fix, "unknown": True} when the dates can't be read (the
    package manager's own cutoff and the post-install age check still apply).
    """
    if days <= 0:
        return {"version": fix}
    times = times_for(ecosystem, name)
    if not times:
        return {"version": fix, "unknown": True}
    eco = "PyPI" if ecosystem == "PyPI" else "npm"
    fixed = [v for v in times if STABLE.fullmatch(v) and vkey(v, eco) >= vkey(fix, eco) and ok(v)]
    if not fixed:
        return {"version": fix, "unknown": True}
    ready = [v for v in fixed if times[v] <= cutoff(days, now)]
    if ready:
        return {"version": max(ready, key=lambda v: vkey(v, eco))}
    first = min(times[v] for v in fixed)
    return {"version": None, "released": first.date().isoformat(),
            "wait_until": (first + timedelta(days=days)).date().isoformat()}


def held_note(name: str, fix: str, p: dict, days: int) -> str:
    return (f"{name} {fix} was published on {p['released']}, less than {days} days ago. scs installs a new release "
            f"only after it has been public for {days} days, so a hijacked release can be caught first. It will be "
            f"installed from {p['wait_until']}. To install it now, set “Wait before installing new releases” to 0 in "
            f"Settings (or `scs plan --min-age 0`).")


def npm_before(days: int, now: Optional[datetime] = None) -> str:
    """Value for npm's --before (all npm versions support it)."""
    return cutoff(days, now).strftime("%Y-%m-%dT%H:%M:%SZ")


def too_new(changed: dict[str, str], days: int, now: Optional[datetime] = None) -> tuple[list[str], list[str]]:
    """For pip packages {name: version} that just changed: (too new, dates unreadable)."""
    bad, unknown = [], []
    for name, version in sorted(changed.items()):
        times = pypi_times(name)
        if times is None:
            unknown.append(f"{name} {version}")
        elif version in times and times[version] > cutoff(days, now):
            bad.append(f"{name} {version} (published {times[version].date().isoformat()})")
    return bad, unknown
