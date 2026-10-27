"""Loose, ecosystem-agnostic version comparison.

Good enough to order fixed versions and detect major bumps; it is not a full
PEP 440 / semver implementation. Pre-release tags sort before the release.
"""
from __future__ import annotations

import re
from functools import total_ordering

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")
_PRE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "pre": -1, "rc": -1, "c": -1}


@total_ordering
class LooseVersion:
    def __init__(self, s: str):
        self.raw = s
        s = s.strip().lstrip("vV")
        s = s.split("+", 1)[0]  # drop build metadata
        parts: list[tuple[int, int]] = []
        for tok in _TOKEN.findall(s):
            if tok.isdigit():
                parts.append((0, int(tok)))
            elif tok.lower() in ("post", "patch", "r", "p"):
                continue  # post-release: treat the following number as one more component
            else:
                parts.append((-1, _PRE.get(tok.lower(), -5)))
        while parts and parts[-1] == (0, 0):
            parts.pop()
        self.parts = parts

    def _cmp_key(self, n: int) -> list[tuple[int, int]]:
        # Pad with a value that sorts after pre-release markers but equal to ".0".
        return self.parts + [(0, 0)] * (n - len(self.parts))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LooseVersion):
            return NotImplemented
        n = max(len(self.parts), len(other.parts))
        return self._cmp_key(n) == other._cmp_key(n)

    def __lt__(self, other: "LooseVersion") -> bool:
        n = max(len(self.parts), len(other.parts))
        return self._cmp_key(n) < other._cmp_key(n)

    def __repr__(self) -> str:
        return f"LooseVersion({self.raw!r})"


def _deb_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if not c:
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg's verrevcmp: alternating non-digit / digit runs; '~' sorts before everything."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < len(a) else 0
            bc = _deb_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _deb_split(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, rev = v.rpartition("-") if "-" in v else (v, "", "0")
    return epoch, upstream, rev


def deb_compare(a: str, b: str) -> int:
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


@total_ordering
class DebVersion:
    def __init__(self, s: str):
        self.raw = s

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DebVersion) and deb_compare(self.raw, other.raw) == 0

    def __lt__(self, other: "DebVersion") -> bool:
        return deb_compare(self.raw, other.raw) < 0

    def __repr__(self) -> str:
        return f"DebVersion({self.raw!r})"


def _is_deb(ecosystem: str) -> bool:
    return ecosystem.startswith(("Ubuntu:", "Debian:"))


def vkey(s: str, ecosystem: str = ""):
    return DebVersion(s) if _is_deb(ecosystem) else LooseVersion(s)


def major(s: str) -> int | None:
    s = re.sub(r"^\d+:", "", s.strip())  # Debian epoch
    m = re.match(r"\s*[vV]?(\d+)", s)
    return int(m.group(1)) if m else None


def is_major_bump(current: str, target: str, ecosystem: str = "") -> bool:
    a, b = major(current), major(target)
    if a is None or b is None:
        return False
    if a >= 1990:
        return False  # calendar versioning (certifi 2024.x, pip-tools-style dates)
    if a == 0 and b == 0 and ecosystem != "Go":  # Go x/ modules ship compatible 0.x minors
        # 0.x: semver treats minor as breaking
        ma = re.match(r"\s*[vV]?0\.(\d+)", current)
        mb = re.match(r"\s*[vV]?0\.(\d+)", target)
        return bool(ma and mb and ma.group(1) != mb.group(1))
    return b > a


def lowest_fix_above(current: str, fixes: list[str], ecosystem: str = "") -> str | None:
    cur = vkey(current, ecosystem)
    above = sorted((f for f in fixes if vkey(f, ecosystem) > cur), key=lambda f: vkey(f, ecosystem))
    return above[0] if above else None
