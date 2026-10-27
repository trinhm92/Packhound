"""Ignore policy (shared, reviewable JSON) and triage decisions (local state).

Policy files, merged in order:
  ~/.config/scs/policy.json      personal rules
  ./scs-policy.json              rules committed with a project / team
Each rule ignores an advisory, optionally narrowed to a package, version or
path glob, and should carry a reason and an expiry date:
  {"advisory": "GHSA-xxxx", "package": "npm:qs", "version": "6.5.2",
   "path": "~/RnD/legacy/*", "reason": "not reachable", "expires": "2027-01-31"}
Rules never hide malicious-package findings unless they set "force": true.

Decisions (~/.local/share/scs/decisions.json) record what triage chose per
finding: patch | verify | defer (with "until") | respond.
"""
from __future__ import annotations

import fnmatch
import getpass
import os
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional

from scs.models import Advisory, Package, normalize_name
from scs.util import data_dir, read_json, write_json

USER_POLICY = Path("~/.config/scs/policy.json").expanduser()
PROJECT_POLICY = Path("scs-policy.json")
ACTIONS = ("respond", "patch", "verify", "defer")


def today() -> str:
    return date.today().isoformat()


def parse_expiry(text: str) -> str:
    """'90d', '12w', '6m' or 'YYYY-MM-DD' -> ISO date."""
    text = text.strip()
    if not text:
        return ""
    units = {"d": 1, "w": 7, "m": 30, "y": 365}
    if text[-1:] in units and text[:-1].isdigit():
        return (date.today() + timedelta(days=int(text[:-1]) * units[text[-1]])).isoformat()
    return datetime.strptime(text, "%Y-%m-%d").date().isoformat()


class Policy:
    def __init__(self, paths: Optional[list[Path]] = None):
        self.paths = paths if paths is not None else [USER_POLICY, PROJECT_POLICY]
        self.rules: list[dict] = []
        for p in self.paths:
            if p.is_file():
                for r in (read_json(p).get("ignore") or []):
                    r["_file"] = str(p)
                    self.rules.append(r)

    def active(self) -> list[dict]:
        return [r for r in self.rules if not self.expired(r)]

    @staticmethod
    def expired(rule: dict) -> bool:
        return bool(rule.get("expires")) and rule["expires"] < today()

    @staticmethod
    def _matches(rule: dict, adv: Advisory, pkgs: list[Package]) -> bool:
        if adv.malicious and not rule.get("force"):
            return False
        ids = {adv.id, *adv.aliases}
        if rule.get("advisory", "*") != "*" and rule["advisory"] not in ids:
            return False
        first = pkgs[0]
        if rule.get("package"):
            eco, _, name = rule["package"].partition(":")
            if eco != first.ecosystem or normalize_name(eco, name) != normalize_name(first.ecosystem, first.name):
                return False
        if rule.get("version") and rule["version"] != first.version:
            return False
        if rule.get("path"):
            pattern = os.path.expanduser(rule["path"])
            # conservative: only ignore when every install location is covered
            if not all(fnmatch.fnmatch(p.location, pattern) or fnmatch.fnmatch(p.meta.get("project", ""), pattern)
                       for p in pkgs):
                return False
        return True

    def filter(self, advs: list[Advisory], pkgs: list[Package]) -> tuple[list[Advisory], list[dict]]:
        """Split advisories into (kept, ignored-with-rule)."""
        kept, ignored = [], []
        active = self.active()
        for a in advs:
            rule = next((r for r in active if self._matches(r, a, pkgs)), None)
            if rule:
                ignored.append({"advisory": a.id, "reason": rule.get("reason", ""), "expires": rule.get("expires", ""),
                                "file": rule.get("_file", "")})
            else:
                kept.append(a)
        return kept, ignored

    @staticmethod
    def add(rule: dict, path: Path = USER_POLICY) -> dict:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = read_json(path) if path.is_file() else {}
        rule = {k: v for k, v in rule.items() if v not in (None, "")}
        rule.setdefault("added", today())
        try:
            rule.setdefault("by", getpass.getuser())
        except Exception:
            pass
        data.setdefault("ignore", []).append(rule)
        write_json(path, data)
        return rule

    @staticmethod
    def prune(path: Path = USER_POLICY) -> int:
        if not path.is_file():
            return 0
        data = read_json(path)
        before = len(data.get("ignore") or [])
        data["ignore"] = [r for r in data.get("ignore") or [] if not Policy.expired(r)]
        write_json(path, data)
        return before - len(data["ignore"])


class Decisions:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or data_dir() / "decisions.json"
        self.data: dict = read_json(self.path) if self.path.is_file() else {}

    def get(self, key: str, advisory_ids: set[str]) -> Optional[dict]:
        d = self.data.get(key)
        if not d:
            return None
        d = dict(d)
        if d["action"] == "defer" and d.get("until", "") < today():
            return None  # deferral ran out: triage again
        d["stale"] = bool(advisory_ids - set(d.get("advisories", [])))
        return d

    def set(self, key: str, action: str, advisory_ids: list[str], until: str = "", note: str = "") -> None:
        assert action in ACTIONS
        self.data[key] = {"action": action, "advisories": sorted(advisory_ids), "decided": today(),
                          **({"until": until} if until else {}), **({"note": note} if note else {})}

    def drop(self, key: str) -> None:
        self.data.pop(key, None)

    def save(self) -> None:
        write_json(self.path, self.data)
