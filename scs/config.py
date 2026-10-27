"""Configuration: defaults < ~/.config/scs/config.json < ./scs.json < CLI flags.

JSON rather than TOML so the core runs on Python 3.10 without third-party parsers.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from scs.util import debug, read_json

DEFAULT_EXCLUDE_DIRS = [
    "node_modules", ".git", ".hg", ".svn", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".next", ".nuxt", ".gradle", ".idea", ".cache", ".Trash", "Library",
    "target", "dist", "build", ".terraform", "Pods", "DerivedData",
]


@dataclass
class Config:
    roots: list[str] = field(default_factory=list)
    max_depth: int = 7
    exclude_dirs: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))
    collectors: list[str] = field(default_factory=list)  # empty = all available
    system: bool = True          # scan global/system installs (brew, interpreters, globals)
    offline: bool = False
    nvd: bool = False
    nvd_api_key: str = ""
    ioc_dirs: list[str] = field(default_factory=list)
    verbose: bool = False
    # Phase 7. Secrets are referenced as "env:NAME" so they never sit in the config file.
    reputation: dict = field(default_factory=dict)  # {"malwarebazaar_key": "env:ABUSECH_AUTH_KEY", "virustotal_key": "env:VT_API_KEY", "virustotal_limit": 20}
    notify: dict = field(default_factory=dict)      # {"desktop": true, "slack_webhook": "env:...", "webhook": "...", "teams_webhook": "...", "email": {...}}
    alert_min_severity: str = "high"
    # fixes skip releases younger than this (supply-chain cooldown, see scs/cooldown.py); 0 turns it off
    fix_min_age_days: int = 7

    def expanded_roots(self) -> list[Path]:
        out = []
        for r in self.roots:
            p = Path(os.path.expanduser(r)).resolve()
            if p.is_dir():
                out.append(p)
        return out


def load_config() -> Config:
    cfg = Config()
    for path in (Path("~/.config/scs/config.json").expanduser(), Path("scs.json")):
        if path.is_file():
            debug(f"loading config {path}")
            data = read_json(path)
            for k, v in data.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
    cfg.nvd_api_key = cfg.nvd_api_key or os.environ.get("NVD_API_KEY", "")
    return cfg


def secret(value) -> str:
    """Resolve "env:NAME" references (the recommended way to configure keys and webhooks)."""
    if isinstance(value, str) and value.startswith("env:"):
        return os.environ.get(value[4:], "")
    return value or ""
