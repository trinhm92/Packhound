"""Core data model shared by collectors, enrichment, analysis and reports."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Optional

# OSV ecosystem names for the ecosystems OSV can answer for.
OSV_ECOSYSTEMS = {"PyPI", "npm", "crates.io", "Go", "RubyGems", "Packagist", "Maven", "NuGet", "Pub", "SwiftURL", "Hex",
                  "CRAN", "ConanCenter", "GitHub Actions", "Hackage", "Julia", "opam"}
# OSV can't compare versions of these server-side: query every advisory of the package, match ranges here
CLIENT_SIDE_RANGES = {"GitHub Actions"}


def osv_supported(ecosystem: str) -> bool:
    """Language ecosystems plus release-qualified distro ecosystems ('Ubuntu:24.04:LTS', 'Debian:12')."""
    return ecosystem in OSV_ECOSYSTEMS or ecosystem.startswith(("Ubuntu:", "Debian:"))

PURL_TYPES = {
    "PyPI": "pypi", "npm": "npm", "crates.io": "cargo", "Go": "golang", "RubyGems": "gem",
    "Packagist": "composer", "Maven": "maven", "NuGet": "nuget", "Homebrew": "brew",
    "Homebrew-cask": "brew-cask", "Snap": "snap", "Flatpak": "flatpak", "Pub": "pub", "SwiftURL": "swift", "Hex": "hex",
    "CRAN": "cran", "ConanCenter": "conan", "CocoaPods": "cocoapods", "GitHub Actions": "github", "Hackage": "hackage",
    "Julia": "julia", "opam": "opam",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def normalize_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("Homebrew", "Homebrew-cask", "crates.io", "RubyGems", "GitHub Actions") \
            or ecosystem.startswith(("Ubuntu:", "Debian:")):
        return name.lower()
    return name


def finding_key(f: dict) -> str:
    """Finding.key computed from a serialized finding."""
    name = f["name"] if f["ecosystem"] == "file" else normalize_name(f["ecosystem"], f["name"])
    return f"{f['ecosystem']}|{name}|{f['version']}"


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    source: str            # collector id: brew, pip, npm-global, cargo, lockfile
    location: str          # file or directory where it was found
    scope: str = "global"  # global | project
    direct: Optional[bool] = None
    dev: bool = False
    chain: list[str] = field(default_factory=list)  # parents, outermost first
    meta: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, normalize_name(self.ecosystem, self.name), self.version)

    @property
    def purl(self) -> str:
        if self.ecosystem.startswith(("Ubuntu:", "Debian:")):
            distro = self.ecosystem.split(":")[0].lower()
            return f"pkg:deb/{distro}/{self.name}@{self.version}?arch=source"
        t = PURL_TYPES.get(self.ecosystem, self.ecosystem.lower())
        return f"pkg:{t}/{self.name}@{self.version}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Advisory:
    id: str
    summary: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    cvss: Optional[float] = None
    fixed: list[str] = field(default_factory=list)  # fixed versions applicable to this package
    malicious: bool = False
    source: str = "osv"        # osv | nvd | ioc
    confidence: str = "exact"  # exact | low
    references: list[str] = field(default_factory=list)
    published: str = ""
    kev: bool = False
    kev_ransomware: bool = False
    epss: Optional[float] = None

    @property
    def cves(self) -> list[str]:
        ids = [self.id] + self.aliases
        return sorted({i for i in ids if i.startswith("CVE-")})

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cves"] = self.cves
        return d


@dataclass
class Finding:
    ecosystem: str
    name: str
    version: str
    packages: list[Package]
    advisories: list[Advisory]
    score: int = 0
    severity: str = "UNKNOWN"
    bucket: str = "monitor"   # respond | patch | verify | monitor
    fix_version: Optional[str] = None
    reasons: list[str] = field(default_factory=list)
    advice: str = ""
    commands: list[str] = field(default_factory=list)
    new: bool = False
    toolchain: Optional[dict] = None   # runtime the fix needs vs. what each location uses
    decision: Optional[dict] = None    # triage decision, if any
    ignored: list[dict] = field(default_factory=list)  # advisories suppressed by policy

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{normalize_name(self.ecosystem, self.name)}|{self.version}"

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem, "name": self.name, "version": self.version,
            "score": self.score, "severity": self.severity, "bucket": self.bucket,
            "fix_version": self.fix_version, "reasons": self.reasons, "advice": self.advice,
            "commands": self.commands, "new": self.new, "toolchain": self.toolchain,
            "decision": self.decision, "ignored": self.ignored,
            "packages": [p.to_dict() for p in self.packages],
            "advisories": [a.to_dict() for a in self.advisories],
        }
