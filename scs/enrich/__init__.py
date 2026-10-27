"""Enrichment: attach advisories (OSV, NVD, IOC packs) and exploit signals (KEV, EPSS)."""
from __future__ import annotations

from scs.config import Config
from scs.enrich import epss, ioc, kev, nvd, osv, runtimes
from scs.models import Advisory, Package, osv_supported
from scs.util import log

Key = tuple[str, str, str]


def enrich(packages: list[Package], cfg: Config, ctx_repos: list) -> tuple[dict[Key, list[Advisory]], list[dict], dict]:
    """Return advisories per package key, IOC file hits, and source status notes."""
    notes: dict[str, str] = {}
    by_key: dict[Key, Package] = {}
    for p in packages:
        by_key.setdefault(p.key, p)

    advisories: dict[Key, list[Advisory]] = {}

    osv_keys = [k for k in by_key if osv_supported(k[0])]
    try:
        found = osv.lookup(osv_keys, offline=cfg.offline)
        for k, advs in found.items():
            advisories.setdefault(k, []).extend(advs)
        notes["osv"] = f"{len(osv_keys)} packages queried, {sum(len(v) for v in found.values())} advisories"
        if osv.LAST_RUN["failed"]:
            notes["osv"] = (f"INCOMPLETE: {osv.LAST_RUN['failed']} of {osv.LAST_RUN['total']} advisories could not be "
                            f"downloaded ({osv.LAST_RUN['first_error'][:200]})")
    except Exception as e:
        notes["osv"] = f"FAILED: {e}"
        log(f"OSV lookup failed: {e}")

    # NVD by CPE: always for git, curl and OpenSSH (a few queries, cached a week), for every Homebrew
    # formula / Windows program with --nvd
    def nvd_wanted(k: Key, p: Package) -> bool:
        if p.source == "devtool":
            return True
        if k[0] == "Homebrew" or (k[0] == "Windows-app" and p.meta.get("cpe")):
            return cfg.nvd or (p.meta.get("cpe") or nvd.cpe_for(p.name))[1] in nvd.DEFAULT_PRODUCTS
        return False
    nvd_pkgs = [p for k, p in by_key.items() if nvd_wanted(k, p)]
    try:
        for k, advs in nvd.lookup(nvd_pkgs, cfg.nvd_api_key, offline=cfg.offline).items():
            advisories.setdefault(k, []).extend(advs)
        what = "Homebrew formulae / Windows programs and OS developer tools" if cfg.nvd else "git, curl and OpenSSH copies"
        notes["nvd"] = f"{len(nvd_pkgs)} {what} matched by CPE (low confidence)" + \
            ("" if cfg.nvd else "; use --nvd for every Homebrew formula")
    except Exception as e:
        notes["nvd"] = f"FAILED: {e}"
        log(f"NVD lookup failed: {e}")

    try:
        found, notes["runtimes"] = runtimes.lookup(list(by_key.values()), offline=cfg.offline)
        for k, advs in found.items():
            advisories.setdefault(k, []).extend(advs)
    except Exception as e:
        notes["runtimes"] = f"FAILED: {e}"
        log(f"runtime release data failed: {e}")

    packs = ioc.load_packs(cfg.ioc_dirs)
    for k, advs in ioc.match_packages(packs, list(by_key.values())).items():
        advisories.setdefault(k, []).extend(advs)
    file_hits = ioc.match_files(packs, ctx_repos)
    notes["ioc"] = f"{len(packs)} IOC packs, {len(file_hits)} file hits"

    cves = sorted({c for advs in advisories.values() for a in advs for c in a.cves})
    try:
        kev_db = kev.load(offline=cfg.offline)
        for advs in advisories.values():
            for a in advs:
                for c in a.cves:
                    if c in kev_db:
                        a.kev = True
                        a.kev_ransomware = a.kev_ransomware or kev_db[c]
        notes["kev"] = f"{len(kev_db)} known-exploited CVEs loaded"
    except Exception as e:
        notes["kev"] = f"FAILED: {e}"
    try:
        scores = epss.scores(cves, offline=cfg.offline)
        for advs in advisories.values():
            for a in advs:
                vals = [scores[c] for c in a.cves if c in scores]
                a.epss = max(vals) if vals else None
        notes["epss"] = f"{len(scores)}/{len(cves)} CVEs scored"
    except Exception as e:
        notes["epss"] = f"FAILED: {e}"
    return advisories, file_hits, notes
