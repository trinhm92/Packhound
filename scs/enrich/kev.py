"""CISA Known Exploited Vulnerabilities catalog."""
from __future__ import annotations

from scs.util import cache_dir, cache_fresh, http_json, read_json, write_json

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TTL = 24 * 3600


def load(offline: bool = False) -> dict[str, bool]:
    """Return {CVE id: used_in_ransomware}."""
    path = cache_dir() / "kev.json"
    if not (path.exists() and (offline or cache_fresh(path, TTL))):
        if offline:
            return {}
        write_json(path, http_json(URL, timeout=90))
    data = read_json(path)
    return {v["cveID"]: v.get("knownRansomwareCampaignUse", "").lower() == "known"
            for v in data.get("vulnerabilities", [])}
