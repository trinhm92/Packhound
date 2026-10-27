"""NVD CPE matching for Homebrew formulae and OS-bundled developer tools (low confidence).

OSV has no Homebrew ecosystem, so formulae are matched to CPE product names. git, curl and
OpenSSH are always looked up; every other formula only with --nvd.
Name mapping is heuristic and results are flagged confidence="low".
"""
from __future__ import annotations

import re
import time
import urllib.parse

from scs.cvss import severity_from_score
from scs.models import Advisory, Package
from scs.util import cache_dir, debug, http_json, log, read_json, write_json
from scs.versions import vkey

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString={}&resultsPerPage=500"
TTL = 7 * 24 * 3600

# brew formula -> (cpe vendor or "*", cpe product)
PRODUCT_MAP = {
    "node": ("nodejs", "node.js"), "go": ("golang", "go"), "python": ("python", "python"),
    "openssh": ("openbsd", "openssh"), "gnupg": ("gnupg", "gnupg"), "xz": ("tukaani", "xz"),
    "ruby": ("ruby-lang", "ruby"), "openjdk": ("oracle", "openjdk"), "git": ("git-scm", "git"),
    "curl": ("haxx", "curl"), "libcurl": ("haxx", "libcurl"), "vim": ("vim", "vim"),
    "sqlite": ("sqlite", "sqlite"), "openssl": ("openssl", "openssl"), "libssh2": ("libssh2", "libssh2"),
    "postgresql": ("postgresql", "postgresql"), "redis": ("redis", "redis"), "nginx": ("f5", "nginx"),
    "imagemagick": ("imagemagick", "imagemagick"), "ffmpeg": ("ffmpeg", "ffmpeg"),
    "libxml2": ("xmlsoft", "libxml2"), "expat": ("libexpat_project", "libexpat"),
    "zlib": ("zlib", "zlib"), "libpng": ("libpng", "libpng"), "jq": ("jqlang", "jq"),
    "wget": ("gnu", "wget"), "bash": ("gnu", "bash"), "php": ("php", "php"),
}


# products looked up even without --nvd: tools every developer runs on untrusted input (repos, URLs, hosts)
DEFAULT_PRODUCTS = {"git", "curl", "openssh"}


def cpe_for(formula: str) -> tuple[str, str]:
    base = re.sub(r"@[\d.]+$", "", formula)
    return PRODUCT_MAP.get(base, ("*", base))


def _in_range(version: str, m: dict) -> bool:
    v = vkey(version)
    parts = m["criteria"].split(":")
    crit_ver = parts[5]
    if crit_ver not in ("*", "-") and len(parts) > 6 and parts[6] not in ("*", "-", ""):
        crit_ver += parts[6]  # OpenSSH style: version 9.8, update p1
    bounds = [k for k in ("versionStartIncluding", "versionStartExcluding",
                          "versionEndIncluding", "versionEndExcluding") if k in m]
    if crit_ver not in ("*", "-"):
        return vkey(crit_ver) == v
    if not bounds:
        return False  # "all versions" criteria are too noisy to trust
    if "versionStartIncluding" in m and v < vkey(m["versionStartIncluding"]):
        return False
    if "versionStartExcluding" in m and v <= vkey(m["versionStartExcluding"]):
        return False
    if "versionEndIncluding" in m and v > vkey(m["versionEndIncluding"]):
        return False
    if "versionEndExcluding" in m and v >= vkey(m["versionEndExcluding"]):
        return False
    return True


def _match(cve: dict, product: str, version: str) -> tuple[bool, list[str]]:
    """Re-check NVD's match ourselves; skip platform-conditional (AND) configs."""
    matched, fixes = False, []
    for conf in cve.get("configurations", []):
        if conf.get("operator") == "AND":
            continue
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) < 6 or parts[4] != product or not m.get("vulnerable"):
                    continue
                if _in_range(version, m):
                    matched = True
                    if "versionEndExcluding" in m:
                        fixes.append(m["versionEndExcluding"])
    return matched, fixes


def _to_advisory(cve: dict, fixes: list[str]) -> Advisory:
    metrics = cve.get("metrics", {})
    score, sev = None, "UNKNOWN"
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if metrics.get(k):
            data = metrics[k][0]["cvssData"]
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or metrics[k][0].get("baseSeverity") or severity_from_score(score)
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return Advisory(
        id=cve["id"], summary=desc[:240], severity=sev.upper(), cvss=score, fixed=sorted(set(fixes)),
        source="nvd", confidence="low", published=cve.get("published", ""),
        references=[f"https://nvd.nist.gov/vuln/detail/{cve['id']}"],
    )


def lookup(pkgs: list[Package], api_key: str = "", offline: bool = False) -> dict:
    path = cache_dir() / "nvd.json"
    cache: dict = read_json(path) if path.exists() else {}
    delay = 0.7 if api_key else 6.5
    headers = {"apiKey": api_key} if api_key else {}
    out: dict = {}
    todo = [p for p in pkgs if not (offline or time.time() - cache.get(f"{p.name}|{p.version}", {}).get("t", 0) < TTL)]
    if todo and not offline:
        eta = int(len(todo) * delay)
        log(f"NVD: {len(todo)} tools to query (~{eta}s{'' if api_key else '; set NVD_API_KEY to go ~10x faster'})")
    for i, p in enumerate(pkgs):
        ck = f"{p.name}|{p.version}"
        if p in todo and not offline:
            vendor, product = p.meta.get("cpe") or cpe_for(p.name)
            ver = re.sub(r"^(\d+(?:\.\d+)*)(p\d+)$", r"\1:\2", p.version)  # 9.8p1 -> 9.8:p1 (CPE update field)
            match = f"cpe:2.3:a:{vendor}:{product}:{ver}"
            try:
                resp = http_json(URL.format(urllib.parse.quote(match, safe=":*")), headers=headers, timeout=90)
                cache[ck] = {"t": time.time(), "product": product, "vulns": [v["cve"] for v in resp.get("vulnerabilities", [])]}
            except Exception as e:
                debug(f"NVD {p.name}: {e}")
            time.sleep(delay)
            if i % 20 == 0:
                write_json(path, cache)
        entry = cache.get(ck)
        if not entry:
            continue
        advs = []
        for cve in entry["vulns"]:
            if cve.get("vulnStatus") == "Rejected":
                continue
            ok, fixes = _match(cve, entry["product"], p.version)
            if ok:
                advs.append(_to_advisory(cve, fixes))
        if advs:
            out[p.key] = advs
    write_json(path, cache)
    return out
