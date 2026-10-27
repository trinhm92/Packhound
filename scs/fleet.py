"""Multi-host: export a machine's latest results as a bundle, merge bundles into a fleet view.

Bundles are plain JSON so they can be collected any way you like (ssh, a shared
folder, CI artefacts). Home-directory paths are rewritten to "~" so usernames
do not travel; secrets never appear in the first place (scs never reads values).
"""
from __future__ import annotations

import os
import platform
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from scs import __version__, history
from scs.models import SEVERITY_ORDER, finding_key
from scs.osinfo import os_release
from scs.util import data_dir, host_id, normalize_host, read_json

BUNDLE_VERSION = 1
MALWARE_LATEST = "malware-latest.json"
SEV_MALWARE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _redact(obj: Any, home: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(home, "~") if home and home in obj else obj
    if isinstance(obj, list):
        return [_redact(x, home) for x in obj]
    if isinstance(obj, dict):  # keys too: e.g. "projects" is keyed by project path
        return {_redact(k, home): _redact(v, home) for k, v in obj.items()}
    return obj


def export(include_malware: bool = True) -> dict:
    host = host_id()
    scan = history.load(host=host) or history.load()
    if not scan:
        raise FileNotFoundError("no scan recorded on this machine: run `scs scan` first")
    scan = {k: v for k, v in scan.items() if k != "packages"}  # inventory stays local
    malware = None
    p = data_dir() / MALWARE_LATEST
    if include_malware and p.is_file():
        malware = read_json(p)
        malware.pop("inventory", None)
    rel = os_release()
    bundle = {
        "bundle_version": BUNDLE_VERSION, "scs_version": __version__, "host": host,
        "exported": datetime.now().astimezone().isoformat(timespec="seconds"),
        "os": rel.get("PRETTY_NAME") or f"{platform.system()} {platform.release()}",
        "platform": f"{platform.system()} {platform.machine()}",
        "scan": scan, "malware": malware,
    }
    return _redact(bundle, os.path.expanduser("~"))


def _age_days(ts: str) -> int | None:
    try:
        return (datetime.now().astimezone() - datetime.fromisoformat(ts)).days
    except (TypeError, ValueError):
        return None


def merge(bundles: list[dict]) -> dict:
    hosts = []
    vulns: dict[str, dict] = {}
    cves: dict[str, dict] = defaultdict(lambda: {"hosts": set(), "severity": "UNKNOWN", "kev": False, "packages": set()})
    respond: list[dict] = []
    malware_items: dict[tuple, dict] = {}
    seen_hosts = set()
    for b in sorted(bundles, key=lambda x: x.get("exported", ""), reverse=True):
        name = normalize_host(b["host"])
        if name in seen_hosts:
            continue  # newest bundle per host wins
        seen_hosts.add(name)
        scan, mw = b.get("scan") or {}, b.get("malware") or {}
        hosts.append({
            "host": name, "os": b.get("os", ""), "exported": b.get("exported", ""),
            "scanned": scan.get("started", ""), "scan_age_days": _age_days(scan.get("started", "")),
            "buckets": (scan.get("summary") or {}).get("buckets", {}),
            "severity": (scan.get("summary") or {}).get("severity", {}),
            "packages": (scan.get("inventory") or {}).get("total", 0),
            "outdated": len(scan.get("outdated") or []),
            "malware": mw.get("counts") if mw else None,
            "malware_scanned": mw.get("started", "") if mw else "",
            "exposure": len(mw.get("exposure") or []) if mw else None,
            "unencrypted_ssh_keys": sum(1 for e in (mw.get("exposure") or []) if e.get("state") == "UNENCRYPTED"),
        })
        for f in scan.get("findings", []):
            if f["ecosystem"] == "file" or f["bucket"] == "respond":
                respond.append({"host": name, "name": f["name"], "version": f["version"], "ecosystem": f["ecosystem"],
                                "advisories": [a["id"] for a in f["advisories"]][:5]})
                if f["ecosystem"] == "file":
                    continue
            # distro packages: same package/version on different releases are different findings
            key = finding_key(f)
            v = vulns.setdefault(key, {"ecosystem": f["ecosystem"], "name": f["name"], "version": f["version"],
                                       "severity": "UNKNOWN", "score": 0, "fix_version": f.get("fix_version"),
                                       "kev": False, "advisories": set(), "hosts": {}, "buckets": set()})
            v["hosts"][name] = f["bucket"]
            v["buckets"].add(f["bucket"])
            v["score"] = max(v["score"], f["score"])
            if SEVERITY_ORDER.get(f["severity"], 0) > SEVERITY_ORDER.get(v["severity"], 0):
                v["severity"] = f["severity"]
            for a in f["advisories"]:
                v["advisories"].add(a["id"])
                v["kev"] = v["kev"] or a.get("kev", False)
                for c in a.get("cves", []):
                    entry = cves[c]
                    entry["hosts"].add(name)
                    entry["packages"].add(f"{f['ecosystem']}:{f['name']}")
                    entry["kev"] = entry["kev"] or a.get("kev", False)
                    if SEVERITY_ORDER.get(a["severity"], 0) > SEVERITY_ORDER.get(entry["severity"], 0):
                        entry["severity"] = a["severity"]
        for m in mw.get("findings", []) if mw else []:
            if SEV_MALWARE.get(m["severity"], 0) < 2:
                continue
            k = (m["check"], tuple(sorted(m.get("rules", []))), re.sub(r"\s+", " ", m["title"]))
            item = malware_items.setdefault(k, {"check": m["check"], "severity": m["severity"], "title": m["title"],
                                                "rules": m.get("rules", []), "hosts": []})
            item["hosts"].append({"host": name, "path": m.get("path", "")})
            if SEV_MALWARE[m["severity"]] > SEV_MALWARE[item["severity"]]:
                item["severity"] = m["severity"]
    vuln_list = sorted(({**v, "advisories": sorted(v["advisories"])[:12], "buckets": sorted(v["buckets"]),
                         "host_count": len(v["hosts"])} for v in vulns.values()),
                       key=lambda v: (-(v["host_count"] * v["score"]), v["name"]))
    cve_list = sorted(({"cve": c, "hosts": sorted(e["hosts"]), "host_count": len(e["hosts"]), "severity": e["severity"],
                        "kev": e["kev"], "packages": sorted(e["packages"])[:6]} for c, e in cves.items()),
                      key=lambda e: (-e["kev"], -e["host_count"], -SEVERITY_ORDER.get(e["severity"], 0), e["cve"]))
    mal_list = sorted(malware_items.values(), key=lambda m: (-SEV_MALWARE[m["severity"]], -len(m["hosts"]), m["title"]))
    shared_ioc = [r for r in respond if sum(1 for x in respond if x["name"] == r["name"]) > 1]
    return {
        "created": datetime.now().astimezone().isoformat(timespec="seconds"), "scs_version": __version__,
        "hosts": sorted(hosts, key=lambda h: h["host"]), "vulnerabilities": vuln_list, "cves": cve_list,
        "respond": respond, "shared_ioc_hosts": sorted({r["host"] for r in shared_ioc}), "malware": mal_list,
        "totals": {"hosts": len(hosts), "unique_vulnerable_packages": len(vuln_list), "cves": len(cve_list),
                   "respond": len(respond), "malware_items": len(mal_list)},
    }
