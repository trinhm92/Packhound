"""OSV.dev: CVE/GHSA/PYSEC/RUSTSEC advisories and MAL-* malicious-package reports."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from scs.cvss import cvss3_base_score, severity_from_score
from scs.models import CLIENT_SIDE_RANGES, Advisory, normalize_name
from scs.util import HttpError, cache_dir, debug, http_json, log, read_json, write_json
from scs.versions import vkey

QUERY_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
QUERY_TTL = 12 * 3600
BATCH = 1000

Key = tuple[str, str, str]


def _qkey(k: Key) -> str:
    return "|".join(k)


def _query(keys: list[Key], offline: bool) -> dict[Key, list[tuple[str, str]]]:
    cache_path = cache_dir() / "osv-query.json"
    cache: dict = read_json(cache_path) if cache_path.exists() else {}
    now = time.time()
    result: dict[Key, list[tuple[str, str]]] = {}
    todo: list[Key] = []
    for k in keys:
        c = cache.get(_qkey(k))
        if c and (offline or now - c["t"] < QUERY_TTL):
            result[k] = [tuple(x) for x in c["ids"]]
        else:
            todo.append(k)
    if offline:
        if todo:
            log(f"offline: {len(todo)} packages have no cached OSV result")
        return result
    for i in range(0, len(todo), BATCH):
        chunk = todo[i:i + BATCH]
        log(f"OSV: querying {i + len(chunk)}/{len(todo)} packages")
        payload = {"queries": [{"package": {"ecosystem": e, "name": n}, **({} if e in CLIENT_SIDE_RANGES else {"version": v})}
                               for e, n, v in chunk]}
        resp = http_json(QUERY_URL, payload, timeout=120)
        for k, r in zip(chunk, resp.get("results", [])):
            ids = [(v["id"], v.get("modified", "")) for v in r.get("vulns", []) or []]
            token = r.get("next_page_token")
            while token:
                e, n, v = k
                more = http_json(QUERY_URL, {"queries": [{"package": {"ecosystem": e, "name": n}, "page_token": token,
                                                          **({} if e in CLIENT_SIDE_RANGES else {"version": v})}]})
                r2 = more["results"][0]
                ids += [(x["id"], x.get("modified", "")) for x in r2.get("vulns", []) or []]
                token = r2.get("next_page_token")
            result[k] = ids
            cache[_qkey(k)] = {"t": now, "ids": ids}
    write_json(cache_path, cache)
    return result


def _vuln_cache() -> Path:
    p = cache_dir() / "osv-vulns"
    p.mkdir(exist_ok=True)
    return p


def _fetch(vid: str, modified: str, offline: bool) -> tuple[dict | None, str]:
    """(advisory or None, error message). Falls back to a stale cached copy when the download fails."""
    path = _vuln_cache() / f"{vid}.json"
    cached = read_json(path) if path.exists() else None
    if cached is not None and (offline or not modified or cached.get("modified") == modified):
        return cached, ""
    if offline:
        return None, ""
    try:
        data = http_json(VULN_URL.format(vid), retries=2)
    except Exception as e:
        debug(f"OSV fetch {vid} failed: {e}")
        return cached, str(e)
    write_json(path, data)
    return data, ""


def _eco_matches(affected_eco: str, eco: str) -> bool:
    if ":" in eco:
        # distro ecosystems are release-specific: Ubuntu 24.04 fixes do not apply to 22.04
        return affected_eco == eco
    return affected_eco.split(":")[0] == eco


def _fixed_versions(vuln: dict, eco: str, name: str) -> list[str]:
    fixes, pro_fixes = [], []
    pro_eco = eco.replace("Ubuntu:", "Ubuntu:Pro:", 1) if eco.startswith("Ubuntu:") else None
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        aeco = pkg.get("ecosystem", "")
        if normalize_name(eco, pkg.get("name", "")) != normalize_name(eco, name):
            continue
        target = fixes if _eco_matches(aeco, eco) else pro_fixes if aeco == pro_eco else None
        if target is None:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":
                continue
            target += [ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev]
    # Ubuntu Pro (ESM) fixes only count when the public archive has none; they carry "esm" in the version
    return sorted(set(fixes or pro_fixes))


def affects(vuln: dict, eco: str, name: str, version: str) -> bool:
    """Whether `version` falls in one of the advisory's ECOSYSTEM/SEMVER ranges (or its version list)."""
    v = vkey(version, eco)
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if not _eco_matches(pkg.get("ecosystem", ""), eco) or normalize_name(eco, pkg.get("name", "")) != normalize_name(eco, name):
            continue
        if version in (aff.get("versions") or []):
            return True
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":
                continue
            inside = False
            for ev in rng.get("events", []):
                if "introduced" in ev:  # events are ordered: each window opens at introduced, closes at fixed
                    if ev["introduced"] == "0" or v >= vkey(ev["introduced"], eco):
                        inside = True
                elif "fixed" in ev and inside and v >= vkey(ev["fixed"], eco):
                    inside = False
                elif "last_affected" in ev and inside and v > vkey(ev["last_affected"], eco):
                    inside = False
            if inside:
                return True
    return False


def to_advisory(vuln: dict, eco: str, name: str) -> Advisory:
    vid = vuln["id"]
    db_sev = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
    db_sev = {"MODERATE": "MEDIUM"}.get(db_sev, db_sev)
    score = None
    for s in vuln.get("severity", []) or []:
        if s.get("type") == "CVSS_V3":
            score = cvss3_base_score(s.get("score", ""))
            if score is not None:
                break
    severity = severity_from_score(score) if score is not None else (db_sev or "UNKNOWN")
    # MAL-* (OpenSSF) or GHSA "Embedded malware" advisories (CWE-506)
    cwes = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    malicious = vid.startswith("MAL-") or "CWE-506" in cwes
    if malicious:
        severity = "CRITICAL"
    refs = [r["url"] for r in vuln.get("references", []) or [] if r.get("url", "").startswith("https://")]
    summary = vuln.get("summary") or (vuln.get("details") or "").strip().split("\n")[0][:240]
    # RUSTSEC informational notices (unmaintained, unsound) are not vulnerabilities as such
    info = next((a.get("database_specific", {}).get("informational") for a in vuln.get("affected", [])
                 if (a.get("database_specific") or {}).get("informational")), None)
    if info and severity == "UNKNOWN":
        severity = "LOW"
        summary = f"[{info}] {summary}"
    return Advisory(
        id=vid, summary=summary, aliases=vuln.get("aliases", []) or [], severity=severity, cvss=score,
        fixed=_fixed_versions(vuln, eco, name), malicious=malicious, source="osv",
        references=refs[:8], published=vuln.get("published", ""),
    )


def dedupe(advs: list[Advisory]) -> list[Advisory]:
    """Merge advisories that describe the same issue (GHSA + PYSEC + CVE aliases)."""
    groups: list[list[Advisory]] = []
    for a in advs:
        ids = {a.id, *a.aliases}
        for g in groups:
            if any(ids & {b.id, *b.aliases} for b in g):
                g.append(a)
                break
        else:
            groups.append([a])
    out = []
    pref = {"GHSA": 0, "MAL": 0, "RUSTSEC": 1, "GO": 1, "PYSEC": 2}
    for g in groups:
        g.sort(key=lambda a: (pref.get(a.id.split("-")[0], 3), a.severity == "UNKNOWN"))
        best = g[0]
        for other in g[1:]:
            best.aliases = sorted((set(best.aliases) | {other.id} | set(other.aliases)) - {best.id})
            best.fixed = sorted(set(best.fixed) | set(other.fixed))
            best.malicious = best.malicious or other.malicious
            if best.cvss is None and other.cvss is not None:
                best.cvss, best.severity = other.cvss, other.severity
            if best.severity == "UNKNOWN":
                best.severity = other.severity
        out.append(best)
    return out


def lookup(keys: list[Key], offline: bool = False) -> dict[Key, list[Advisory]]:
    hits = _query(keys, offline)
    wanted = {vid: mod for ids in hits.values() for vid, mod in ids}
    details = _fetch_all(wanted, offline)
    out: dict[Key, list[Advisory]] = {}
    for k, ids in hits.items():
        vulns = [details[v] for v, _ in ids if details.get(v)]
        if k[0] in CLIENT_SIDE_RANGES:
            vulns = [v for v in vulns if affects(v, *k)]
        advs = [to_advisory(v, k[0], k[1]) for v in vulns]
        advs = [a for a in advs if not _withdrawn(details[a.id])]
        if advs:
            out[k] = dedupe(advs)
    return out


LAST_RUN = {"total": 0, "failed": 0, "first_error": ""}  # read by enrich() to mark the scan incomplete


def _fetch_all(wanted: dict[str, str], offline: bool) -> dict[str, dict]:
    """Download advisory details in parallel with progress; stop early if nothing can be downloaded."""
    LAST_RUN.update(total=0, failed=0, first_error="")
    if not wanted:
        return {}
    total = len(wanted)
    log(f"OSV: loading {total} advisories")
    step = max(20, total // 10)
    details: dict[str, dict] = {}
    errors: list[str] = []
    done = 0
    pool = ThreadPoolExecutor(max_workers=8)
    futures = {pool.submit(_fetch, vid, mod, offline): vid for vid, mod in wanted.items()}
    try:
        for fut in as_completed(futures):
            data, err = fut.result()
            done += 1
            if data is not None:
                details[futures[fut]] = data
            if err:
                errors.append(err)
                if len(errors) >= 8 and not details:  # nothing works: say why now instead of grinding on
                    raise HttpError(f"cannot download advisories from OSV ({len(errors)} failures). First error: {errors[0]}")
            if done % step == 0 or done == total:
                log(f"OSV: {done}/{total} advisories" + (f" ({len(errors)} failed)" if errors else ""))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)  # also on cancel: drop queued downloads
    LAST_RUN.update(total=total, failed=len(errors), first_error=errors[0] if errors else "")
    if errors:
        log(f"OSV: {len(errors)} advisories could not be downloaded; results may be incomplete ({errors[0]})")
    return details


def _withdrawn(vuln: dict) -> bool:
    return bool(vuln.get("withdrawn"))
