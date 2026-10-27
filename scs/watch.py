"""`scs watch`: unattended scan + malware check that alerts only on what is new.

Designed for the scheduler (`scs schedule install`). Each run:
  1. vulnerability scan (recorded in history; findings carry new-since-last-scan)
  2. malware checks: quick (packages, build chain, persistence, extensions) or full, optional reputation
  3. alert on: new findings at/above the threshold, anything malicious / IOC, known-exploited (KEV)
     CVEs, and malware findings that were not present in the previous run
Each alert key is sent once (state in ~/.local/share/scs/alerts.json); every run that
alerts is appended to alerts-log.jsonl. The first run only establishes a baseline and
alerts on malicious/IOC and KEV items, so you are not flooded with existing debt.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scs import notify
from scs.malware import severity_rank
from scs.models import SEVERITY_ORDER, finding_key
from scs.util import host_id, data_dir, log, read_json, write_json

QUICK_MALWARE = ("packages", "buildchain", "persistence", "extensions")
SEV_TO_MALWARE = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _state_path() -> Path:
    return data_dir() / "alerts.json"


def _vuln_lines(result: dict, min_sev: str, first_run: bool) -> list[tuple[str, str, str]]:
    """(key, severity, line) for findings worth an alert."""
    out = []
    threshold = SEVERITY_ORDER[min_sev.upper()]
    for f in result["findings"]:
        kev = any(a.get("kev") for a in f["advisories"])
        urgent = f["bucket"] == "respond" or kev
        if not urgent and (first_run or not f["new"] or SEVERITY_ORDER.get(f["severity"], 0) < threshold):
            continue
        ids = ", ".join((a["cves"][0] if a["cves"] and not a["malicious"] else a["id"]) for a in f["advisories"][:3])
        key = "vuln|" + finding_key(f) + "|" + ",".join(sorted(a["id"] for a in f["advisories"]))
        if f["ecosystem"] == "file":
            line = f"MALICIOUS IOC file {f['name']}"
        else:
            fix = f" → {f['fix_version']}" if f.get("fix_version") else " (no fix yet)"
            tag = "MALICIOUS " if f["bucket"] == "respond" else ("KEV " if kev else "")
            line = f"{tag}{f['severity']} {f['ecosystem']} {f['name']} {f['version']}{fix} — {ids} ({len(f['packages'])} location(s))"
        sev = "critical" if f["bucket"] == "respond" else f["severity"].lower()
        out.append((key, sev if sev in SEV_TO_MALWARE else "medium", line))
    return out


def _malware_key(m: dict) -> str:
    return f"mw|{m['check']}|{m['title']}|{m.get('path', '')}"


def _malware_lines(mres: dict, previous: dict | None, min_sev: str, first_run: bool) -> list[tuple[str, str, str]]:
    prev_keys = {_malware_key(m) for m in (previous or {}).get("findings", [])}
    threshold = severity_rank(SEV_TO_MALWARE.get(min_sev.lower(), "high"))
    out = []
    for m in mres["findings"]:
        k = _malware_key(m)
        fresh = m.get("new") or (previous is not None and k not in prev_keys)
        if first_run and m["severity"] != "critical":
            continue
        if not first_run and (not fresh or severity_rank(m["severity"]) < threshold):
            continue
        out.append((k, m["severity"], f"{m['severity'].upper()} {m['title']} — {m.get('path', '')}"))
    return out


def run(cfg, malware: str = "quick", min_severity: str = "high", reputation: bool = False,
        deliver: bool = True, perform_scan=None) -> dict:
    from scs.cli import _write_reports, perform_scan as default_scan
    from scs.malware import runner
    from scs.report import malware as mreport

    perform_scan = perform_scan or default_scan
    started = datetime.now().astimezone().isoformat(timespec="seconds")
    result = perform_scan(cfg)
    reports = data_dir() / "reports"
    written = _write_reports(result, reports, ["html"])
    report = str(written[0]) if written else ""
    first_vuln = not result.get("has_previous")
    candidates = _vuln_lines(result, min_severity, first_vuln)

    mres = None
    if malware != "none":
        latest = data_dir() / "malware-latest.json"
        previous = read_json(latest) if latest.is_file() else None
        checks = runner.CHECKS if malware == "full" else QUICK_MALWARE
        if reputation:
            checks = tuple(checks) + ("reputation",)
        mres = runner.run(cfg, checks)
        latest.write_text(json.dumps(mres, default=str), encoding="utf-8")
        mpath = reports / f"malware-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        mpath.write_text(mreport.render_html(mres), encoding="utf-8")
        candidates += _malware_lines(mres, previous, min_severity, previous is None)

    from scs import selfcheck
    integrity = selfcheck.verify()
    if integrity["ok"] is False:  # someone changed scs itself: everything above may be untrustworthy
        candidates.insert(0, ("self|" + integrity["detail"][:120], "critical",
                              f"scs itself was modified since it was built ({integrity['how']}): {integrity['detail'][:200]}. "
                              "Reinstall it from a trusted copy before trusting these results."))
    state = read_json(_state_path()) if _state_path().is_file() else {"sent": {}}
    fresh = [(k, s, ln) for k, s, ln in candidates if k not in state["sent"]]
    summary = {"started": started, "host": host_id(), "baseline_run": first_vuln, "report": report,
               "candidates": len(candidates), "alerts": len(fresh), "delivery": {},
               "scan_summary": result["summary"]["buckets"], "malware_counts": (mres or {}).get("counts")}
    if not fresh:
        log("watch: nothing new to alert on")
        return summary

    worst = max((s for _, s, _ in fresh), key=lambda s: severity_rank(s))
    alert = notify.Alert(host=summary["host"], severity=worst,
                         title=f"{len(fresh)} new security finding(s) on {summary['host']}",
                         lines=[ln for _, _, ln in sorted(fresh, key=lambda x: -severity_rank(x[1]))], report=report,
                         counts={"vulnerabilities": sum(k.startswith("vuln|") for k, _, _ in fresh),
                                 "malware": sum(k.startswith("mw|") for k, _, _ in fresh)})
    if deliver and cfg.notify:
        summary["delivery"] = notify.send(alert, cfg.notify)
    elif deliver:
        summary["delivery"] = {"none": "no channels configured (see `notify` in config.json)"}
    now = datetime.now().isoformat(timespec="seconds")
    for k, _, _ in fresh:
        state["sent"][k] = now
    write_json(_state_path(), state)
    with open(data_dir() / "alerts-log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"at": now, "title": alert.title, "severity": worst, "lines": alert.lines,
                            "report": report, "delivery": summary["delivery"]}) + "\n")
    summary["alert"] = {"title": alert.title, "lines": alert.lines}
    return summary


def recent_alerts(limit: int = 20) -> list[dict]:
    p = data_dir() / "alerts-log.jsonl"
    if not p.is_file():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(ln) for ln in reversed(lines) if ln.strip()]
