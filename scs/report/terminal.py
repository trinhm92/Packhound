"""Plain-text / ANSI terminal report."""
from __future__ import annotations

import os
import sys

from scs.analyze import BUCKET_TITLES, BUCKETS, RESPOND_CHECKLIST
from scs.report import short_path, where

_COLOR = bool(sys.stdout and sys.stdout.isatty()) and not os.environ.get("NO_COLOR")
SEV_COLOR = {"CRITICAL": "1;31", "HIGH": "31", "MEDIUM": "33", "LOW": "36", "UNKNOWN": "37"}
BUCKET_COLOR = {"respond": "1;41;97", "patch": "1;32", "verify": "1;33", "monitor": "1;37"}


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def dim(text: str) -> str:
    return c(text, "2")


def _adv_line(f: dict) -> str:
    advs = f["advisories"]
    ids = []
    for a in advs[:3]:
        ids.append(a["cves"][0] if a["cves"] and not a["malicious"] else a["id"])
    more = f" +{len(advs) - 3}" if len(advs) > 3 else ""
    tags = []
    if any(a["kev"] for a in advs):
        tags.append(c("KEV", "1;35"))
    epss = max((a["epss"] or 0 for a in advs), default=0)
    if epss >= 0.01:
        tags.append(f"EPSS {epss:.0%}")
    if any(a["confidence"] == "low" for a in advs):
        tags.append(dim("low-confidence"))
    return ", ".join(ids) + more + ("  " + " ".join(tags) if tags else "")


def render(result: dict, limit: int = 15, out=sys.stdout) -> None:
    w = out.write
    s = result["summary"]
    inv = result["inventory"]
    w(f"\n{c('scs supply-chain scan', '1')}  {result['host']}  {result['started']}  ({result['duration_s']}s)\n")
    by_src = " · ".join(f"{k} {v['count']}" for k, v in result["collectors"].items() if v["status"] == "ok")
    w(f"Inventory: {inv['total']} package instances, {inv['unique']} unique — {by_src}\n")
    for k, v in result["collectors"].items():
        if v["status"] != "ok":
            w(dim(f"  collector {k}: {v['status']}\n"))
    for k, v in result["sources"].items():
        mark = c("✗", "31") if v.startswith(("FAILED", "INCOMPLETE")) else c("✓", "32")
        w(f"  {mark} {k}: {v}\n")
    b = s["buckets"]
    w("Findings: " + " · ".join(c(f"{b[k]} {BUCKET_TITLES[k].split(' (')[0].lower()}", BUCKET_COLOR[k] if b[k] else "2")
                                for k in BUCKETS))
    w(f"   ({s['new']} new since last scan)\n" if result.get("has_previous") else "\n")

    findings = result["findings"]
    for bucket in BUCKETS:
        items = [f for f in findings if f["bucket"] == bucket]
        if not items:
            continue
        w(f"\n{c(' ' + BUCKET_TITLES[bucket] + ' ', BUCKET_COLOR[bucket])}\n")
        if bucket == "respond":
            for i, step in enumerate(RESPOND_CHECKLIST, 1):
                w(dim(f"  {i}. {step}\n"))
        for f in items[:limit]:
            sev = c(f"{f['severity'][:4]:<4}", SEV_COLOR.get(f["severity"], "0"))
            new = c(" NEW", "1;36") if f["new"] and result.get("has_previous") else ""
            if f["ecosystem"] == "file":
                w(f"  {f['score']:>3} {sev}  {c('IOC file', '1')} {short_path(f['name'])}{new}\n")
            else:
                arrow = f" → {c(f['fix_version'], '32')}" if f.get("fix_version") else ""
                w(f"  {f['score']:>3} {sev}  {dim(f['ecosystem'])} {c(f['name'], '1')} {f['version']}{arrow}"
                  f"   {_adv_line(f)}{new}\n")
            locs = [where(p) for p in f["packages"]]
            if locs:
                extra = f" (+{len(locs) - 2} more)" if len(locs) > 2 else ""
                w(dim(f"        in: {'; '.join(locs[:2])}{extra}\n"))
            intro = sorted({i for p in f["packages"] for i in (p.get("meta") or {}).get("introduced_by", [])
                            if not p.get("direct")})
            if intro:
                w(dim(f"        pulled in by: {', '.join(intro[:4])}{f' (+{len(intro) - 4})' if len(intro) > 4 else ''}\n"))
            if f.get("decision"):
                d = f["decision"]
                w(c(f"        decision: {d['action']}{' until ' + d['until'] if d.get('until') else ''}"
                    f"{' (stale: new advisories)' if d.get('stale') else ''}\n", "36"))
            if f["reasons"]:
                w(f"        {c('why verify:', '33') if bucket == 'verify' else dim('note:')} {'; '.join(f['reasons'])}\n")
            w(f"        {f['advice']}\n")
            for cmd in f["commands"][:3]:
                w(dim(f"        $ {cmd}\n"))
        if len(items) > limit:
            w(dim(f"  … {len(items) - limit} more in the HTML/JSON report\n"))

    outdated = result.get("outdated", [])
    if outdated:
        names = ", ".join(o["name"] for o in outdated[:12])
        w(f"\n{c('Outdated packages (Homebrew, Snap, Flatpak, winget, Chocolatey, Scoop)', '1')} ({len(outdated)}): {names}{'…' if len(outdated) > 12 else ''}\n")
        if not result["config"].get("nvd"):
            w(dim("  No CVE data for Homebrew without --nvd; outdated is a weak signal, not proof of a vulnerability.\n"))
    ignored = result.get("ignored") or []
    pol = result.get("policy") or {}
    if ignored or pol.get("expired"):
        w(dim(f"\n{len(ignored)} finding(s) hidden by ignore rules; {pol.get('expired', 0)} expired rule(s) "
              f"(see `scs policy`)\n"))
    if result["errors"]:
        w(dim(f"\n{len(result['errors'])} non-fatal errors (see JSON report)\n"))
    if not findings:
        w(c("\nNo known vulnerable or malicious packages found.\n", "32"))
    elif any(not f.get("decision") for f in findings):
        undecided = sum(not f.get("decision") for f in findings)
        w(f"\nNext: {c('scs triage', '1')} ({undecided} findings without a decision), then {c('scs plan', '1')}.\n")


def render_plan(plan: dict, out=sys.stdout) -> None:
    w = out.write
    w(f"\n{c('Patch plan (dry run — nothing executed)', '1')}  scan {plan['scan']['started']}\n")
    if plan["untriaged"]:
        w(dim(f"{plan['untriaged']} findings not triaged and not included (scs triage, or plan --suggested)\n"))
    for path in plan["ioc_files"]:
        w(c(f"IOC file: {short_path(path)} — inspect and remove, then follow the incident checklist\n", "1;31"))
    if not plan["targets"]:
        w("No targets: no findings were marked patch/verify/respond.\n")
    for n, t in enumerate(plan["targets"], 1):
        pk = t["packages"]
        w(f"\n{c(f'[target_{n}] ' + t['title'], '1')}  {len(pk)} package change(s)\n")
        for wmsg in t["warnings"][:6]:
            w(f"  {c('!', '33')} {wmsg}\n")
        if len(t["warnings"]) > 6:
            w(dim(f"  … {len(t['warnings']) - 6} more warnings in the plan file\n"))
        for cmd in t["change"][:6]:
            w(f"  $ {cmd}\n")
        if len(t["change"]) > 6:
            w(dim(f"  … {len(t['change']) - 6} more commands\n"))
        if t["verify"]:
            w(dim(f"  verify: {' ; '.join(t['verify'][:3])}\n"))
        for m in t["manual"][:3]:
            w(dim(f"  note: {m}\n"))
