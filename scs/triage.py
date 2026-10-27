"""Interactive triage of a recorded scan: decide what to patch now, verify, defer or ignore.

Decisions are saved after every answer, so quitting (or Ctrl+C) keeps progress.
Ignoring writes a rule with a reason and expiry to the policy file.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from scs.analyze import BUCKET_TITLES, BUCKETS
from scs.models import finding_key
from scs.policy import USER_POLICY, Decisions, Policy, parse_expiry
from scs.report import short_path, where
from scs.report.terminal import SEV_COLOR, c, dim

DEFAULT_ACTION = {"respond": "respond", "patch": "patch", "verify": "verify", "monitor": "defer"}
KEYS = {"r": "respond", "p": "patch", "v": "verify", "d": "defer"}
HELP = ("[Enter]=suggested  p=patch now  v=verify first  d=defer  i=ignore  s=skip  "
        "m=more detail  b=accept suggested for the rest of this bucket  u=undo  q=save & quit")


def _card(f: dict, idx: int, total: int, out: Callable[[str], None]) -> None:
    sev = c(f"{f['severity']}", SEV_COLOR.get(f["severity"], "0"))
    if f["ecosystem"] == "file":
        title = f"IOC file {short_path(f['name'])}"
    else:
        fix = f" → {c(f['fix_version'], '32')}" if f.get("fix_version") else " (no fix yet)"
        title = f"{f['ecosystem']} {c(f['name'], '1')} {f['version']}{fix}"
    out(f"\n[{idx}/{total}] {c(BUCKET_TITLES[f['bucket']], '1')} · score {f['score']} · {sev}")
    out(f"  {title}")
    advs = f["advisories"]
    ids = ", ".join((a["cves"][0] if a["cves"] and not a["malicious"] else a["id"]) for a in advs[:4])
    more = f" +{len(advs) - 4}" if len(advs) > 4 else ""
    kev = c(" KEV", "1;35") if any(a["kev"] for a in advs) else ""
    out(f"  {ids}{more}{kev}")
    if advs and advs[0].get("summary"):
        out(dim(f"  {advs[0]['summary'][:150]}"))
    for p in f["packages"][:2]:
        out(dim(f"  in: {where(p)}"))
    if len(f["packages"]) > 2:
        out(dim(f"  … and {len(f['packages']) - 2} more locations"))
    for r in f["reasons"]:
        out(f"  {c('!', '33')} {r}")
    out(f"  {f['advice']}")
    if f.get("decision"):
        d = f["decision"]
        stale = " (new advisories since)" if d.get("stale") else ""
        out(dim(f"  previous decision: {d['action']} on {d['decided']}{stale}"))


def _details(f: dict, out: Callable[[str], None]) -> None:
    for a in f["advisories"]:
        out(f"    {a['severity']:<8} {a['id']} {', '.join(a['cves'][:3])} fixed in {', '.join(a['fixed'][-3:]) or '-'}")
        out(dim(f"             {a['summary'][:120]}"))
    for p in f["packages"]:
        out(f"    location: {short_path(p['location'])}")
        for path in (p.get("meta") or {}).get("paths", [])[:3]:
            out(dim(f"      chain: {' > '.join(path)}"))
    if f.get("toolchain") and f["toolchain"].get("fix_requires"):
        t = f["toolchain"]
        out(f"    fix requires {t['runtime']} {t['fix_requires']}")
    for cmd in f["commands"]:
        out(dim(f"    $ {cmd}"))


def _ask_ignore(f: dict, ask: Callable[[str], str], out: Callable[[str], None]) -> list[dict] | None:
    malicious = any(a["malicious"] for a in f["advisories"])
    if malicious:
        out(c("  This is a known-malicious package. Ignoring it hides an active compromise.", "1;31"))
        if ask("  Type IGNORE MALICIOUS to continue: ").strip() != "IGNORE MALICIOUS":
            out("  not ignored")
            return None
    reason = ""
    while not reason:
        reason = ask("  Reason (required, e.g. 'not reachable: dev tool only'): ").strip()
    while True:
        try:
            expires = parse_expiry(ask("  Expires [90d] (e.g. 30d, 12w, 2027-01-31): ").strip() or "90d")
            break
        except ValueError:
            out("  use 30d / 12w / 6m / YYYY-MM-DD")
    scope = ask("  Scope: [1] this package@version (default)  [2] this package, any version  [3] these advisories everywhere: ").strip() or "1"
    pkg = None if scope == "3" or f["ecosystem"] == "file" else f"{f['ecosystem']}:{f['name']}"
    version = f["version"] if scope == "1" else None
    return [{"advisory": a["id"], "package": pkg, "version": version, "reason": reason, "expires": expires,
             "force": True if malicious else None} for a in f["advisories"]]


def run(result: dict, decisions: Decisions, ask: Callable[[str], str] = input,
        out: Callable[[str], None] = print, include_decided: bool = False,
        buckets: list[str] | None = None, policy_path: Path = USER_POLICY, auto: bool = False) -> dict:
    items = [f for f in result["findings"]
             if (include_decided or not f.get("decision") or f["decision"].get("stale"))
             and (not buckets or f["bucket"] in buckets)]
    stats = {"respond": 0, "patch": 0, "verify": 0, "defer": 0, "ignore": 0, "skip": 0}
    if not items:
        out("Nothing to triage: every finding has a current decision (use --all to revisit).")
        return stats
    if not auto:
        out(f"Triage {len(items)} findings from scan of {result['host']} at {result['started']}.")
        out(dim(HELP))
    history: list[tuple[str, dict | None]] = []
    accept_bucket: set[str] = set()
    i = 0
    while i < len(items):
        f = items[i]
        key = finding_key(f)
        ids = [a["id"] for a in f["advisories"]]
        suggested = DEFAULT_ACTION[f["bucket"]]
        if auto or f["bucket"] in accept_bucket:
            if suggested != "defer":  # auto mode never defers on your behalf
                decisions.set(key, suggested, ids)
                stats[suggested] += 1
            else:
                stats["skip"] += 1
            i += 1
            continue
        _card(f, i + 1, len(items), out)
        choice = ask(f"  Action [{suggested}]: ").strip().lower()
        if choice in ("", *KEYS):
            action = KEYS.get(choice, suggested)
            if action == "respond" and not any(a["malicious"] for a in f["advisories"]):
                action = "patch"
            until = ""
            if action == "defer":
                while True:
                    try:
                        until = parse_expiry(ask("  Defer for [14d]: ").strip() or "14d")
                        break
                    except ValueError:
                        out("  use 14d / 4w / YYYY-MM-DD")
            history.append((key, decisions.data.get(key)))
            decisions.set(key, action, ids, until=until)
            stats[action] += 1
        elif choice == "i":
            rules = _ask_ignore(f, ask, out)
            if rules is None:
                continue
            for r in rules:
                Policy.add(r, policy_path)
            history.append((key, decisions.data.get(key)))
            decisions.drop(key)
            stats["ignore"] += 1
            out(dim(f"  {len(rules)} ignore rule(s) written to {short_path(str(policy_path))}"))
        elif choice == "s":
            stats["skip"] += 1
        elif choice == "m":
            _details(f, out)
            continue
        elif choice == "b":
            accept_bucket.add(f["bucket"])
            continue
        elif choice == "u":
            if history:
                prev_key, prev = history.pop()
                if prev is None:
                    decisions.drop(prev_key)
                else:
                    decisions.data[prev_key] = prev
                decisions.save()
                i = max(0, i - 1)
                out(dim("  undone (ignore rules already written stay in the policy file)"))
            continue
        elif choice == "q":
            break
        else:
            out(dim(HELP))
            continue
        decisions.save()
        i += 1
    decisions.save()
    done = ", ".join(f"{v} {k}" for k, v in stats.items() if v)
    out(f"\nSaved decisions: {done or 'none'}. Next: `scs plan` to build the patch plan.")
    return stats


def bucket_names() -> list[str]:
    return list(BUCKETS)
