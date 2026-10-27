"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from shlex import quote as q

from scs import __version__, history, selfcheck, toolchain, triage
from scs import plan as patch_plan
from scs.analyze import AnalysisContext, build_findings, summarize
from scs.collectors import Context, registry, run_collectors
from scs.config import load_config
from scs.enrich import enrich
from scs.models import SEVERITY_ORDER
from scs.policy import PROJECT_POLICY, USER_POLICY, Decisions, Policy, parse_expiry
from scs.report import html as html_report
from scs.report import short_path, terminal
from scs.util import host_id, data_dir, log, set_verbose

PLANNED: dict[str, str] = {}

STATUS_COLOR = {"applied": "32", "partial": "33", "rolled_back": "33", "skipped": "2", "dry-run": "36",
                "failed": "31", "rollback_failed": "1;31", "interrupted": "31", "pending": "2"}


def _write_reports(result: dict, out_dir: Path, formats: list[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = result["started"].replace(":", "").replace("-", "").replace("T", "-")[:15]
    written = []
    if "html" in formats:
        p = out_dir / f"scan-{stamp}.html"
        p.write_text(html_report.render(result), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = out_dir / f"scan-{stamp}.json"
        p.write_text(html_report.render_json(result), encoding="utf-8")
        written.append(p)
    return written


def _exit_code(result: dict, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_ORDER[fail_on.upper()]
    worst = max((SEVERITY_ORDER.get(f["severity"], 0) for f in result["findings"]), default=0)
    return 2 if worst >= threshold else 0


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = load_config()
    if args.root:
        cfg.roots = args.root
    if args.only:
        cfg.collectors = args.only.split(",")
    cfg.system = not args.no_system
    cfg.offline = args.offline or cfg.offline
    cfg.nvd = args.nvd or cfg.nvd
    cfg.max_depth = args.max_depth or cfg.max_depth
    if args.ioc_dir:
        cfg.ioc_dirs += args.ioc_dir
    result = perform_scan(cfg, inventory=args.inventory, save=not args.no_save)
    formats = [x for x in args.format.split(",") if x]
    written = _write_reports(result, Path(args.out).expanduser() if args.out else data_dir() / "reports", formats)
    terminal.render(result, limit=args.limit)
    for p in written:
        print(f"report: {p}")
    return _exit_code(result, args.fail_on)


def perform_scan(cfg, inventory: bool = False, save: bool = True) -> dict:
    """Collect → enrich → analyse; returns the result dict (also recorded in history when save)."""
    t0 = time.time()
    started = datetime.now().astimezone().isoformat(timespec="seconds")
    host = host_id()
    ctx = Context(cfg)
    packages, stats = run_collectors(ctx)
    log(f"collected {len(packages)} package instances; looking up advisories…")
    prev_scan = history.load(host=host)
    advisories, file_hits, notes = enrich(packages, cfg, ctx.project_dirs())
    project_dirs = sorted({p.meta["project"] for p in packages if p.meta.get("project")})
    projects = {d: toolchain.detect_project(d) for d in project_dirs}
    actx = AnalysisContext(
        graphs=ctx.graphs, policy=Policy(), decisions=Decisions(), projects=projects,
        brew_versions={p.name: p.version for p in packages if p.source == "brew"},
        requirements=toolchain.Requirements(offline=cfg.offline),
    )
    log("checking fixed versions against project toolchains…")
    findings, ignored = build_findings(packages, advisories, file_hits, history.previous_keys(host), actx)

    unique = {p.key for p in packages}
    result = {
        "scs_version": __version__, "host": host, "started": started,
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "duration_s": round(time.time() - t0, 1),
        "config": {"roots": [str(r) for r in cfg.expanded_roots()], "offline": cfg.offline, "nvd": cfg.nvd,
                   "system": cfg.system},
        "collectors": stats, "sources": notes, "errors": ctx.errors,
        "inventory": {"total": len(packages), "unique": len(unique),
                      "by_ecosystem": dict(Counter(e for e, _, _ in unique))},
        "has_previous": prev_scan is not None,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
        "ignored": ignored,
        "policy": {"rules": len(actx.policy.rules), "expired": sum(Policy.expired(r) for r in actx.policy.rules)},
        "projects": {d: {k: v for k, v in info.items() if k not in ("pins", "scripts", "markers")}
                     for d, info in projects.items()},
        "outdated": sorted(({"name": p.name, "version": p.version, "latest": p.meta.get("latest"),
                             "kind": p.meta.get("kind"), "source": p.source, "ecosystem": p.ecosystem,
                             "location": p.location, "meta": {k: v for k, v in p.meta.items()
                                                              if k in ("root", "pinned", "bucket", "display")}}
                            for p in packages
                            if p.source in ("brew", "snap", "flatpak", "winget", "choco", "scoop") and p.meta.get("outdated")), key=lambda o: o["name"]),
        "packages": [p.to_dict() for p in packages] if inventory else [],
    }
    if save:
        result["scan_id"] = history.save(result)
    return result


def cmd_report(args: argparse.Namespace) -> int:
    result = history.load(scan_id=args.id)
    if not result:
        log("no scans recorded yet — run `scs scan` first")
        return 1
    formats = [x for x in args.format.split(",") if x]
    written = _write_reports(result, Path(args.out).expanduser() if args.out else data_dir() / "reports", formats)
    terminal.render(result, limit=args.limit)
    for p in written:
        print(f"report: {p}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    for sid, started, host, summary in history.listing(args.limit):
        s = json.loads(summary)
        b = s["buckets"]
        print(f"#{sid:<4} {started}  {host}  respond={b['respond']} patch={b['patch']} "
              f"verify={b['verify']} monitor={b['monitor']}")
    return 0


def cmd_collectors(args: argparse.Namespace) -> int:
    cfg = load_config()
    ctx = Context(cfg)
    for c in registry():
        ok = "available" if c.available(ctx) else "not found"
        kind = "system" if c.system else "project/env"
        print(f"{c.id:<11} {ok:<10} {kind:<11} {c.description}")
    return 0


def _load_scan(scan_id: int | None) -> dict | None:
    result = history.load(scan_id=scan_id) if scan_id else history.load(host=host_id()) or history.load()
    if not result:
        log("no scans recorded yet — run `scs scan` first")
    return result


def cmd_triage(args: argparse.Namespace) -> int:
    result = _load_scan(args.id)
    if not result:
        return 1
    if not args.auto and not sys.stdin.isatty():
        log("triage is interactive; use --auto to accept the suggested buckets non-interactively")
        return 1
    decisions = Decisions()
    try:
        triage.run(result, decisions, include_decided=args.all, buckets=args.bucket,
                   policy_path=Path(args.policy).expanduser() if args.policy else USER_POLICY, auto=args.auto)
    except (KeyboardInterrupt, EOFError):
        decisions.save()
        print("\ninterrupted — decisions so far are saved")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    result = _load_scan(args.id)
    if not result:
        return 1
    actions = tuple(args.only.split(",")) if args.only else patch_plan.DEFAULT_ACTIONS
    plan = patch_plan.build(result, Decisions(), actions=actions, suggested=args.suggested,
                            include_outdated=args.outdated, migrate=args.migrate, min_age=args.min_age)
    out_dir = Path(args.out).expanduser() if args.out else data_dir() / "plans"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    ext = ".cmd" if plan.get("shell") == "cmd" else ".sh"
    md, sh, js = out_dir / f"plan-{stamp}.md", out_dir / f"plan-{stamp}{ext}", out_dir / f"plan-{stamp}.json"
    md.write_text(patch_plan.to_markdown(plan), encoding="utf-8")
    sh.write_text(patch_plan.to_script(plan), encoding="utf-8")
    js.write_text(json.dumps(plan, indent=1), encoding="utf-8")
    terminal.render_plan(plan)
    print(f"\nplan: {md}\nscript (dry run, guarded): {sh}\njson: {js}")
    return 0


def cmd_ignore(args: argparse.Namespace) -> int:
    path = PROJECT_POLICY if args.project else USER_POLICY
    try:
        expires = parse_expiry(args.expires)
    except ValueError:
        log("--expires takes 30d / 12w / 6m / YYYY-MM-DD")
        return 1
    rule = Policy.add({"advisory": args.advisory, "package": args.package, "version": args.version,
                       "path": args.path, "reason": args.reason, "expires": expires}, path)
    print(f"added to {path}: {json.dumps(rule)}")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    if args.prune:
        for path in (USER_POLICY, PROJECT_POLICY):
            n = Policy.prune(path)
            if n:
                print(f"removed {n} expired rule(s) from {path}")
    pol = Policy()
    if not pol.rules:
        print(f"no ignore rules ({USER_POLICY} / ./{PROJECT_POLICY})")
    for r in pol.rules:
        status = "EXPIRED" if Policy.expired(r) else "active "
        scope = " ".join(x for x in (r.get("package"), r.get("version"), r.get("path")) if x) or "everywhere"
        print(f"{status} {r.get('advisory', '*'):<22} {scope:<30} until {r.get('expires') or 'never'}  "
              f"— {r.get('reason', '')}  [{short_path(r['_file'])}]")
    return 0


def cmd_malware(args: argparse.Namespace) -> int:
    from scs.malware import runner, severity_rank
    from scs.report import malware as mreport
    cfg = load_config()
    if args.root:
        cfg.roots = args.root
    if args.ioc_dir:
        cfg.ioc_dirs += args.ioc_dir
    checks = tuple(args.only.split(",")) if args.only else runner.CHECKS
    if args.reputation and "reputation" not in checks:
        checks += ("reputation",)
    unknown = set(checks) - set(runner.CHECKS) - set(runner.OPT_IN_CHECKS)
    if unknown:
        log(f"unknown checks: {', '.join(sorted(unknown))} (choose from {', '.join(runner.CHECKS)})")
        return 1
    result = runner.run(cfg, checks, integrity_mode=args.integrity, yara_dirs=args.yara_rules or [],
                        extra_paths=args.path or [], downloads=not args.no_downloads, guarddog=args.guarddog,
                        update_baseline=not args.no_baseline)
    out_dir = Path(args.out).expanduser() if args.out else data_dir() / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    written = []
    formats = [x for x in args.format.split(",") if x]
    if "html" in formats:
        p = out_dir / f"malware-{stamp}.html"
        p.write_text(mreport.render_html(result), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = out_dir / f"malware-{stamp}.json"
        p.write_text(json.dumps(result, indent=1, default=str), encoding="utf-8")
        written.append(p)
    (data_dir() / "malware-latest.json").write_text(json.dumps(result, default=str), encoding="utf-8")  # for `scs export`
    mreport.render(result, show_all=args.all)
    for p in written:
        print(f"report: {p}")
    if args.fail_on:
        worst = max((severity_rank(f["severity"]) for f in result["findings"]), default=0)
        return 2 if worst >= severity_rank(args.fail_on) else 0
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    from scs.malware import quarantine
    if args.list:
        items = quarantine.listing()
        if not items:
            print("quarantine is empty")
        for m in items:
            print(f"{m['id']}  {m['quarantined_at']}  {short_path(m['original_path'])}  — {m['reason']}")
        return 0
    if args.restore:
        m = quarantine.restore(args.restore)
        print(f"restored {m['original_path']}")
        return 0
    if not args.path:
        log("give a path to quarantine, or --list / --restore ID")
        return 1
    if not args.reason:
        log("--reason is required (it is stored in the quarantine manifest)")
        return 1
    target = Path(args.path).expanduser()
    if not args.yes:
        if not sys.stdin.isatty():
            log("refusing to move files without confirmation; pass --yes")
            return 1
        ans = input(f"Move {target} into quarantine (it stops working until restored)? [y/N] ").strip().lower()
        if ans != "y":
            print("cancelled")
            return 1
    m = quarantine.add(str(target), args.reason)
    print(f"quarantined {m['original_path']} as {m['id']} (sha256 {m['sha256'][:16]}…)")
    if m["original_path"].endswith(".plist") and "/Launch" in m["original_path"]:
        print("launchd still has it loaded until logout/reboot; unload now with:\n"
              f"  launchctl bootout gui/$(id -u) {q(m['original_path'])}   # agents\n"
              f"  sudo launchctl bootout system {q(m['original_path'])}     # daemons")
    print(f"restore with: scs quarantine --restore {m['id']}")
    return 0


def _select_targets(plan: dict, args: argparse.Namespace) -> list[int] | None:
    total = len(plan["targets"])
    if args.all:
        return list(range(1, total + 1))
    if not args.target:
        return None
    out = []
    for t in args.target:
        n = int(str(t).replace("target_", ""))
        if not 1 <= n <= total:
            raise ValueError(f"target_{n} does not exist (plan has {total})")
        out.append(n)
    return out


def _list_targets(plan: dict, plan_path: str) -> None:
    print(f"plan: {plan_path}")
    for n, t in enumerate(plan["targets"], 1):
        risk = " !" if t["warnings"] or t["kind"] == "brew" else ""
        print(f"  target_{n:<3} {t['title']}  ({len(t['packages'])} changes){risk}")
    print("Choose with --target N (repeatable) or --all; add --dry-run to preview.")


def cmd_patch(args: argparse.Namespace) -> int:
    from scs import executor
    if args.history:
        for j in executor.history():
            counts = Counter(t["status"] for t in j.get("targets", []))
            print(f"{j['id']}  {'dry-run ' if j.get('dry_run') else ''}"
                  + ", ".join(f"{v} {k}" for k, v in counts.items()) + f"  ({short_path(j['plan'])})")
        return 0
    try:
        plan, plan_path = executor.load_plan(args.plan)
        selected = _select_targets(plan, args)
    except (FileNotFoundError, ValueError) as e:
        log(str(e))
        return 1
    if selected is None:
        _list_targets(plan, plan_path)
        return 1
    if not args.dry_run and not args.yes and not sys.stdin.isatty():
        log("non-interactive: pass --yes (and --accept-risk for risky targets), or --dry-run")
        return 1
    opts = executor.Options(yes=args.yes, accept_risk=args.accept_risk, dry_run=args.dry_run,
                            rollback=not args.no_rollback, baseline_verify=not args.no_baseline,
                            allow_dirty=args.allow_dirty, force=args.force, keep_going=args.keep_going,
                            ignore_scripts=args.ignore_scripts, allow_sudo=args.allow_sudo,
                            timeout=args.timeout)
    runner = executor.Runner(plan, plan_path, opts)
    print(f"run {runner.run.id}{' (dry run)' if args.dry_run else ''}: plan {short_path(plan_path)}, "
          f"journal {short_path(str(runner.run.dir / 'journal.json'))}")
    journal = runner.execute(selected)
    print("\nSummary")
    for rec in journal["targets"]:
        status = terminal.c(f"{rec['status']:<15}", STATUS_COLOR.get(rec["status"], "0"))
        print(f"  target_{rec['n']:<3} {status} {rec['title']}" + (f" — {rec['reason']}" if rec.get("reason") else ""))
    if any(r["status"] in ("applied", "partial") for r in journal["targets"]):
        print("Next: `scs scan` to refresh findings (fixed items drop out).")
    bad = any(r["status"] in ("rolled_back", "rollback_failed", "failed", "interrupted") for r in journal["targets"])
    return 2 if bad else 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Run only the plan's verification commands (no changes)."""
    from scs import executor
    try:
        plan, plan_path = executor.load_plan(args.plan)
        selected = _select_targets(plan, args)
    except (FileNotFoundError, ValueError) as e:
        log(str(e))
        return 1
    if selected is None:
        _list_targets(plan, plan_path)
        return 1
    runner = executor.Runner(plan, plan_path, executor.Options(timeout=args.timeout))
    failed = 0
    for n in selected:
        t = plan["targets"][n - 1]
        print(f"\n== target_{n}: {t['title']}")
        for k, c in enumerate(t["verify"]):
            if executor.missing_tools([c]):
                print(f"   skip  {c}  (tool not installed)")
                continue
            rc, logp, secs = runner._cmd(n, "verify-only", k, c, runner.run.dir)
            print(f"   {'pass' if rc == 0 else 'FAIL'}  {c}  ({secs}s)")
            failed += rc != 0
    print(f"\nlogs: {runner.run.dir / 'logs'}")
    return 2 if failed else 0


def cmd_export(args: argparse.Namespace) -> int:
    from scs import fleet
    try:
        bundle = fleet.export(include_malware=not args.no_malware)
    except FileNotFoundError as e:
        log(str(e))
        return 1
    text = json.dumps(bundle, default=str)
    if args.out in (None, "-"):
        sys.stdout.write(text + "\n")
    else:
        Path(args.out).expanduser().write_text(text, encoding="utf-8")
        log(f"bundle written to {args.out} ({len(text) // 1024} KiB)")
    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    from scs import fleet
    from scs.report import fleet as freport
    files = [Path(f).expanduser() for f in args.bundles]
    for d in args.dir or []:
        files += sorted(Path(d).expanduser().glob("*.json"))
    bundles = []
    for f in files:
        try:
            b = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            log(f"skipping {f}: {e}")
            continue
        if b.get("bundle_version") != fleet.BUNDLE_VERSION:
            log(f"skipping {f}: not an scs export bundle")
            continue
        bundles.append(b)
    if not bundles:
        log("no bundles to merge (create them with `scs export` on each machine)")
        return 1
    merged = fleet.merge(bundles)
    out_dir = Path(args.out).expanduser() if args.out else data_dir() / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    html_path, json_path = out_dir / f"fleet-{stamp}.html", out_dir / f"fleet-{stamp}.json"
    html_path.write_text(freport.render_html(merged), encoding="utf-8")
    json_path.write_text(json.dumps(merged, indent=1, default=str), encoding="utf-8")
    freport.render(merged, limit=args.limit)
    print(f"\nreport: {html_path}\njson: {json_path}")
    return 2 if merged["respond"] else 0


def _watch_opts(args: argparse.Namespace) -> list[str]:
    opts = []
    for r in args.root or []:
        opts += ["--root", str(Path(r).expanduser().resolve())]
    opts += ["--malware", args.malware, "--min-severity", args.min_severity]
    if args.reputation:
        opts.append("--reputation")
    return opts


def cmd_watch(args: argparse.Namespace) -> int:
    from scs import notify, watch
    cfg = load_config()
    if args.root:
        cfg.roots = args.root
    if args.test_alert:
        if not cfg.notify:
            log("no `notify` channels in ~/.config/scs/config.json or ./scs.json")
            return 1
        res = notify.send(notify.Alert(host=host_id(), title="scs test alert", severity="low",
                                       lines=["If you can read this, alert delivery works."]), cfg.notify)
        for ch, r in res.items():
            print(f"  {ch}: {r}")
        return 0 if all(r == "ok" for r in res.values()) else 1
    summary = watch.run(cfg, malware=args.malware, min_severity=args.min_severity, reputation=args.reputation,
                        deliver=not args.no_notify)
    if summary.get("baseline_run"):
        print("baseline run: only malicious/IOC and known-exploited items alert; later runs alert on anything new")
    if summary.get("alert"):
        print(summary["alert"]["title"])
        for ln in summary["alert"]["lines"][:20]:
            print(f"  • {ln}")
        for ch, r in summary["delivery"].items():
            print(f"  sent via {ch}: {r}")
    else:
        print("nothing new")
    print(f"report: {summary['report']}")
    return 2 if summary.get("alert") else 0


def cmd_alerts(args: argparse.Namespace) -> int:
    from scs import watch
    items = watch.recent_alerts(args.limit)
    if not items:
        print("no alerts yet")
    for a in items:
        print(f"{a['at']}  {a['severity'].upper():<8} {a['title']}")
        for ln in a["lines"][:5]:
            print(f"    • {ln}")
    return 0


def cmd_schedule(args: argparse.Namespace) -> int:
    from scs import schedule
    if args.action == "status":
        print(schedule.status())
        return 0
    if args.action == "remove":
        for line in schedule.remove():
            print(line)
        return 0
    try:
        when = schedule.parse_when(args.daily, args.weekly)
    except ValueError as e:
        log(str(e))
        return 1
    cmd = schedule.watch_command(_watch_opts(args))
    if args.action == "print" or args.print:
        print(schedule.describe(cmd, when))
        return 0
    try:
        for line in schedule.install(cmd, when):
            print(line)
    except RuntimeError as e:
        log(str(e))
        return 1
    print(f"`scs watch` will run {'every ' + when['day'] if when['day'] else 'daily'} at "
          f"{when['hour']:02d}:{when['minute']:02d}. Check with `scs schedule status`; logs in {schedule.log_dir()}")
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from scs.ui import app
    return app.run(browser=args.browser, port=args.port, open_window=not args.no_open)


def cmd_planned(args: argparse.Namespace) -> int:
    print(f"`scs {args.cmd}` is not implemented yet: {PLANNED[args.cmd]}. See PLAN.md.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    # `packhound` and `scs` are the same command; help and errors use the name that was typed
    invoked = os.path.basename(sys.argv[0]).lower()
    prog = "packhound" if invoked.startswith("packhound") or os.path.basename(os.path.dirname(sys.argv[0])) == "packhound" else "scs"
    ap = argparse.ArgumentParser(prog=prog, description="Packhound supply chain security scanner: inventory, CVEs, "
                                                         "malicious packages, runtimes, build chain.")
    ap.add_argument("--version", action="version", version=f"{prog} {__version__}")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def outputs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--out", help="report directory (default ~/.local/share/scs/reports)")
        p.add_argument("--format", default="html,json", help="comma list of html,json ('' for terminal only)")
        p.add_argument("--limit", type=int, default=15, help="max findings per bucket in the terminal")

    s = sub.add_parser("scan", help="inventory packages and look up advisories (read-only)")
    s.add_argument("--root", action="append", help="project folder to search for lockfiles/venvs (repeatable)")
    s.add_argument("--only", help="comma list of collectors (see `scs collectors`)")
    s.add_argument("--no-system", action="store_true", help="skip global installs (brew, interpreters, npm -g)")
    s.add_argument("--offline", action="store_true", help="use cached advisory data only; send nothing")
    s.add_argument("--nvd", action="store_true", help="match Homebrew formulae against NVD by CPE (slow, low confidence)")
    s.add_argument("--max-depth", type=int, help="directory depth under each root (default 7)")
    s.add_argument("--ioc-dir", action="append", help="extra directory of IOC pack JSON files")
    s.add_argument("--inventory", action="store_true", help="include the full package inventory in the JSON report")
    s.add_argument("--no-save", action="store_true", help="do not record this scan in history")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="exit 2 if a finding reaches this severity")
    outputs(s)
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="re-render a recorded scan")
    r.add_argument("--id", type=int, help="scan id (default: latest)")
    outputs(r)
    r.set_defaults(func=cmd_report)

    h = sub.add_parser("history", help="list recorded scans")
    h.add_argument("--limit", type=int, default=20)
    h.set_defaults(func=cmd_history)

    c = sub.add_parser("collectors", help="list collectors and whether they apply here")
    c.set_defaults(func=cmd_collectors)

    t = sub.add_parser("triage", help="decide per finding: patch now / verify first / defer / ignore")
    t.add_argument("--id", type=int, help="scan id (default: latest for this host)")
    t.add_argument("--all", action="store_true", help="revisit findings that already have a decision")
    t.add_argument("--bucket", action="append", choices=["respond", "patch", "verify", "monitor"],
                   help="only triage these buckets (repeatable)")
    t.add_argument("--auto", action="store_true", help="accept suggested actions without prompting (never ignores or defers)")
    t.add_argument("--policy", help=f"policy file for ignore rules (default {short_path(str(USER_POLICY))})")
    t.set_defaults(func=cmd_triage)

    pl = sub.add_parser("plan", help="build the dry-run patch plan from triage decisions")
    pl.add_argument("--id", type=int, help="scan id (default: latest for this host)")
    pl.add_argument("--only", help="comma list of decisions to include (default patch,verify,respond)")
    pl.add_argument("--suggested", action="store_true", help="also include untriaged findings using their suggested bucket")
    pl.add_argument("--outdated", action="store_true",
                    help="also update outdated Homebrew/winget/Chocolatey/Scoop/Snap/Flatpak packages (no CVE feed exists for them)")
    pl.add_argument("--migrate", action="store_true",
                    help="when a fix needs a newer Python, move that environment to one (pyenv; old env kept in backups)")
    pl.add_argument("--min-age", type=int, metavar="DAYS",
                    help="skip PyPI/npm releases younger than this (default: fix_min_age_days in the config, 7; 0 = off)")
    pl.add_argument("--out", help="output directory (default ~/.local/share/scs/plans)")
    pl.set_defaults(func=cmd_plan)

    ig = sub.add_parser("ignore", help="add an ignore rule (needs a reason; expires by default)")
    ig.add_argument("advisory", help="advisory id (GHSA-…, CVE-…, PYSEC-…) or * with --package")
    ig.add_argument("--package", help="limit to ecosystem:name, e.g. npm:qs or PyPI:requests")
    ig.add_argument("--version", help="limit to this installed version")
    ig.add_argument("--path", help="limit to locations matching this glob, e.g. '~/RnD/legacy/*'")
    ig.add_argument("--reason", required=True)
    ig.add_argument("--expires", default="90d", help="30d / 12w / 6m / YYYY-MM-DD (default 90d)")
    ig.add_argument("--project", action="store_true", help=f"write to ./{PROJECT_POLICY} instead of your user policy")
    ig.set_defaults(func=cmd_ignore)

    pa = sub.add_parser("patch", help="apply the plan target by target with snapshot, verify and automatic rollback")
    pa.add_argument("--plan", help="plan JSON (default: latest from `scs plan`)")
    pa.add_argument("--target", action="append", help="target number from the plan, e.g. 2 or target_2 (repeatable)")
    pa.add_argument("--all", action="store_true", help="every target in the plan, in order")
    pa.add_argument("--dry-run", action="store_true", help="run preflight only and show what would happen")
    pa.add_argument("--yes", action="store_true", help="do not ask per target (risky targets still need --accept-risk)")
    pa.add_argument("--accept-risk", action="store_true",
                    help="allow targets with toolchain warnings, no verification, or no rollback (Homebrew)")
    pa.add_argument("--no-rollback", action="store_true", help="keep the failed state instead of restoring the snapshot")
    pa.add_argument("--no-baseline", action="store_true", help="skip running verify commands before the change")
    pa.add_argument("--allow-dirty", action="store_true", help="patch projects with uncommitted manifest/lockfile changes")
    pa.add_argument("--force", action="store_true", help="apply even if some planned versions are no longer installed")
    pa.add_argument("--keep-going", action="store_true", help="continue with the next target after a rollback")
    pa.add_argument("--ignore-scripts", action="store_true", help="npm/yarn/pnpm: do not run install scripts while updating")
    pa.add_argument("--allow-sudo", action="store_true",
                    help="allow targets that need sudo (APT); asks for the password once, then runs `sudo -n`")
    pa.add_argument("--timeout", type=int, default=1800, help="seconds per command (default 1800)")
    pa.add_argument("--history", action="store_true", help="list previous patch runs")
    pa.set_defaults(func=cmd_patch)

    ve = sub.add_parser("verify", help="run only the plan's verification commands (no changes)")
    ve.add_argument("--plan")
    ve.add_argument("--target", action="append")
    ve.add_argument("--all", action="store_true")
    ve.add_argument("--timeout", type=int, default=1800)
    ve.set_defaults(func=cmd_verify)

    mw = sub.add_parser("malware", help="look for malicious install scripts, tampering, persistence and exposure")
    mw.add_argument("--root", action="append", help="project folder(s) for node_modules, venvs, git hooks, workflows")
    mw.add_argument("--only", help="comma list of checks: packages,integrity,signatures,persistence,extensions,engines,exposure")
    mw.add_argument("--integrity", choices=["code", "full", "off"], default="code",
                    help="pip RECORD verification: code files only (default), every file, or off")
    mw.add_argument("--yara-rules", action="append", help="extra directory of .yar/.yara rules (repeatable)")
    mw.add_argument("--path", action="append", help="extra file/dir for YARA/ClamAV (repeatable)")
    mw.add_argument("--no-downloads", action="store_true", help="do not include ~/Downloads in engine scans")
    mw.add_argument("--guarddog", action="store_true", help="also run GuardDog on packages with install hooks (slow)")
    mw.add_argument("--reputation", action="store_true",
                    help="opt-in: look up SHA-256 hashes (never files) on MalwareBazaar/VirusTotal; needs ABUSECH_AUTH_KEY / VT_API_KEY")
    mw.add_argument("--ioc-dir", action="append", help="extra directory of IOC pack JSON files")
    mw.add_argument("--no-baseline", action="store_true", help="do not update the persistence baseline")
    mw.add_argument("--all", action="store_true", help="also show informational items")
    mw.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="exit 2 at or above this severity")
    mw.add_argument("--out", help="report directory (default ~/.local/share/scs/reports)")
    mw.add_argument("--format", default="html,json", help="comma list of html,json ('' for terminal only)")
    mw.set_defaults(func=cmd_malware)

    qa = sub.add_parser("quarantine", help="move a suspicious file/dir aside (never deletes); list or restore")
    qa.add_argument("path", nargs="?")
    qa.add_argument("--reason", help="why (stored in the manifest)")
    qa.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    qa.add_argument("--list", action="store_true")
    qa.add_argument("--restore", metavar="ID")
    qa.set_defaults(func=cmd_quarantine)

    ex = sub.add_parser("export", help="bundle this machine's latest scan + malware results for `scs merge`")
    ex.add_argument("--out", help="file to write (default: stdout, e.g. for `ssh host scs export > host.json`)")
    ex.add_argument("--no-malware", action="store_true", help="leave out the latest malware scan")
    ex.set_defaults(func=cmd_export)

    me = sub.add_parser("merge", help="merge `scs export` bundles from several machines into a fleet report")
    me.add_argument("bundles", nargs="*", help="bundle JSON files")
    me.add_argument("--dir", action="append", help="directory of bundle JSON files (repeatable)")
    me.add_argument("--out", help="report directory (default ~/.local/share/scs/reports)")
    me.add_argument("--limit", type=int, default=15)
    me.set_defaults(func=cmd_merge)

    def watch_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--root", action="append", help="project folder(s) to include")
        p.add_argument("--malware", choices=["quick", "full", "none"], default="quick",
                       help="malware checks per run (quick = packages, build chain, persistence, extensions)")
        p.add_argument("--min-severity", choices=["critical", "high", "medium", "low"], default="high",
                       help="alert threshold for new findings (malicious/IOC and KEV always alert)")
        p.add_argument("--reputation", action="store_true", help="include opt-in hash reputation lookups")

    wa = sub.add_parser("watch", help="scan + malware check, alert only on what is new (for schedulers)")
    watch_args(wa)
    wa.add_argument("--no-notify", action="store_true", help="record alerts but do not send them")
    wa.add_argument("--test-alert", action="store_true", help="send a test message to the configured channels")
    wa.set_defaults(func=cmd_watch)

    al = sub.add_parser("alerts", help="list recent alerts")
    al.add_argument("--limit", type=int, default=20)
    al.set_defaults(func=cmd_alerts)

    sc = sub.add_parser("schedule", help="run `scs watch` periodically (launchd / systemd timer / Task Scheduler)")
    sc.add_argument("action", choices=["install", "print", "status", "remove"])
    sc.add_argument("--daily", metavar="HH:MM", help="every day at this time (default 09:00)")
    sc.add_argument("--weekly", nargs=2, metavar=("DAY", "HH:MM"), help="e.g. --weekly mon 09:00")
    sc.add_argument("--print", action="store_true", help="show what would be installed, change nothing")
    watch_args(sc)
    sc.set_defaults(func=cmd_schedule)

    ui = sub.add_parser("ui", help="open the graphical app (native window with pywebview, else your browser)")
    ui.add_argument("--browser", action="store_true", help="always use the default browser")
    ui.add_argument("--port", type=int, default=0, help="local port (default: random)")
    ui.add_argument("--no-open", action="store_true", help="only print the address")
    ui.set_defaults(func=cmd_ui)

    po = sub.add_parser("policy", help="list ignore rules")
    po.add_argument("--prune", action="store_true", help="delete expired rules")
    po.set_defaults(func=cmd_policy)

    from scs import fixers
    fixers.add_parser(sub)
    selfcheck.add_parser(sub)

    for name in PLANNED:
        p = sub.add_parser(name, help=f"(planned) {PLANNED[name]}")
        p.set_defaults(func=cmd_planned)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    set_verbose(args.verbose)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
