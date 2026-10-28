"""Local HTTP server for the GUI (standard library only).

Security model (this API can patch and quarantine):
  * binds to 127.0.0.1 on a random port
  * every /api and /report request needs the per-launch token (X-SCS-Token header,
    or ?token= for report frames); requests without it get 403
  * the Host header must be 127.0.0.1/localhost:<port> (blocks DNS-rebinding from websites)
  * no CORS headers are ever sent, so other origins cannot read responses
  * static files come only from scs/ui/static; reports are rendered on demand, not read from paths
"""
from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import subprocess
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from scs import __version__, history
from scs.ui import viewmodel as vm
from scs.ui.jobs import Busy, Job, JobManager
from scs.util import data_dir, host_id, read_json, write_json

STATIC = Path(__file__).resolve().parent / "static"
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon"}
APP_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'")
CONFIG = Path("~/.config/scs/config.json").expanduser()
SETTINGS_KEYS = ("roots", "notify", "alert_min_severity", "reputation", "offline", "nvd", "fix_min_age_days")


# ---------------------------------------------------------------- helpers shared by endpoints

def _latest_scan() -> Optional[dict]:
    return history.load(host=host_id())


def _latest_malware() -> Optional[dict]:
    p = data_dir() / "malware-latest.json"
    return read_json(p) if p.is_file() else None


def _read_config() -> dict:
    return read_json(CONFIG) if CONFIG.is_file() else {}


def pick_folder() -> Optional[str]:
    """Native folder chooser (works in browser mode too)."""
    system = platform.system()
    try:
        if system == "Darwin":
            r = subprocess.run(["osascript", "-e", 'POSIX path of (choose folder with prompt "Choose a projects folder for scs")'],
                               capture_output=True, text=True, timeout=600)
        elif system == "Windows":
            ps = ("Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; "
                  "if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }")
            r = subprocess.run(["powershell", "-NoProfile", "-STA", "-Command", ps], capture_output=True, text=True, timeout=600)
        elif shutil.which("zenity"):
            r = subprocess.run(["zenity", "--file-selection", "--directory"], capture_output=True, text=True, timeout=600)
        elif shutil.which("kdialog"):
            r = subprocess.run(["kdialog", "--getexistingdirectory", os.path.expanduser("~")], capture_output=True, text=True, timeout=600)
        else:
            return None
    except (OSError, subprocess.TimeoutExpired):
        return None
    path = r.stdout.strip().rstrip("/") if r.returncode == 0 else ""
    return path or None


def askpass_helper() -> str:
    """A SUDO_ASKPASS script that shows a graphical password prompt (Linux/macOS); '' if none available."""
    system = platform.system()
    d = data_dir() / "ui"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "askpass.sh"
    if system == "Darwin":
        body = ("#!/bin/sh\nosascript -e 'display dialog \"scs needs your password to install system updates.\" "
                "default answer \"\" with hidden answer with title \"Packhound\"' -e 'text returned of result'\n")
    elif shutil.which("zenity"):
        body = "#!/bin/sh\nzenity --password --title='scs needs your password to install system updates'\n"
    elif shutil.which("kdialog"):
        body = "#!/bin/sh\nkdialog --password 'scs needs your password to install system updates'\n"
    else:
        return ""
    p.write_text(body)
    p.chmod(0o700)
    return str(p)


# ---------------------------------------------------------------- application state / actions

class App:
    def __init__(self, folder_picker: Callable[[], Optional[str]] = pick_folder):
        self.jobs = JobManager()
        self.token = secrets.token_urlsafe(24)
        self.folder_picker = folder_picker
        self.last_plan: Optional[tuple[dict, str]] = None
        self._integrity: Optional[dict] = None  # scs's own integrity, checked once per session

    # ----- read
    def status(self) -> dict:
        scan, mw = _latest_scan(), _latest_malware()
        if mw:
            mw = {**mw, "counts": self.malware()["counts"]}  # without the items the user has since ignored
        cfg = _read_config()
        job = self.jobs.current
        return {"version": __version__, "host": host_id(), "platform": platform.system(),
                "health": vm.health(scan, mw), "scanned": scan.get("started") if scan else None,
                "malware_scanned": mw.get("started") if mw else None,
                "counts": vm.counts([vm.plain_finding(f) for f in scan["findings"]]) if scan else None,
                "malware_counts": (mw or {}).get("counts"), "roots": cfg.get("roots", []),
                "outdated": len((scan or {}).get("outdated", [])), "integrity": self.integrity(),
                "job": job.view(len(job.log)) if job else None}

    def integrity(self) -> dict:
        if self._integrity is None:
            from scs import selfcheck
            try:
                self._integrity = selfcheck.verify()
            except Exception as e:  # never block the app on the check itself
                self._integrity = {"ok": None, "how": "error", "detail": str(e)[:200]}
        return self._integrity

    def findings(self) -> dict:
        from scs.policy import Decisions
        scan = _latest_scan()
        if not scan:
            return {"items": [], "groups": vm.GROUPS, "scanned": None}
        decisions = Decisions()
        items = []
        for f in scan["findings"]:
            d = decisions.get(vm.finding_key(f), {a["id"] for a in f["advisories"]})
            items.append(vm.plain_finding({**f, "decision": d}))
        return {"items": items, "groups": vm.GROUPS, "scanned": scan["started"],
                "outdated": scan.get("outdated", [])}

    def malware(self) -> dict:
        from scs.malware import ignore
        mw = _latest_malware()
        if not mw:
            return {"items": [], "ignored": [], "scanned": None}
        # rules added or removed since that check apply right away, without a new check
        everything = mw["findings"] + [{k: v for k, v in m.items() if k != "ignore"} for m in mw.get("ignored", [])]
        shown, ignored = ignore.split(everything)
        counts = {s: sum(m["severity"] == s for m in shown) for s in ("critical", "high", "medium", "low", "info")}
        from scs.malware import actions
        return {"items": [{**vm.plain_malware(m), **actions.describe(m)} for m in shown], "scanned": mw["started"],
                "actions": [{**v, "path": vm.short_path(v["path"])} for v in map(actions.to_view, actions.history()[:50])],
                "ignored": [{**vm.plain_malware(m), "reason": m["ignore"]["reason"], "expires": m["ignore"]["expires"],
                             "added": m["ignore"]["added"]} for m in ignored],
                "counts": counts, "stats": mw.get("stats", {}),
                "exposure": [{**e, "path": vm.short_path(e.get("path", ""))} for e in mw.get("exposure", [])]}

    def malware_ignore(self, item_id: str, reason: str, expires: str = "90d") -> dict:
        from scs.malware import ignore
        from scs.policy import parse_expiry
        mw = _latest_malware() or {}
        f = next((m for m in mw.get("findings", []) if ignore.finding_id(m) == item_id), None)
        if not f:
            raise ValueError("item not found (run the check again?)")
        ignore.add(f, reason, "" if expires == "never" else parse_expiry(expires))
        return {"ok": True}

    def malware_act(self, item_id: str, action_id: str) -> dict:
        """Fix one reported item. Quick actions run now; ones that run a package manager become a job."""
        from scs.malware import actions, ignore
        mw = _latest_malware() or {}
        f = next((m for m in mw.get("findings", []) if ignore.finding_id(m) == item_id), None)
        if not f:
            raise ValueError("item not found (run the check again?)")
        act = next((a for a in actions.available(f) if a.id == action_id), None)
        if not act:
            raise ValueError("that action isn't available for this item any more")
        if act.slow:
            return {"job": self.jobs.start("fix", f"{act.label}: {f['title']}",
                                           lambda job: actions.to_view(actions.apply(f, action_id, job.append))).view()}
        return {"done": actions.to_view(actions.apply(f, action_id))}

    def malware_undo(self, record_id: str) -> dict:
        from scs.malware import actions
        return {"undone": actions.to_view(actions.undo(record_id))}

    def malware_unignore(self, item_id: str) -> dict:
        from scs.malware import ignore
        if not ignore.remove(item_id):
            raise ValueError("no such ignore rule")
        return {"ok": True}

    # ----- jobs
    def _cfg(self):
        from scs.config import load_config
        return load_config()

    def start_scan(self) -> Job:
        def run(job: Job):
            from scs.cli import _write_reports, perform_scan
            cfg = self._cfg()
            if not cfg.roots:
                job.append("No project folders chosen: scanning system-wide tools and apps only.")
            result = perform_scan(cfg)
            _write_reports(result, data_dir() / "reports", ["html"])
            b = result["summary"]["buckets"]
            return {"summary": b, "new": result["summary"]["new"]}
        return self.jobs.start("scan", "Scanning for vulnerable and malicious software", run)

    def start_malware(self, mode: str = "quick", reputation: bool = False) -> Job:
        def run(job: Job):
            from scs.malware import runner
            checks = runner.CHECKS if mode == "full" else ("packages", "buildchain", "persistence", "extensions", "exposure")
            if reputation:
                checks = tuple(checks) + ("reputation",)
            res = runner.run(self._cfg(), checks)
            (data_dir() / "malware-latest.json").write_text(json.dumps(res, default=str), encoding="utf-8")
            return {"counts": res["counts"]}
        title = "Full malware check" if mode == "full" else "Quick malware check"
        return self.jobs.start("malware", title, run)

    def triage(self, key: str, action: str, days: int = 14, reason: str = "", expires: str = "90d") -> dict:
        from scs.policy import Decisions, Policy, parse_expiry
        scan = _latest_scan()
        f = next((x for x in (scan or {}).get("findings", []) if vm.finding_key(x) == key), None)
        if not f:
            raise ValueError("finding not found (rescan?)")
        ids = [a["id"] for a in f["advisories"]]
        d = Decisions()
        if action == "ignore":
            if not reason.strip():
                raise ValueError("a reason is required to ignore an item")
            if any(a["malicious"] for a in f["advisories"]):
                raise ValueError("malicious items cannot be ignored from the app")
            for i in ids:
                Policy.add({"advisory": i, "package": f"{f['ecosystem']}:{f['name']}", "version": f["version"],
                            "reason": reason.strip(), "expires": parse_expiry(expires)})
            d.drop(key)
        elif action == "clear":
            d.drop(key)
        elif action in ("patch", "verify", "defer", "respond"):
            if action == "defer" and not 1 <= int(days) <= 365:
                raise ValueError("remind me in 1 day to 12 months")
            until = parse_expiry(f"{int(days)}d") if action == "defer" else ""
            d.set(key, action, ids, until=until)
        else:
            raise ValueError(f"unknown action {action}")
        d.save()
        return {"ok": True}

    def build_plan(self, include_check: bool = False, outdated: bool = False, keys: Optional[list[str]] = None,
                   migrate: bool = False) -> dict:
        """keys=None: everything decided or suggested; keys=[...]: exactly the items chosen on the Fix page."""
        from scs import plan as patch_plan
        from scs.policy import Decisions
        scan = _latest_scan()
        if not scan:
            raise ValueError("scan first")
        decisions = Decisions()
        if keys is not None:
            # an explicit pick on the Fix page wins over earlier choices (e.g. "remind me later")
            chosen = set(keys)
            scan = {**scan, "findings": [f for f in scan["findings"] if vm.finding_key(f) in chosen]}
            actions = ("patch", "verify", "respond")
            decisions = Decisions(Path(os.devnull))
        else:
            actions = ("patch", "verify", "respond") if include_check else ("patch", "respond")
        plan = patch_plan.build(scan, decisions, actions=actions, suggested=True, include_outdated=outdated, migrate=migrate)
        out_dir = data_dir() / "plans"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"plan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        write_json(path, plan)
        self.last_plan = (plan, str(path))
        return {"path": str(path), "targets": [_plain_target(n, t) for n, t in enumerate(plan["targets"], 1)],
                "untriaged": plan["untriaged"]}

    def start_patch(self, targets: list[int], accept_risk: bool = False) -> Job:
        if not self.last_plan:
            raise ValueError("build a plan first")
        plan, path = self.last_plan

        def run(job: Job):
            return self._execute(job, plan, path, sorted(targets), accept_risk)
        return self.jobs.start("patch", f"Updating {len(targets)} group(s)", run)

    def _execute(self, job: Job, plan: dict, path: str, targets: list[int], accept_risk: bool) -> dict:
        """Run plan targets (password / UAC prompts are graphical), then rescan and report what is left."""
        from scs import executor
        from scs.cli import _write_reports, perform_scan
        windows = platform.system() == "Windows"
        ask = "" if windows else askpass_helper()
        opts = executor.Options(yes=True, accept_risk=accept_risk, allow_sudo=windows or bool(ask), askpass=ask,
                                keep_going=True, out=job.append)  # groups are independent
        journal = executor.Runner(plan, path, opts).execute(targets)
        job.append("\nRefreshing results…")
        result = perform_scan(self._cfg())
        _write_reports(result, data_dir() / "reports", ["html"])
        left = [vm.plain_finding(f) for f in result["findings"] if f["bucket"] != "monitor"]
        return {"targets": [{"n": r["n"], "title": r["title"], "status": r["status"], "reason": r.get("reason", ""),
                             "still_vulnerable": r.get("still_vulnerable", [])} for r in journal["targets"]],
                "journal": journal.get("id"), "remaining": result["summary"]["buckets"],
                "left": [{"name": i["name"], "headline": i["headline"], "why": (i["notes"] or [i["action"]])[0]}
                         for i in left[:30]]}

    def start_fix_all(self, migrate: bool = False) -> Job:
        """One click: every finding with a fix (safe and check-first), each group verified and undone on failure."""
        def run(job: Job):
            from scs import plan as patch_plan
            from scs.policy import Decisions
            scan = _latest_scan()
            if not scan:
                raise ValueError("scan first")
            todo = [f for f in scan["findings"] if f["bucket"] in ("respond", "patch", "verify")]
            job.append(f"{len(todo)} item(s) have a fix; planning…")
            plan = patch_plan.build({**scan, "findings": todo}, Decisions(Path(os.devnull)),
                                    actions=("patch", "verify", "respond"), suggested=True, migrate=migrate)
            path = data_dir() / "plans" / f"plan-{datetime.now().strftime('%Y%m%d-%H%M%S')}-all.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            write_json(path, plan)
            return self._execute(job, plan, str(path), list(range(1, len(plan["targets"]) + 1)), accept_risk=True)
        return self.jobs.start("fix", "Fixing everything that can be fixed", run)

    def start_fix_safe(self) -> Job:
        """One click: every 'Safe to update' item, risk-free targets only, then rescan."""
        def run(job: Job):
            from scs import plan as patch_plan
            from scs.policy import Decisions
            scan = _latest_scan()
            if not scan:
                raise ValueError("scan first")
            # only what *this* scan classifies as safe: saved choices (which may predate newer
            # safety checks) are neither used nor created by this button
            safe = [f for f in scan["findings"] if f["bucket"] == "patch"]
            job.append(f"{len(safe)} item(s) are safe to update")
            plan = patch_plan.build({**scan, "findings": safe}, Decisions(Path(os.devnull)), actions=("patch",),
                                    suggested=True)
            path = data_dir() / "plans" / f"plan-{datetime.now().strftime('%Y%m%d-%H%M%S')}-safe.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            write_json(path, plan)
            return self._execute(job, plan, str(path), list(range(1, len(plan["targets"]) + 1)), accept_risk=False)
        return self.jobs.start("fix", "Fixing safe items", run)

    # ----- quarantine / settings / schedule
    def quarantine(self, path: str, reason: str) -> dict:
        from scs.malware import quarantine
        mw = _latest_malware() or {}
        if not any(m.get("path") == path for m in mw.get("findings", [])):
            raise ValueError("only items reported by the malware check can be quarantined from the app")
        m = quarantine.add(path, reason or "quarantined from the scs app")
        return {"id": m["id"], "path": m["original_path"]}

    def settings(self) -> dict:
        from scs import schedule
        cfg = _read_config()
        return {"config": {k: cfg.get(k) for k in SETTINGS_KEYS if k in cfg}, "config_path": str(CONFIG),
                "schedule": schedule.status(), "can_pick_folder": True}

    def save_settings(self, data: dict) -> dict:
        cfg = _read_config()
        for k in SETTINGS_KEYS:
            if k in data:
                cfg[k] = data[k]
        if "fix_min_age_days" in cfg:
            cfg["fix_min_age_days"] = max(0, min(90, int(cfg["fix_min_age_days"])))
        if "roots" in cfg:
            cfg["roots"] = [r for r in dict.fromkeys(cfg["roots"]) if r and os.path.isdir(os.path.expanduser(r))]
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        write_json(CONFIG, cfg)
        return {"ok": True, "config": {k: cfg.get(k) for k in SETTINGS_KEYS if k in cfg}}

    def schedule_action(self, action: str, daily: str = "09:00", weekly_day: str = "") -> dict:
        from scs import schedule
        if action == "remove":
            return {"messages": schedule.remove(), "status": schedule.status()}
        when = schedule.parse_when(None if weekly_day else daily, [weekly_day, daily] if weekly_day else None)
        roots = _read_config().get("roots", [])
        opts = []
        for r in roots:
            opts += ["--root", os.path.expanduser(r)]
        cmd = schedule.watch_command(opts + ["--malware", "quick"])
        if action == "preview":
            return {"preview": schedule.describe(cmd, when)}
        return {"messages": schedule.install(cmd, when), "status": schedule.status()}


def _plain_target(n: int, t: dict) -> dict:
    risky = bool(t["warnings"]) or t["kind"] in ("brew", "apt", "winget", "choco", "flatpak") or not t["verify"]
    return {"n": n, "title": t["title"], "kind": t["kind"], "packages": [f"{p['name']} {p['from']} → {p['to'] or 'remove'}"
                                                                         for p in t["packages"]],
            "warnings": t["warnings"], "notes": t["manual"][:6], "risky": risky, "has_changes": any(
                c.strip() and not c.lstrip().startswith(("#", "rem ")) for c in t["change"]),
            "commands": t["change"], "verify": t["verify"]}


# ---------------------------------------------------------------- HTTP plumbing

class Handler(BaseHTTPRequestHandler):
    server_version = "scs-ui"
    app: App
    port: int

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: Optional[dict] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: Any) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    def _token_ok(self, query: dict) -> bool:
        tok = self.headers.get("X-SCS-Token") or (query.get("token") or [""])[0]
        return secrets.compare_digest(tok, self.app.token)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        if not self._host_ok():
            return self._send(403, b"forbidden host", "text/plain")
        url = urlparse(self.path)
        query = parse_qs(url.query)
        path = url.path
        if not path.startswith(("/api/", "/report/")):
            if method != "GET":
                return self._send(405, b"", "text/plain")
            return self._static(path)
        if not self._token_ok(query):
            return self._json(403, {"error": "missing or wrong token"})
        try:
            if path.startswith("/report/"):
                return self._report(path.rsplit("/", 1)[-1])
            data = self._body() if method == "POST" else {}
            return self._json(200, self._api(method, path, data, query))
        except Busy as e:
            return self._json(409, {"error": str(e)})
        except (ValueError, KeyError, OSError, RuntimeError) as e:  # OSError: file not found, permission, exists…
            return self._json(400, {"error": str(e)})

    def _static(self, path: str) -> None:
        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        target = (STATIC / name).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file():  # no path traversal out of static/
            return self._send(404, b"not found", "text/plain")
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        extra = {"Content-Security-Policy": APP_CSP} if target.suffix == ".html" else {}
        self._send(200, target.read_bytes(), ctype, extra)

    def _report(self, which: str) -> None:
        from scs.report import html as html_report
        from scs.report import malware as mreport
        if which == "scan":
            scan = _latest_scan()
            body = html_report.render(scan) if scan else "<p>No scan yet.</p>"
        elif which == "malware":
            mw = _latest_malware()
            body = mreport.render_html(mw) if mw else "<p>No malware check yet.</p>"
        else:
            return self._send(404, b"", "text/plain")
        csp = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'self'"
        self._send(200, body.encode(), "text/html; charset=utf-8", {"Content-Security-Policy": csp})

    def _api(self, method: str, path: str, data: dict, query: dict) -> Any:
        app = self.app
        routes: dict[tuple[str, str], Callable[[], Any]] = {
            ("GET", "/api/status"): app.status,
            ("GET", "/api/findings"): app.findings,
            ("GET", "/api/malware"): app.malware,
            ("GET", "/api/settings"): app.settings,
            ("GET", "/api/quarantine"): lambda: __import__("scs.malware.quarantine", fromlist=["x"]).listing(),
            ("POST", "/api/scan"): lambda: app.start_scan().view(),
            ("POST", "/api/malware"): lambda: app.start_malware(data.get("mode", "quick"), bool(data.get("reputation"))).view(),
            ("POST", "/api/triage"): lambda: app.triage(data["key"], data["action"], int(data.get("days", 14)),
                                                         data.get("reason", ""), data.get("expires", "90d")),
            ("POST", "/api/plan"): lambda: app.build_plan(bool(data.get("include_check")), bool(data.get("outdated")),
                                                          data.get("keys"), bool(data.get("migrate"))),
            ("POST", "/api/patch"): lambda: app.start_patch([int(x) for x in data["targets"]], bool(data.get("accept_risk"))).view(),
            ("POST", "/api/fix-safe"): lambda: app.start_fix_safe().view(),
            ("POST", "/api/fix-all"): lambda: app.start_fix_all(bool(data.get("migrate"))).view(),
            ("POST", "/api/malware/ignore"): lambda: app.malware_ignore(data["id"], data.get("reason", ""),
                                                                        data.get("expires", "90d")),
            ("POST", "/api/malware/unignore"): lambda: app.malware_unignore(data["id"]),
            ("POST", "/api/malware/act"): lambda: app.malware_act(data["id"], data["action"]),
            ("POST", "/api/malware/undo"): lambda: app.malware_undo(data["id"]),
            ("POST", "/api/quarantine"): lambda: app.quarantine(data["path"], data.get("reason", "")),
            ("POST", "/api/quarantine/restore"): lambda: __import__("scs.malware.quarantine", fromlist=["x"]).restore(data["id"]),
            ("POST", "/api/settings"): lambda: app.save_settings(data),
            ("POST", "/api/schedule"): lambda: app.schedule_action(data["action"], data.get("daily", "09:00"),
                                                                   data.get("weekly_day", "")),
            ("POST", "/api/pick-folder"): lambda: {"path": app.folder_picker()},
            ("POST", "/api/notify/test"): lambda: _test_alert(),
            ("POST", "/api/open"): lambda: _open_external(data["url"]),
        }
        if method == "POST" and path.startswith("/api/jobs/") and path.endswith("/cancel"):
            return app.jobs.cancel(path.split("/")[3]).view(10**9)
        if method == "GET" and path.startswith("/api/jobs/"):
            job = app.jobs.get(path.rsplit("/", 1)[-1])
            if not job:
                raise KeyError("no such job")
            return job.view(int((query.get("since") or ["0"])[0]))
        fn = routes.get((method, path))
        if not fn:
            raise KeyError(f"unknown endpoint {method} {path}")
        return fn()


def _open_external(url: str) -> dict:
    """Open advisory links in the system browser (https only) instead of inside the app window."""
    import webbrowser
    if not url.startswith("https://"):
        raise ValueError("only https links can be opened")
    webbrowser.open(url)
    return {"ok": True}


def _test_alert() -> dict:
    from scs import notify
    from scs.config import load_config
    cfg = load_config()
    if not cfg.notify:
        raise ValueError("no notification channels configured")
    return notify.send(notify.Alert(host=host_id(), title="scs test alert", severity="low",
                                    lines=["If you can read this, alert delivery works."]), cfg.notify)


def serve(app: Optional[App] = None, port: int = 0) -> tuple[ThreadingHTTPServer, App, str]:
    """Start the server in a background thread; returns (server, app, url-with-token)."""
    app = app or App()
    handler = type("BoundHandler", (Handler,), {"app": app})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    handler.port = httpd.server_port
    threading.Thread(target=httpd.serve_forever, daemon=True, name="scs-ui-http").start()
    return httpd, app, f"http://127.0.0.1:{httpd.server_port}/#token={app.token}"
