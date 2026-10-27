"""Execute a patch plan target by target: preflight → baseline verify → snapshot →
apply → verify → post-update checks → (rollback on regression).

Safety rules:
  * one target at a time, each confirmed (or --yes); risky targets need --accept-risk
  * never runs sudo; never runs a plan whose versions no longer match what is installed
  * a verify command only counts as a regression if it passed before the change
  * after an update, install-time code of the changed packages is re-checked with the
    malware rules; a critical/high hit rolls the target back
  * rollback restores the on-disk snapshot (offline, exact); failed state is kept
Every step is journaled to ~/.local/share/scs/runs/<run-id>/journal.json with logs.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from scs import shell, snapshot
from scs.windows import is_admin
from scs.collectors import lockfiles
from scs.models import normalize_name
from scs.util import data_dir, read_json, run, write_json

SUDO_RE = re.compile(r"(^|&&\s*|;\s*|\|\|\s*|\|\s*)sudo\s+(?!-n\b)")
PHASES = ("preflight", "baseline", "snapshot", "apply", "verify", "postcheck", "rollback")
CMD_ENV = {"npm_config_fund": "false", "npm_config_audit": "false", "npm_config_update_notifier": "false",
           "PIP_DISABLE_PIP_VERSION_CHECK": "1", "HOMEBREW_NO_ENV_HINTS": "1", "GOTOOLCHAIN": "local"}


@dataclass
class Options:
    yes: bool = False
    accept_risk: bool = False
    dry_run: bool = False
    rollback: bool = True
    baseline_verify: bool = True
    allow_dirty: bool = False
    force: bool = False
    keep_going: bool = False
    ignore_scripts: bool = False
    allow_sudo: bool = False
    askpass: str = ""  # GUI: SUDO_ASKPASS helper that shows a graphical password prompt
    timeout: int = 1800
    ask: Callable[[str], str] = input
    out: Callable[[str], None] = print


@dataclass
class Run:
    id: str
    dir: Path
    plan_path: str
    journal: dict = field(default_factory=dict)

    def save(self) -> None:
        write_json(self.dir / "journal.json", self.journal)


def runs_dir() -> Path:
    p = data_dir() / "runs"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------- inspection helpers

def _segments(cmd: str, dialect: str = "sh") -> list[list[str]]:
    try:
        tokens = shell.by_name(dialect).split(cmd)
    except ValueError:
        tokens = cmd.split()
    segs, cur = [], []
    for t in tokens:
        if t in ("&&", "||", ";", "|"):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def missing_tools(cmds: list[str], dialect: str = "sh") -> list[str]:
    missing = []
    for c in cmds:
        for seg in _segments(c, dialect):
            while seg and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0]) or seg[0] in ("env", "time", "nice", "sudo")
                           or (seg[0].startswith("-") and len(seg) > 1)):
                seg = seg[1:]  # VAR=value prefixes, wrappers (sudo -n …) and their flags are not the tool
            if not seg:
                continue
            exe = seg[0].lstrip("(")  # `a && (b || c)` groups
            if not exe:
                continue
            if exe.lower() in ("cd", "echo", "export", ":", "true", "test", "[", "rem", "set", "if", "copy", "mkdir", "("):
                continue
            ok = os.path.exists(exe) if "/" in exe else shutil.which(exe) is not None
            if not ok and exe not in missing:
                missing.append(exe)
    return missing


def uses_sudo(cmds: list[str], dialect: str = "sh") -> bool:
    return any(seg and seg[0] in ("sudo", "doas") for c in cmds for seg in _segments(c, dialect))


def current_versions(target: dict) -> dict[str, set[str]]:
    """What is installed now for the packages this target touches (normalized name -> versions)."""
    out: dict[str, set[str]] = {}
    eco = target["packages"][0]["ecosystem"] if target["packages"] else ""

    def add(name: str, version: str, e: str = eco) -> None:
        out.setdefault(normalize_name(e, name), set()).add(version)

    kind = target["kind"]
    if kind == "pip":
        from scs.collectors.python import scan_site
        for p in scan_site(Path(target["meta"]["site"]), "global"):
            add(p.name, p.version, "PyPI")
    elif kind == "py-migrate":
        from scs.collectors.python import scan_site
        for site in target["meta"].get("sites", []):
            if Path(site).is_dir():  # gone once the environment has been retired
                for p in scan_site(Path(site), "global"):
                    add(p.name, p.version, "PyPI")
    elif kind == "npm-global":
        from scs.collectors.node import walk_node_modules
        found: list = []
        walk_node_modules(Path(target["id"]), target["id"], [], set(), found)
        for p in found:
            add(p.name, p.version, "npm")
    elif kind == "project":
        d = Path(target["id"])
        for name in {p.get("lockfile") for p in target["packages"] if p.get("lockfile")}:
            parser = lockfiles.parser_for(name)
            if parser and (d / name).is_file():
                pkgs, _ = parser(d / name)
                for p in pkgs:
                    add(p.name, p.version, p.ecosystem)
    elif kind == "apt":
        from scs.collectors import dpkg
        pkgs, _ = dpkg.collect_status(None, dpkg.DPKG_STATUS.read_text(errors="replace"), eco)
        for p in pkgs:
            add(p.name, p.version)
    elif kind == "brew":
        names = sorted({p["name"] for p in target["packages"]})
        res = run(["brew", "list", "--versions", *names], timeout=120) or ""
        for line in res.splitlines():
            parts = line.split()
            for v in parts[1:]:
                add(parts[0], re.sub(r"_\d+$", "", v), "Homebrew")
    elif kind in ("winget", "choco"):
        from scs.collectors import windows as w
        if kind == "winget":
            pk = w.winget_packages(run(["winget", "list", "--disable-interactivity"], timeout=180) or "", "")
        else:
            pk = w.choco_packages(run(["choco", "list", "--limit-output"], timeout=180) or "", "")
        for p in pk:
            add(p.name, p.version, p.ecosystem)
    elif kind == "scoop":
        from scs.collectors import windows as w
        for p in w.scoop_packages([Path(target["id"])] if Path(target["id"], "apps").is_dir() else w.scoop_roots()):
            add(p.name, p.version, "scoop")
    elif kind == "snap":
        from scs.collectors.snap import parse_snap_list
        for r in parse_snap_list(run(["snap", "list", "--unicode=never"], timeout=60) or ""):
            add(r["name"], r["version"], "Snap")
    elif kind == "cargo":
        from scs.collectors.cargo import _collect, _path
        if _path().is_file():
            for p in _collect(None):
                add(p.name, p.version, "crates.io")
    return out


def still_vulnerable(target: dict, versions: dict[str, set[str]]) -> list[str]:
    left = []
    for p in target["packages"]:
        if p["from"] in versions.get(normalize_name(p["ecosystem"], p["name"]), set()):
            left.append(f"{p['name']} {p['from']}")
    return left


def stale_packages(target: dict, versions: dict[str, set[str]]) -> list[str]:
    return [f"{p['name']} (planned from {p['from']}, installed: {', '.join(sorted(versions.get(normalize_name(p['ecosystem'], p['name']), set()))) or 'none'})"
            for p in target["packages"]
            if p["from"] not in versions.get(normalize_name(p["ecosystem"], p["name"]), set())]


def _dirty_files(target: dict) -> list[str]:
    if target["kind"] != "project":
        return []
    d = Path(target["id"])
    if not any((p / ".git").exists() for p in [d, *d.parents]):
        return []
    files = [f for f in snapshot.MANIFESTS if (d / f).is_file()]
    out = run(["git", "-C", str(d), "status", "--porcelain", "--", *files], timeout=30) or ""
    return [ln[3:] for ln in out.splitlines() if ln.strip()]


def post_update_malware(target: dict) -> list[str]:
    """Re-check install-time code of what was just installed (critical/high only)."""
    from scs.enrich import ioc
    from scs.malware import packages as mpk
    ind = ioc.malware_indicators(ioc.load_packs([]))
    roots = []
    if target["kind"] == "project" and (Path(target["id"]) / "node_modules").is_dir():
        roots.append(Path(target["id"]) / "node_modules")
    if target["kind"] == "npm-global":
        roots.append(Path(target["id"]))
    bad = []
    if roots:
        findings, _ = mpk.scan_node_trees(roots, ind["filenames"], ind["sha256"])
        bad += [f"{f.title} ({f.path})" for f in findings if f.severity in ("critical", "high")]
    if target["kind"] == "pip":
        findings, _ = mpk.scan_site_packages([Path(target["meta"]["site"])])
        bad += [f"{f.title}" for f in findings if f.severity in ("critical", "high")]
    return bad


# ---------------------------------------------------------------- execution

class Runner:
    def __init__(self, plan: dict, plan_path: str, opts: Options):
        self.plan = plan
        self.opts = opts
        rid = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.run = Run(rid, runs_dir() / rid, plan_path)
        self.run.dir.mkdir(parents=True, exist_ok=True)
        (self.run.dir / "logs").mkdir(exist_ok=True)
        self.run.journal = {"id": rid, "plan": plan_path, "started": datetime.now().isoformat(timespec="seconds"),
                            "dry_run": opts.dry_run, "targets": []}
        self.env = {**os.environ, **CMD_ENV, "DEBIAN_FRONTEND": "noninteractive"}
        from scs import fixers
        self.env["PYTHONPATH"] = os.pathsep.join(x for x in (fixers.package_parent(), os.environ.get("PYTHONPATH")) if x)
        if opts.ignore_scripts:
            self.env["npm_config_ignore_scripts"] = "true"
        self.sudo_ready = False
        self.dialect = plan.get("shell", "sh")

    def _sudo_login(self) -> bool:
        """Ask for the sudo password once, in the foreground; commands then use `sudo -n` (never prompt)."""
        if self.sudo_ready:
            return True
        self.opts.out("   sudo: authenticating once for this run")
        if self.opts.askpass:
            env = {**os.environ, "SUDO_ASKPASS": self.opts.askpass}
            self.sudo_ready = subprocess.run(["sudo", "-A", "-v"], env=env, stdin=subprocess.DEVNULL).returncode == 0
        else:
            self.sudo_ready = subprocess.run(["sudo", "-v"]).returncode == 0
        return self.sudo_ready

    def _cmd(self, n: int, phase: str, k: int, cmd: str, backup: Path, elevate: bool = False) -> tuple[int, str, float]:
        if self.dialect == "sh":
            cmd = SUDO_RE.sub(r"\1sudo -n ", cmd)  # never block on a password prompt with stdin closed
        log = self.run.dir / "logs" / f"t{n}-{phase}-{k}.log"
        if elevate:
            cmd = self._elevated(cmd, log, backup)
        t0 = time.time()
        with open(log, "w") as f:
            f.write(f"$ {cmd}\n\n")
            f.flush()
            try:
                # cmd.exe: pass one string (list2cmdline would escape quotes as \" which cmd does not
                # understand); /s strips exactly the outer quotes we add and runs the rest verbatim
                argv = f'cmd /d /s /c "{cmd}"' if self.dialect == "cmd" else ["bash", "-o", "pipefail", "-c", cmd]
                r = subprocess.run(argv, stdout=f, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, env={**self.env, "BACKUP": str(backup)},
                                   timeout=self.opts.timeout)
                rc = r.returncode
            except subprocess.TimeoutExpired:
                f.write(f"\n[scs] timed out after {self.opts.timeout}s\n")
                rc = 124
        return rc, str(log), round(time.time() - t0, 1)

    def _elevated(self, cmd: str, log: Path, backup: Path) -> str:
        """Windows: run `cmd` in an Administrator process (one UAC prompt) and wait for it.

        The elevated process writes its output next to our log; we print it into the log afterwards.
        """
        bat = log.with_suffix(".cmd")
        out = log.with_suffix(".elevated.log")
        bat.write_text("@echo off\r\n"
                       f'set "BACKUP={backup}"\r\n'
                       f'set "PYTHONPATH={self.env.get("PYTHONPATH", "")}"\r\n'
                       f'cd /d "{Path.home()}"\r\n'
                       f'({cmd}) > "{out}" 2>&1\r\n'
                       "exit /b %ERRORLEVEL%\r\n", encoding="utf-8")
        ps = (f"$p = Start-Process -FilePath '{bat}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; "
              f"if (Test-Path '{out}') {{ Get-Content '{out}' }}; exit $p.ExitCode")
        return f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{ps}"'

    @staticmethod
    def _tail(log: str, n: int = 12) -> str:
        try:
            lines = Path(log).read_text(errors="replace").splitlines()
        except OSError:
            return ""
        return "\n".join("      " + ln for ln in lines[-n:])

    def _step(self, rec: dict, phase: str, **kw) -> dict:
        s = {"phase": phase, "at": datetime.now().isoformat(timespec="seconds"), **kw}
        rec["steps"].append(s)
        self.run.save()
        return s

    def execute(self, selected: list[int]) -> dict:
        say = self.opts.out
        targets = self.plan["targets"]
        for n in selected:
            t = targets[n - 1]
            rec = {"n": n, "title": t["title"], "kind": t["kind"], "status": "pending", "steps": [],
                   "packages": [f"{p['name']} {p['from']} → {p['to'] or 'remove'}" for p in t["packages"]]}
            self.run.journal["targets"].append(rec)
            say(f"\n== target_{n}: {t['title']} ({len(t['packages'])} package change(s))")
            try:
                ok = self._target(n, t, rec)
            except KeyboardInterrupt:
                say("   interrupted")
                rec["status"] = "interrupted"
                if rec.get("snapshot"):
                    self._rollback(n, t, rec, "interrupted by user")
                self.run.save()
                break
            self.run.save()
            if not ok and not self.opts.keep_going and rec["status"] in ("rolled_back", "rollback_failed", "failed"):
                say("   stopping (use --keep-going to continue with the next target)")
                break
        self.run.journal["finished"] = datetime.now().isoformat(timespec="seconds")
        self.run.save()
        return self.run.journal

    def _target(self, n: int, t: dict, rec: dict) -> bool:
        say, opts = self.opts.out, self.opts
        backup = self.run.dir / "backups" / f"t{n}"
        changes = [c for c in t["change"] if c.strip() and not c.lstrip().startswith("#")]
        verifies = [c for c in t["verify"] if c.strip() and not c.lstrip().startswith("#")]

        # ---- preflight
        problems: list[str] = []
        risks: list[str] = []
        if not changes:
            # say *why* there is nothing to run (OS-managed Python, tool has no compatible release yet, …)
            why = (t["warnings"] or t["manual"] or ["nothing to apply (all steps are manual or skipped)"])[0]
            problems.append(why)
        needs_sudo = uses_sudo(changes + verifies, self.dialect)
        elevate = bool(t.get("elevate") or t["kind"] == "choco") and self.dialect == "cmd" and not is_admin()
        if elevate and not opts.allow_sudo:
            problems.append("needs Administrator rights: re-run with --allow-sudo (Windows asks for approval once per step)")
        if needs_sudo and not opts.allow_sudo:
            problems.append("needs sudo: re-run with --allow-sudo (you will be asked for your password once)")
        miss = missing_tools(changes, self.dialect)
        if miss:
            problems.append(f"tools not found: {', '.join(miss)}")
        miss_v = missing_tools(verifies, self.dialect)
        if miss_v:
            verifies = [c for c in verifies if not set(missing_tools([c], self.dialect)) & set(miss_v)]
            risks.append(f"verify tools not installed, those checks are skipped: {', '.join(miss_v)}")
        if t["kind"] == "apt":
            from scs.collectors import dpkg
            if not dpkg.DPKG_STATUS.is_file():
                problems.append("this is not a dpkg-based system (plan made on another machine?)")
                rec["status"] = "skipped"
                self._step(rec, "preflight", problems=problems, risks=risks, stale=[])
                for p in problems:
                    say(f"   skip: {p}")
                return True
        versions = current_versions(t) if t["packages"] else {}
        stale = stale_packages(t, versions)
        if stale and len(stale) == len(t["packages"]):
            problems.append("already changed since the plan was made: " + "; ".join(stale[:4]))
        elif stale and not opts.force:
            problems.append("plan is stale for: " + "; ".join(stale[:4]) + " (re-run scs plan, or --force)")
        dirty = _dirty_files(t)
        if dirty and not opts.allow_dirty:
            problems.append(f"uncommitted changes in {', '.join(dirty[:5])} (commit/stash first, or --allow-dirty)")
        if t["warnings"]:
            risks += t["warnings"]
        if t["kind"] == "brew":
            risks.append("Homebrew upgrades cannot be rolled back automatically")
        if t["kind"] in ("winget", "choco", "flatpak"):
            risks.append(f"{t['kind']} rollback is best-effort (reinstalls the previous version if still published)")
        if t["kind"] == "apt":
            risks.append("APT rollback is best-effort (downgrade to recorded versions while the old .debs are available)")
        if not verifies:
            risks.append("no verification commands: a breaking change would not be detected")
        self._step(rec, "preflight", problems=problems, risks=risks, stale=stale)
        if problems:
            rec["status"] = "skipped"
            rec["reason"] = problems[0]
            for p in problems:
                say(f"   skip: {p}")
            return True
        for r in risks:
            say(f"   ! {r}")
        say("   will run:")
        for c in changes:
            say(f"     $ {c}")

        # ---- confirmation
        if opts.dry_run:
            rec["status"] = "dry-run"
            say(f"   verify: {len(verifies)} command(s); snapshot: {t['kind']}; dry run, nothing executed")
            return True
        if risks and not opts.accept_risk and opts.yes:
            rec["status"] = "skipped"
            rec["reason"] = "needs review: " + risks[0]
            say("   skip: has risks; review them and re-run with --accept-risk")
            return True
        if not opts.yes or (risks and not opts.accept_risk):
            ans = opts.ask(f"   apply target_{n}? [y/N/q] ").strip().lower()
            if ans == "q":
                rec["status"] = "skipped"
                raise KeyboardInterrupt
            if ans != "y":
                rec["status"] = "skipped"
                say("   skipped")
                return True

        if needs_sudo and not self._sudo_login():
            rec["status"] = "skipped"
            say("   skip: sudo authentication failed")
            return True

        # ---- baseline verify
        baseline: dict[str, int] = {}
        baseline_logs: dict[str, str] = {}
        if opts.baseline_verify and verifies:
            say(f"   baseline: running {len(verifies)} verify command(s) before changing anything")
            for k, c in enumerate(verifies):
                rc, log, secs = self._cmd(n, "baseline", k, c, backup)
                baseline[c], baseline_logs[c] = rc, log
                self._step(rec, "baseline", cmd=c, rc=rc, log=log, seconds=secs)
                say(f"     {'pass' if rc == 0 else 'FAIL (already failing before the change)'}  {c}")

        # ---- snapshot
        say("   snapshot…")
        state = snapshot.take(t, backup)
        rec["snapshot"] = state
        for k, c in enumerate(cmd for cmd in t["backup"] if not re.search(r"\bgit\b.*\b(switch|checkout)\b", cmd)):
            rc, log, _ = self._cmd(n, "backup", k, c, backup)  # plan's own records (freeze lists etc.), best effort
            self._step(rec, "snapshot", cmd=c, rc=rc, log=log)
        self._step(rec, "snapshot", state=state)

        # ---- apply
        for k, c in enumerate(changes):
            say(f"   apply: {c}")
            rc, log, secs = self._cmd(n, "apply", k, c, backup, elevate)
            self._step(rec, "apply", cmd=c, rc=rc, log=log, seconds=secs)
            if rc != 0 and _network_error(log):
                # DNS/VPN blips are common (and installs are idempotent): one retry before undoing
                say(f"   network problem ({_network_error(log)}); retrying in {NETWORK_RETRY_DELAY}s…")
                time.sleep(NETWORK_RETRY_DELAY)
                rc, log, secs = self._cmd(n, "apply-retry", k, c, backup, elevate)
                self._step(rec, "apply", cmd=c, rc=rc, log=log, seconds=secs, retry=True)
            if rc != 0:
                say(f"   command failed (exit {rc}):\n{self._tail(log)}")
                net = _network_error(log)
                reason = f"network problem: {net}. Check your internet/VPN and try again" if net else \
                    f"apply command failed: {_error_line(log) or c}"
                return self._rollback(n, t, rec, reason)

        # ---- verify
        regressions, still_failing = [], []
        for k, c in enumerate(verifies):
            rc, log, secs = self._cmd(n, "verify", k, c, backup)
            self._step(rec, "verify", cmd=c, rc=rc, log=log, seconds=secs)
            before = baseline.get(c)
            if rc == 0:
                say(f"     pass  {c}")
            elif before not in (None, 0) and _new_problems(baseline_logs.get(c, ""), log, c):
                # consistency checks (pip check, npm ls) list each problem: one that is new is a regression
                regressions.append(c)
                say(f"     FAIL  {c}  (new problems: {'; '.join(_new_problems(baseline_logs[c], log, c)[:3])})")
            elif before not in (None, 0):
                still_failing.append(c)
                say(f"     fail  {c}  (was already failing: not counted)")
            else:
                regressions.append(c)
                say(f"     FAIL  {c}\n{self._tail(log)}")
        if regressions:
            return self._rollback(n, t, rec, f"verification regressed: {regressions[0]}")

        # ---- post-update checks
        bad = post_update_malware(t)
        left = still_vulnerable(t, current_versions(t))
        self._step(rec, "postcheck", malware=bad, still_vulnerable=left, still_failing=still_failing)
        if bad:
            say("   install-time code of the updated packages looks malicious:")
            for b in bad[:5]:
                say(f"     ! {b}")
            return self._rollback(n, t, rec, "post-update malware check failed")
        rec["status"] = "partial" if left else "applied"
        rec["still_vulnerable"] = left
        if left:
            names = {x.rsplit(" ", 1)[0] for x in left}
            why = next((m for m in t["manual"] if m.split(" ", 1)[0] in names), "")
            rec["reason"] = f"still vulnerable: {', '.join(left[:4])}" + (f" ({why})" if why else "")
        if left:
            say(f"   applied, but still vulnerable: {', '.join(left[:6])} (a parent pins it, or no compatible fix)")
        else:
            say("   applied and verified")
        return True

    def _plan_rollback(self, n: int, t: dict, backup: Path) -> list[str]:
        """Package managers that keep (scoop, snap) or can reinstall (winget, choco) the previous version."""
        cmds = [c for c in t["rollback"] if c.strip() and not c.lstrip().startswith(("#", "rem "))]
        if not cmds:
            raise snapshot.SnapshotError("no rollback commands in the plan")
        elevate = bool(t.get("elevate")) and self.dialect == "cmd" and not is_admin()
        for k, c in enumerate(cmds):
            rc, log, _ = self._cmd(n, "rollback", k, c, backup, elevate)
            if rc != 0:
                raise snapshot.SnapshotError(f"rollback command failed (exit {rc}): {c}\n{self._tail(log)}")
        return [f"ran {len(cmds)} rollback command(s) from the plan"]

    def _rollback(self, n: int, t: dict, rec: dict, reason: str) -> bool:
        say = self.opts.out
        rec["reason"] = reason
        if not self.opts.rollback:
            rec["status"] = "failed"
            say(f"   NOT rolling back (--no-rollback). Snapshot kept in {self.run.dir / 'backups' / f't{n}'}")
            self._step(rec, "rollback", skipped=True, reason=reason)
            return False
        state = rec.get("snapshot") or {}
        backup = self.run.dir / "backups" / f"t{n}"
        say(f"   rolling back: {reason}")
        try:
            if state.get("via") == "plan-rollback":
                notes = self._plan_rollback(n, t, backup)
            else:
                notes = snapshot.restore(t, state, backup)
        except Exception as e:
            rec["status"] = "rollback_failed"
            self._step(rec, "rollback", ok=False, error=str(e))
            say(f"   ROLLBACK FAILED: {e}\n   Manual rollback from the plan:")
            for c in t["rollback"]:
                say(f"     $ {c}")
            return False
        self._step(rec, "rollback", ok=True, notes=notes)
        for note in notes:
            say(f"     {note}")
        recheck = []
        for k, c in enumerate(c for c in t["verify"] if c.strip() and not c.lstrip().startswith("#")):
            rc, log, _ = self._cmd(n, "rollback-verify", k, c, backup)
            recheck.append({"cmd": c, "rc": rc})
        self._step(rec, "rollback", verify=recheck)
        rec["status"] = "rolled_back"
        say(f"   rolled back; previous state restored (failed state kept in {backup / 'failed-state'})")
        return False


# ---------------------------------------------------------------- plan loading / history

NETWORK_RETRY_DELAY = 8
_NETWORK = re.compile(r"(ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|ECONNREFUSED|getaddrinfo|Temporary failure in name resolution"
                      r"|Name or service not known|nodename nor servname|NewConnectionError|Max retries exceeded"
                      r"|Could not resolve host|Connection timed out|Network is unreachable|ConnectTimeoutError"
                      r"|Read timed out|connection broken by)[^\n]{0,80}")


def _new_problems(before_log: str, after_log: str, cmd: str) -> list[str]:
    """Problem lines a deterministic consistency check reports now but did not report before the change."""
    if not re.search(r"\bpip check\b|\bnpm(\.cmd)? ls\b", cmd):
        return []

    def lines(path: str) -> set[str]:
        try:
            return {ln.strip() for ln in Path(path).read_text(errors="replace").splitlines()[1:] if ln.strip()}
        except OSError:
            return set()
    return sorted(lines(after_log) - lines(before_log))


def _network_error(log: str) -> str:
    """Short description if a command failed for network reasons (worth one retry), else ''."""
    try:
        text = Path(log).read_text(errors="replace")[-20000:]
    except OSError:
        return ""
    m = _NETWORK.search(text)
    if not m:
        return ""
    host = re.search(r"(?:to |host:? |://)([a-z0-9.-]+\.[a-z]{2,})", m.group(0) + text[m.end():m.end() + 200], re.I)
    return f"could not reach {host.group(1)}" if host else m.group(1)


def _error_line(log: str) -> str:
    """The most telling line of a failed command's output (pip/npm/brew print an ERROR: line)."""
    try:
        lines = [ln.strip() for ln in Path(log).read_text(errors="replace").splitlines() if ln.strip()]
    except OSError:
        return ""
    for ln in reversed(lines):
        if re.match(r"^(ERROR|error|npm ERR!|Error:|E:|fatal:)", ln):
            return ln[:240]
    return lines[-1][:240] if len(lines) > 1 else ""


def latest_plan() -> Optional[Path]:
    plans = sorted((data_dir() / "plans").glob("plan-*.json"))
    return plans[-1] if plans else None


def load_plan(path: Optional[str]) -> tuple[dict, str]:
    p = Path(path).expanduser() if path else latest_plan()
    if not p or not p.is_file():
        raise FileNotFoundError("no plan found: run `scs plan` first (or pass --plan PATH)")
    return json.loads(p.read_text()), str(p)


def history(limit: int = 20) -> list[dict]:
    out = []
    for j in sorted(runs_dir().glob("*/journal.json"), reverse=True)[:limit]:
        try:
            out.append(read_json(j))
        except Exception:
            continue
    return out
