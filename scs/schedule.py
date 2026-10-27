"""`scs schedule`: run `scs watch` periodically with the OS scheduler.

  macOS    ~/Library/LaunchAgents/com.scs.watch.plist (launchctl bootstrap gui/<uid>)
  Linux    ~/.config/systemd/user/scs-watch.{service,timer} (Persistent=true: catches up after sleep/boot)
  Windows  Task Scheduler task \\scs\\watch running a small wrapper .cmd (schtasks /TR is limited to 261 chars)
`--print` shows exactly what would be installed without touching the system.
The persistence audit recognises these entries as scs's own job.
"""
from __future__ import annotations

import os
import platform
import plistlib
import re
import subprocess
import sys
from pathlib import Path

from scs.util import data_dir

LABEL = "com.scs.watch"
UNIT = "scs-watch"
TASK = r"\scs\watch"
DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
PROJECT_ROOT = Path(__file__).resolve().parent.parent  # lets `python -m scs` work without pip install


def parse_when(daily: str | None, weekly: list[str] | None) -> dict:
    if weekly:
        day, hhmm = weekly[0].lower()[:3], weekly[1]
        if day not in DAYS:
            raise ValueError(f"unknown day {weekly[0]!r}")
    else:
        day, hhmm = None, daily or "09:00"
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", hhmm)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        raise ValueError(f"time must be HH:MM, got {hhmm!r}")
    return {"hour": int(m.group(1)), "minute": int(m.group(2)), "day": day}


def watch_command(opts: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):  # packaged desktop app: the binary itself runs `watch` headless
        return [sys.executable, "--watch", *opts]
    return [sys.executable, "-m", "scs", "watch", *opts]


def log_dir() -> Path:
    p = data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------- macOS

# launchd pins the code signature of the program it starts. The packaged app is ad-hoc signed, so
# installing a newer build changes that signature and macOS kills the next run ("Launch Constraint
# Violation"); a pyenv or Homebrew Python is replaced the same way on upgrade. Starting it through
# Apple's /bin/sh keeps the pinned program stable across updates.
SH_EXEC = ["/bin/sh", "-c", 'exec "$0" "$@"']


def launchd_args(cmd: list[str]) -> list[str]:
    return cmd if cmd[:3] == SH_EXEC else [*SH_EXEC, *cmd]


def launchd_plist(cmd: list[str], when: dict) -> bytes:
    cmd = launchd_args(cmd)
    cal = {"Hour": when["hour"], "Minute": when["minute"]}
    if when["day"]:
        cal["Weekday"] = DAYS.index(when["day"])
    return plistlib.dumps({
        "Label": LABEL, "ProgramArguments": cmd, "WorkingDirectory": str(PROJECT_ROOT),
        "EnvironmentVariables": {"PYTHONPATH": str(PROJECT_ROOT), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        "StartCalendarInterval": cal, "ProcessType": "Background", "LowPriorityIO": True, "Nice": 10,
        "StandardOutPath": str(log_dir() / "watch.out.log"), "StandardErrorPath": str(log_dir() / "watch.err.log"),
    })


def _plist_path() -> Path:
    return Path("~/Library/LaunchAgents").expanduser() / f"{LABEL}.plist"


LEGACY_NAMES = ("Supply Chain Scanner",)  # earlier names of the desktop app


def _moved_app(exe: str) -> bool:
    """The schedule runs another copy of the app that is gone, or the one from before the rename,
    while this copy is the packaged app (installed in /Applications or Program Files)."""
    if not getattr(sys, "frozen", False) or not exe or os.path.normcase(exe) == os.path.normcase(sys.executable):
        return False
    installed = any(seg in sys.executable for seg in ("/Applications/", "\\Programs\\", "Program Files"))
    return not os.path.exists(exe) or (installed and any(n in exe for n in LEGACY_NAMES))


def repair() -> bool:
    """Called when the desktop app opens: fix a schedule made by an older build.

    - it starts the app binary directly (launchd then kills it after an update: see SH_EXEC)
    - it points at an app that was renamed or removed (it would silently stop running)
    The time and options are kept.
    """
    if platform.system() == "Windows":
        return _repair_windows()
    p = _plist_path()
    if platform.system() != "Darwin" or not p.exists():
        return False
    try:
        pl = plistlib.loads(p.read_bytes())
    except Exception:
        return False
    args = pl.get("ProgramArguments", [])
    core = args[3:] if args[:3] == SH_EXEC else args
    if pl.get("Label") != LABEL:
        return False
    if core and "--watch" in core and _moved_app(core[0]):
        cal = pl.get("StartCalendarInterval", {})
        when = {"hour": cal.get("Hour", 9), "minute": cal.get("Minute", 0),
                "day": DAYS[cal["Weekday"] % 7] if "Weekday" in cal else None}
        pl = plistlib.loads(launchd_plist(watch_command(core[core.index("--watch") + 1:]), when))
    elif launchd_args(args) != args:
        pl["ProgramArguments"] = launchd_args(args)
    else:
        return False
    p.write_bytes(plistlib.dumps(pl))
    uid = os.getuid()
    subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(p)], capture_output=True)
    return subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(p)], capture_output=True).returncode == 0


# ---------------------------------------------------------------- Linux

def systemd_units(cmd: list[str], when: dict) -> tuple[str, str]:
    import shlex
    day = f"{when['day'].capitalize()} " if when["day"] else ""
    service = (f"[Unit]\nDescription=scs supply-chain watch\n\n[Service]\nType=oneshot\n"
               f"WorkingDirectory={PROJECT_ROOT}\nEnvironment=PYTHONPATH={PROJECT_ROOT}\n"
               f"Environment=PATH={os.environ.get('PATH', '/usr/bin:/bin')}\n"
               f"ExecStart={' '.join(shlex.quote(c) for c in cmd)}\nNice=10\nIOSchedulingClass=idle\n")
    timer = (f"[Unit]\nDescription=Run scs watch on a schedule\n\n[Timer]\n"
             f"OnCalendar={day}*-*-* {when['hour']:02d}:{when['minute']:02d}:00\nPersistent=true\n"
             f"RandomizedDelaySec=300\n\n[Install]\nWantedBy=timers.target\n")
    return service, timer


def _unit_dir() -> Path:
    return Path("~/.config/systemd/user").expanduser()


def cron_line(cmd: list[str], when: dict) -> str:
    import shlex
    dow = str(DAYS.index(when["day"])) if when["day"] else "*"
    return (f"{when['minute']} {when['hour']} * * {dow} cd {shlex.quote(str(PROJECT_ROOT))} && "
            f"PYTHONPATH={shlex.quote(str(PROJECT_ROOT))} {' '.join(shlex.quote(c) for c in cmd)} "
            f">> {shlex.quote(str(log_dir() / 'watch.log'))} 2>&1")


# ---------------------------------------------------------------- Windows

def windows_wrapper(cmd: list[str]) -> str:
    from subprocess import list2cmdline
    return ("@echo off\r\n"
            f'cd /d "{PROJECT_ROOT}"\r\n'
            f'set "PYTHONPATH={PROJECT_ROOT}"\r\n'
            f'{list2cmdline(cmd)} >> "{log_dir() / "watch.log"}" 2>&1\r\n')


def _wrapper_path() -> Path:
    return data_dir() / "schedule" / "scs-watch.cmd"


def _repair_windows() -> bool:
    """Point the scheduled task's wrapper at this copy of the app when the old one was renamed or removed."""
    w = _wrapper_path()
    if not w.is_file():
        return False
    m = re.search(r'^"?([^"\r\n]+?\.exe)"? --watch(.*?) >>', w.read_text(encoding="utf-8", errors="replace"), re.M)
    if not m or not _moved_app(m.group(1)):
        return False
    w.write_text(windows_wrapper(watch_command(m.group(2).split())), encoding="utf-8")
    return True


def schtasks_args(wrapper: Path, when: dict) -> list[str]:
    args = ["schtasks", "/Create", "/TN", TASK, "/TR", f'"{wrapper}"', "/ST", f"{when['hour']:02d}:{when['minute']:02d}", "/F"]
    if when["day"]:
        args += ["/SC", "WEEKLY", "/D", when["day"].upper()]
    else:
        args += ["/SC", "DAILY"]
    return args


# ---------------------------------------------------------------- actions

def describe(cmd: list[str], when: dict, system: str | None = None) -> str:
    system = system or platform.system()
    if system == "Darwin":
        return f"# {_plist_path()}\n" + launchd_plist(cmd, when).decode()
    if system == "Linux":
        svc, tmr = systemd_units(cmd, when)
        return (f"# {_unit_dir() / (UNIT + '.service')}\n{svc}\n# {_unit_dir() / (UNIT + '.timer')}\n{tmr}\n"
                f"# without systemd, add this to `crontab -e` instead:\n{cron_line(cmd, when)}\n")
    wrapper = _wrapper_path()
    return f"# {wrapper}\n{windows_wrapper(cmd)}\n# then:\n{subprocess.list2cmdline(schtasks_args(wrapper, when))}\n"


def install(cmd: list[str], when: dict) -> list[str]:
    system = platform.system()
    done = []
    if system == "Darwin":
        p = _plist_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(launchd_plist(cmd, when))
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(p)], capture_output=True)  # replace an older version
        r = subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(p)], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"launchctl bootstrap failed: {r.stderr.strip()}")
        done.append(f"installed LaunchAgent {p}")
    elif system == "Linux":
        if not subprocess.run(["systemctl", "--user", "show-environment"], capture_output=True).returncode == 0:
            raise RuntimeError("no systemd user session; add this line with `crontab -e` instead:\n" + cron_line(cmd, when))
        d = _unit_dir()
        d.mkdir(parents=True, exist_ok=True)
        svc, tmr = systemd_units(cmd, when)
        (d / f"{UNIT}.service").write_text(svc)
        (d / f"{UNIT}.timer").write_text(tmr)
        for args in (["daemon-reload"], ["enable", "--now", f"{UNIT}.timer"]):
            r = subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(f"systemctl --user {' '.join(args)} failed: {r.stderr.strip()}")
        done.append(f"installed and started {UNIT}.timer (systemd user)")
    else:
        wrapper = _wrapper_path()
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        wrapper.write_text(windows_wrapper(cmd), encoding="utf-8")
        r = subprocess.run(schtasks_args(wrapper, when), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"schtasks failed: {r.stderr.strip() or r.stdout.strip()}")
        done.append(f"created scheduled task {TASK}")
    return done


def remove() -> list[str]:
    system = platform.system()
    done = []
    if system == "Darwin":
        p = _plist_path()
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(p)], capture_output=True)
        if p.exists():
            p.unlink()
            done.append(f"removed {p}")
    elif system == "Linux":
        subprocess.run(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"], capture_output=True)
        for ext in ("timer", "service"):
            f = _unit_dir() / f"{UNIT}.{ext}"
            if f.exists():
                f.unlink()
                done.append(f"removed {f}")
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    else:
        r = subprocess.run(["schtasks", "/Delete", "/TN", TASK, "/F"], capture_output=True, text=True)
        if r.returncode == 0:
            done.append(f"deleted scheduled task {TASK}")
    return done or ["nothing was scheduled"]


def status() -> str:
    system = platform.system()
    if system == "Darwin":
        p = _plist_path()
        if not p.exists():
            return "not scheduled"
        r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], capture_output=True, text=True)
        cal = plistlib.loads(p.read_bytes()).get("StartCalendarInterval", {})
        return f"LaunchAgent {p} ({'loaded' if r.returncode == 0 else 'NOT loaded'}), runs at {cal}"
    if system == "Linux":
        r = subprocess.run(["systemctl", "--user", "list-timers", f"{UNIT}.timer", "--no-pager"], capture_output=True, text=True)
        return r.stdout.strip() if f"{UNIT}.timer" in r.stdout else "not scheduled"
    r = subprocess.run(["schtasks", "/Query", "/TN", TASK, "/FO", "LIST"], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "not scheduled"


def is_own_entry(item: dict) -> bool:
    """True for the scheduler entries this module creates (so the persistence audit doesn't flag them)."""
    args = " ".join(item.get("args", [])) or item.get("command", "")
    runs_watch = "-m scs watch" in args or "scs-watch.cmd" in args or (
        any(n in args for n in ("Packhound", *LEGACY_NAMES)) and " --watch" in args)
    return runs_watch and (item.get("label") in (LABEL, f"{UNIT}.service", "watch")
                           or os.path.basename(item.get("path", "")) in (f"{LABEL}.plist", f"{UNIT}.service"))
