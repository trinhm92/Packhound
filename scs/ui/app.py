"""Launch the GUI: native window via pywebview when installed, otherwise the default browser.

`scs ui` / `scs-gui` (the packaged app's entry point) both end up here.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
import webbrowser
from typing import Optional

from scs.ui.server import App, pick_folder, serve

TITLE = "Packhound"


# Common tool locations, used if the login shell cannot be asked.
FALLBACK_PATH = ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin", "~/.cargo/bin",
                 "~/go/bin", "~/.local/bin", "/snap/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]


def login_shell_path(timeout: float = 6) -> list[str]:
    """PATH as the user's terminal sees it. Apps opened from Finder/the dock only get /usr/bin:/bin:…,
    so Homebrew, cargo, go and friends would be invisible to the scan."""
    if os.name == "nt":
        return []
    shell = os.environ.get("SHELL") or ("/bin/zsh" if sys.platform == "darwin" else "/bin/bash")
    marker = "__SCS_PATH__"
    for flags in ("-ilc", "-lc"):  # interactive first: many setups extend PATH in .zshrc/.bashrc
        try:
            r = subprocess.run([shell, flags, f'printf "{marker}%s{marker}" "$PATH"'], capture_output=True, text=True,
                               timeout=timeout, stdin=subprocess.DEVNULL, env={**os.environ, "TERM": "dumb"})
        except (OSError, subprocess.TimeoutExpired):
            continue
        m = re.search(f"{marker}(.*?){marker}", r.stdout)
        if m and m.group(1):
            return m.group(1).split(":")
    return []


def augment_path() -> None:
    dirs = login_shell_path() + os.environ.get("PATH", "").split(os.pathsep) + \
        [os.path.expanduser(d) for d in FALLBACK_PATH]
    seen, merged = set(), []
    for d in dirs:
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            merged.append(d)
    os.environ["PATH"] = os.pathsep.join(merged)


def _webview():
    try:
        import webview  # type: ignore[import-not-found]
        return webview
    except ImportError:
        return None


def run(browser: bool = False, port: int = 0, open_window: bool = True) -> int:
    augment_path()
    app = App()
    httpd, app, url = serve(app, port)
    webview = None if browser else _webview()
    try:
        if webview and open_window:
            window = webview.create_window(TITLE, url, width=1240, height=860, min_size=(900, 600))

            def native_picker() -> Optional[str]:
                try:
                    res = window.create_file_dialog(webview.FOLDER_DIALOG)
                    return res[0] if res else None
                except Exception:
                    return pick_folder()

            app.folder_picker = native_picker
            webview.start()  # blocks until the window is closed
        else:
            if open_window:
                webbrowser.open(url)
            print(f"{TITLE} is running at:\n  {url}\n(keep this window open; press Ctrl+C to quit)")
            if not webview and not browser:
                print("Tip: `pip install -r requirements-gui.txt` to get a native app window instead of a browser tab.")
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0


def main_gui() -> None:
    """Entry point for the packaged desktop app.

    `<app> --watch [watch options]` runs `scs watch` headless (used by the scheduler, since
    a frozen app has no `python -m scs`), `<app> --cli <command …>` runs any scs command
    (used by patch plans); without arguments it opens the window.
    """
    if sys.stdout is None or sys.stderr is None:
        # windowed builds (Windows, console=False) have no console: print()/log() would crash,
        # so send output to ~/.local/share/scs/logs/app.log instead
        from scs.util import data_dir
        log_dir = data_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        stream = open(log_dir / "app.log", "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stdout or stream
        sys.stderr = sys.stderr or stream
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        # patch plans call back into scs (`scs fixer …`); a frozen app has no `python -m scs`
        augment_path()
        from scs.cli import main
        sys.exit(main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--watch":
        augment_path()  # scheduled runs start with launchd's minimal PATH too
        from scs.cli import main
        sys.exit(main(["watch", *sys.argv[2:]]))
    try:
        from scs import schedule
        schedule.repair()  # a schedule set up by an older build would be killed after this update
    except Exception:
        pass
    sys.exit(run())
