"""Alert delivery: desktop notification, generic webhook, Slack, Microsoft Teams, email.

Configured in config.json under "notify"; secrets as "env:NAME":
  {"desktop": true,
   "webhook": "env:SCS_WEBHOOK",              # JSON POST of the full alert
   "slack_webhook": "env:SCS_SLACK_WEBHOOK",  # Slack incoming webhook
   "teams_webhook": "env:SCS_TEAMS_WEBHOOK",  # Teams Workflows "post to channel" webhook (Adaptive Card)
   "email": {"host": "smtp.example.com", "port": 587, "starttls": true, "username": "me@example.com",
             "password": "env:SCS_SMTP_PASSWORD", "from": "scs@example.com", "to": ["me@example.com"]}}
Webhooks must be https (http only for localhost). Alerts contain package names, advisory ids,
host name and local report paths — never secret values.
"""
from __future__ import annotations

import json
import platform
import shutil
import smtplib
import subprocess
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from email.message import EmailMessage
from typing import Callable

from scs.config import secret
from scs.util import USER_AGENT, urlopen


@dataclass
class Alert:
    host: str
    title: str
    severity: str                 # highest severity in the alert
    lines: list[str] = field(default_factory=list)
    report: str = ""              # local path to the HTML report
    counts: dict = field(default_factory=dict)

    def text(self, max_lines: int = 12) -> str:
        body = "\n".join(f"• {ln}" for ln in self.lines[:max_lines])
        more = f"\n…and {len(self.lines) - max_lines} more" if len(self.lines) > max_lines else ""
        rep = f"\nReport: {self.report}" if self.report else ""
        return f"{self.title}\n{body}{more}{rep}"


class NotifyError(Exception):
    pass


def _check_url(url: str) -> None:
    u = urllib.parse.urlparse(url)
    local = u.hostname in ("localhost", "127.0.0.1", "::1")
    if u.scheme != "https" and not (u.scheme == "http" and local):
        raise NotifyError(f"refusing non-https webhook {u.scheme}://{u.hostname}")


def post_json(url: str, payload: dict, timeout: int = 20) -> int:
    _check_url(url)
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as r:
        return r.status


def _desktop(alert: Alert, runner: Callable = subprocess.run) -> None:
    title = f"scs: {alert.title}"[:120]
    msg = "; ".join(alert.lines[:3])[:240] or alert.title
    system = platform.system()
    if system == "Darwin":
        esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')  # noqa: E731
        runner(["osascript", "-e", f'display notification "{esc(msg)}" with title "{esc(title)}"'],
               capture_output=True, timeout=20)
    elif system == "Linux":
        if not shutil.which("notify-send"):
            raise NotifyError("notify-send not installed")
        runner(["notify-send", "-u", "critical" if alert.severity in ("critical", "high") else "normal", title, msg],
               capture_output=True, timeout=20)
    elif system == "Windows":
        sq = lambda s: s.replace("'", "''")  # noqa: E731
        ps = ("Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; "
              "$n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true; "
              f"$n.ShowBalloonTip(10000, '{sq(title)}', '{sq(msg)}', 'Warning'); Start-Sleep -Seconds 11; $n.Dispose()")
        runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, timeout=30)
    else:
        raise NotifyError(f"no desktop notifier for {system}")


def _slack(alert: Alert) -> dict:
    return {"text": f"*{alert.title}* ({alert.host})\n" + "\n".join(f"• {ln}" for ln in alert.lines[:15])
            + (f"\nReport on {alert.host}: `{alert.report}`" if alert.report else "")}


def _teams(alert: Alert) -> dict:
    body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": alert.title, "wrap": True},
            {"type": "TextBlock", "text": f"Host: {alert.host}", "isSubtle": True, "spacing": "None"}]
    body += [{"type": "TextBlock", "text": f"• {ln}", "wrap": True, "spacing": "Small"} for ln in alert.lines[:15]]
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4", "body": body}
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}


def _email(alert: Alert, conf: dict, smtp_factory=smtplib.SMTP) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[scs] {alert.title} ({alert.host})"
    msg["From"] = conf["from"]
    to = conf["to"] if isinstance(conf["to"], list) else [conf["to"]]
    msg["To"] = ", ".join(to)
    msg.set_content(alert.text(max_lines=50))
    with smtp_factory(conf["host"], int(conf.get("port", 587)), timeout=30) as s:
        if conf.get("starttls", True):
            s.starttls()
        if conf.get("username"):
            s.login(conf["username"], secret(conf.get("password", "")))
        s.send_message(msg)


def send(alert: Alert, conf: dict, post: Callable = post_json, runner: Callable = subprocess.run,
         smtp_factory=smtplib.SMTP) -> dict[str, str]:
    """Deliver to every configured channel; returns {channel: "ok" | error}."""
    results: dict[str, str] = {}

    def attempt(name: str, fn: Callable[[], object]) -> None:
        try:
            fn()
            results[name] = "ok"
        except Exception as e:  # one broken channel must not stop the others
            results[name] = f"error: {e}"

    if conf.get("desktop"):
        attempt("desktop", lambda: _desktop(alert, runner))
    for key, build in (("webhook", lambda a: asdict(a)), ("slack_webhook", _slack), ("teams_webhook", _teams)):
        url = secret(conf.get(key))
        if url:
            attempt(key, lambda url=url, build=build: post(url, build(alert)))
        elif conf.get(key):
            results[key] = "error: environment variable not set"
    if conf.get("email"):
        attempt("email", lambda: _email(alert, conf["email"], smtp_factory))
    return results
