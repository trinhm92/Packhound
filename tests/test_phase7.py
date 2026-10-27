import json
import os
import plistlib
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from scs import notify, schedule, watch
from scs.config import Config
from scs.malware import persistence, reputation


class Receiver:
    """Local HTTP endpoint that records JSON posts (stands in for Slack/Teams/webhooks)."""

    def __init__(self):
        self.posts: list[tuple[str, dict]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.posts.append((self.path, json.loads(body)))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


class ReputationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.tmp / "cache")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def files(self):
        d = self.tmp / "dl"
        d.mkdir()
        (d / "a.exe").write_bytes(b"MZ...a")
        (d / "b.bin").write_bytes(b"\x7fELF...b")
        (d / "c.bin").write_bytes(b"\x7fELF...c")
        (d / "notes.txt").write_text("hello")
        return reputation.collect_targets([d])

    def test_targets_and_providers(self):
        files = self.files()
        self.assertEqual(sorted(f.name for f in files), ["a.exe", "b.bin", "c.bin"])  # text file skipped
        a_hash = reputation.sha256(files[[f.name for f in files].index("a.exe")])
        mb_calls, vt_calls, sleeps = [], [], []

        def mb(digest, key):
            mb_calls.append(digest)
            return {"found": True, "signature": "AgentTesla", "tags": ["exe"]} if digest == a_hash else {"found": False}

        def vt(digest, key):
            vt_calls.append(digest)
            return {"found": True, "malicious": 12 if len(vt_calls) == 1 else 2, "suspicious": 0, "undetected": 50}

        f, st = reputation.check(files, "mbkey", "vtkey", vt_limit=5, mb=mb, vt=vt, sleep=sleeps.append)
        sev = sorted(x.severity for x in f)
        self.assertEqual(sev, ["critical", "critical", "medium"])  # MB hit, VT 12 engines, VT 2 engines
        self.assertEqual(len(mb_calls), 3)
        self.assertEqual(len(vt_calls), 2)  # the MalwareBazaar hit is not sent to VirusTotal
        self.assertEqual(sleeps, [15.5])  # rate-limited between VT queries
        mb_calls.clear()
        vt_calls.clear()
        reputation.check(files, "mbkey", "vtkey", mb=mb, vt=vt, sleep=sleeps.append)
        self.assertEqual((mb_calls, vt_calls), ([], []))  # cached

    def test_vt_budget_and_parsers(self):
        files = self.files()
        calls = []
        reputation.check(files, "", "vtkey", vt_limit=1, vt=lambda d, k: calls.append(d) or {"found": False},
                         sleep=lambda s: None)
        self.assertEqual(len(calls), 1)
        r = reputation.malwarebazaar("x", "k", post=lambda u, f, h: {"query_status": "ok", "data": [
            {"signature": "Lumma", "tags": ["stealer"], "first_seen": "2025-01-01"}]})
        self.assertEqual((r["found"], r["signature"]), (True, "Lumma"))
        self.assertFalse(reputation.malwarebazaar("x", "k", post=lambda u, f, h: {"query_status": "hash_not_found"})["found"])
        v = reputation.virustotal("x", "k", get=lambda u, h: {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 4, "undetected": 60},
            "popular_threat_classification": {"suggested_threat_label": "trojan.x"}}}})
        self.assertEqual((v["malicious"], v["label"]), (4, "trojan.x"))
        self.assertFalse(reputation.virustotal("x", "k", get=lambda u, h: None)["found"])


class NotifyTests(unittest.TestCase):
    def test_channels(self):
        rx = Receiver()
        self.addCleanup(rx.close)
        alert = notify.Alert(host="h", title="2 new findings", severity="high", lines=["a", "b"], report="/r.html")
        sent_mail = []

        class FakeSMTP:
            def __init__(self, host, port, timeout):
                self.host = host

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def starttls(self):
                pass

            def login(self, u, p):
                sent_mail.append(("login", u, p))

            def send_message(self, m):
                sent_mail.append(("msg", m["Subject"], m.get_content()))

        runs = []
        conf = {"desktop": True, "webhook": f"{rx.url}/hook", "slack_webhook": "env:TEST_SLACK", "teams_webhook": f"{rx.url}/teams",
                "email": {"host": "smtp.test", "from": "a@x", "to": ["b@x"], "username": "u", "password": "env:TEST_PW"}}
        with mock.patch.dict(os.environ, {"TEST_SLACK": f"{rx.url}/slack", "TEST_PW": "pw"}), \
                mock.patch("platform.system", return_value="Darwin"):
            res = notify.send(alert, conf, runner=lambda *a, **k: runs.append(a[0]), smtp_factory=FakeSMTP)
        self.assertEqual(set(res.values()), {"ok"}, res)
        paths = {p: body for p, body in rx.posts}
        self.assertEqual(paths["/hook"]["title"], "2 new findings")
        self.assertIn("• a", paths["/slack"]["text"])
        self.assertEqual(paths["/teams"]["attachments"][0]["contentType"], "application/vnd.microsoft.card.adaptive")
        self.assertEqual(runs[0][0], "osascript")
        self.assertIn(("login", "u", "pw"), sent_mail)

    def test_refuses_plain_http_and_reports_missing_env(self):
        alert = notify.Alert(host="h", title="t", severity="low")
        res = notify.send(alert, {"webhook": "http://example.com/x", "slack_webhook": "env:NOT_SET_ANYWHERE"})
        self.assertIn("non-https", res["webhook"])
        self.assertIn("not set", res["slack_webhook"])


def scan_result(findings, has_previous):
    return {"host": "h", "started": "2026-10-26T10:00:00+07:00", "duration_s": 1, "scs_version": "t", "has_previous": has_previous,
            "summary": {"buckets": {"respond": 0, "patch": 0, "verify": 0, "monitor": 0}, "severity": {}, "total": 0, "new": 0},
            "findings": findings, "inventory": {"total": 1, "unique": 1}, "sources": {}, "collectors": {}, "errors": [],
            "config": {}, "outdated": []}


def finding(name, sev="HIGH", bucket="patch", new=True, kev=False, adv="GHSA-1"):
    from scs.models import Advisory, Finding, Package
    p = Package("npm", name, "1.0.0", "lockfile", "/p/package-lock.json", meta={"project": "/p", "lockfile": "package-lock.json"})
    a = Advisory(adv, aliases=["CVE-2026-1"], severity=sev, malicious=bucket == "respond", kev=kev, fixed=["1.0.1"])
    return Finding("npm", name, "1.0.0", [p], [a], score=80, severity=sev, bucket=bucket, fix_version="1.0.1",
                   new=new).to_dict()


class WatchTests(unittest.TestCase):
    def test_baseline_then_new_and_dedupe(self):
        tmp = Path(tempfile.mkdtemp())
        rx = Receiver()
        self.addCleanup(rx.close)
        cfg = Config(notify={"webhook": f"{rx.url}/hook"})
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp)}):
            first = [finding("old-debt"), finding("evil", sev="CRITICAL", bucket="respond", adv="MAL-1")]
            s1 = watch.run(cfg, malware="none", perform_scan=lambda c: scan_result(first, False))
            self.assertTrue(s1["baseline_run"])
            self.assertEqual(s1["alert"]["lines"][0].startswith("MALICIOUS"), True)
            self.assertEqual(len(s1["alert"]["lines"]), 1)  # existing HIGH debt does not alert on the baseline run
            second = [finding("old-debt", new=False), finding("evil", sev="CRITICAL", bucket="respond", adv="MAL-1", new=False),
                      finding("fresh", sev="HIGH"), finding("minor", sev="MEDIUM"), finding("exploited", sev="MEDIUM", new=False, kev=True)]
            s2 = watch.run(cfg, malware="none", perform_scan=lambda c: scan_result(second, True))
            names = " ".join(s2["alert"]["lines"])
            self.assertIn("fresh", names)
            self.assertIn("KEV", names)
            self.assertNotIn("minor", names)       # below threshold
            self.assertNotIn("evil", names)        # already alerted once
            s3 = watch.run(cfg, malware="none", perform_scan=lambda c: scan_result(second, True))
            self.assertEqual(s3["alerts"], 0)      # nothing new since
            self.assertEqual(len(rx.posts), 2)
            self.assertEqual(len(watch.recent_alerts()), 2)


class ScheduleTests(unittest.TestCase):
    # macOS paths are simulated with platform.system() == "Darwin"; os.getuid (missing on Windows) is patched too
    def test_when_and_renderers(self):
        self.assertEqual(schedule.parse_when("07:05", None), {"hour": 7, "minute": 5, "day": None})
        self.assertEqual(schedule.parse_when(None, ["Friday", "18:30"])["day"], "fri")
        with self.assertRaises(ValueError):
            schedule.parse_when("25:00", None)
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": tempfile.mkdtemp()}):
            cmd = schedule.watch_command(["--malware", "quick"])
            pl = plistlib.loads(schedule.launchd_plist(cmd, schedule.parse_when(None, ["mon", "08:30"])))
            self.assertEqual(pl["StartCalendarInterval"], {"Hour": 8, "Minute": 30, "Weekday": 1})
            self.assertEqual(pl["ProgramArguments"][:3], schedule.SH_EXEC)  # launchd pins /bin/sh, not our binary
            self.assertEqual(pl["ProgramArguments"][4:7], ["-m", "scs", "watch"])
            svc, tmr = schedule.systemd_units(cmd, schedule.parse_when("09:00", None))
            self.assertIn("OnCalendar=*-*-* 09:00:00", tmr)
            self.assertIn("Persistent=true", tmr)
            self.assertIn("-m scs watch", svc)
            self.assertTrue(schedule.cron_line(cmd, schedule.parse_when(None, ["sun", "06:00"])).startswith("0 6 * * 0 "))
            args = schedule.schtasks_args(Path("C:/x/scs-watch.cmd"), schedule.parse_when(None, ["wed", "12:00"]))
            self.assertEqual(args[-4:], ["/SC", "WEEKLY", "/D", "WED"])
            self.assertIn("-m scs watch", schedule.windows_wrapper(cmd))

    def test_repair_wraps_old_launch_agent(self):
        d = Path(tempfile.mkdtemp())
        old = {"Label": schedule.LABEL, "ProgramArguments": ["/Applications/Supply Chain Scanner.app/Contents/MacOS/Supply Chain Scanner", "--watch"]}
        (d / f"{schedule.LABEL}.plist").write_bytes(plistlib.dumps(old))
        with mock.patch.object(schedule, "_plist_path", return_value=d / f"{schedule.LABEL}.plist"), \
                mock.patch.object(schedule.platform, "system", return_value="Darwin"), \
                mock.patch.object(schedule.os, "getuid", return_value=501, create=True), \
                mock.patch.object(schedule.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertTrue(schedule.repair())
            self.assertFalse(schedule.repair())  # already wrapped: nothing to do
        args = plistlib.loads((d / f"{schedule.LABEL}.plist").read_bytes())["ProgramArguments"]
        self.assertEqual(args, [*schedule.SH_EXEC, "/Applications/Supply Chain Scanner.app/Contents/MacOS/Supply Chain Scanner", "--watch"])
        own = {"kind": "launchd", "path": str(d / f"{schedule.LABEL}.plist"), "label": schedule.LABEL,
               "program": "/bin/sh", "args": args}
        self.assertEqual(persistence.audit_autostart([own]), [])

    def test_repair_follows_the_renamed_app(self):
        d = Path(tempfile.mkdtemp())
        plist = d / f"{schedule.LABEL}.plist"
        legacy = "/Applications/Supply Chain Scanner.app/Contents/MacOS/Supply Chain Scanner"
        new = "/Applications/Packhound.app/Contents/MacOS/Packhound"
        old = {"Label": schedule.LABEL, "ProgramArguments": [*schedule.SH_EXEC, legacy, "--watch", "--malware", "quick"],
               "WorkingDirectory": "/Applications/Supply Chain Scanner.app/Contents/Resources",
               "StartCalendarInterval": {"Hour": 9, "Minute": 0, "Weekday": 1}}
        env = {"XDG_DATA_HOME": tempfile.mkdtemp()}

        def run_repair(exe, exists):
            plist.write_bytes(plistlib.dumps(old))
            with mock.patch.object(schedule, "_plist_path", return_value=plist), \
                    mock.patch.object(schedule.platform, "system", return_value="Darwin"), \
                    mock.patch.object(schedule.os, "getuid", return_value=501, create=True), \
                    mock.patch.object(schedule.subprocess, "run") as run, \
                    mock.patch.object(schedule.sys, "frozen", True, create=True), \
                    mock.patch.object(schedule.sys, "executable", exe), \
                    mock.patch.object(schedule.os.path, "exists", side_effect=lambda p: exists), \
                    mock.patch.dict(os.environ, env):
                run.return_value.returncode = 0
                return schedule.repair(), plistlib.loads(plist.read_bytes())

        changed, pl = run_repair(new, exists=True)  # the old app is still there, the new one is installed
        self.assertTrue(changed)
        self.assertEqual(pl["ProgramArguments"], [*schedule.SH_EXEC, new, "--watch", "--malware", "quick"])
        self.assertEqual(pl["StartCalendarInterval"], {"Hour": 9, "Minute": 0, "Weekday": 1})
        self.assertNotIn("Supply Chain Scanner", pl["WorkingDirectory"])
        # a test copy outside /Applications never takes over a schedule whose app still exists
        changed, pl = run_repair("/Users/me/build/Packhound.app/Contents/MacOS/Packhound", exists=True)
        self.assertFalse(changed)
        self.assertIn(legacy, pl["ProgramArguments"])
        # …but it does when the scheduled app is gone
        self.assertTrue(run_repair("/Users/me/build/Packhound.app/Contents/MacOS/Packhound", exists=False)[0])

    def test_repair_windows_wrapper(self):
        data = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": data}):
            w = schedule._wrapper_path()
            w.parent.mkdir(parents=True, exist_ok=True)
            for old_exe in (r"C:\Users\me\AppData\Local\Programs\Supply Chain Scanner\Supply Chain Scanner.exe",
                            r"C:\Apps\scanner.exe"):  # quoted (spaces) and unquoted
                w.write_text(schedule.windows_wrapper([old_exe, "--watch", "--malware", "full"]), encoding="utf-8")
                exe = r"C:\Users\me\AppData\Local\Programs\Packhound\Packhound.exe"
                with mock.patch.object(schedule.sys, "frozen", True, create=True), \
                        mock.patch.object(schedule.sys, "executable", exe), \
                        mock.patch.object(schedule.platform, "system", return_value="Windows"), \
                        mock.patch.object(schedule.os.path, "exists", return_value=False):
                    self.assertTrue(schedule.repair())
                text = w.read_text(encoding="utf-8")
                self.assertRegex(text, r'Packhound\.exe"? --watch --malware full')
                self.assertNotIn(old_exe, text)

    def test_persistence_audit_ignores_own_job(self):
        own = {"kind": "launchd", "path": f"/Users/x/Library/LaunchAgents/{schedule.LABEL}.plist", "label": schedule.LABEL,
               "program": "/usr/bin/python3", "args": ["/usr/bin/python3", "-m", "scs", "watch"]}
        fake = dict(own, label="com.other", path="/Users/x/Library/LaunchAgents/com.other.plist")
        f = persistence.audit_autostart([own, fake])
        # an imitation is still audited (on Windows it also gets a "missing program" finding)
        self.assertEqual({x.meta["item"]["label"] for x in f}, {"com.other"})


if __name__ == "__main__":
    unittest.main()
